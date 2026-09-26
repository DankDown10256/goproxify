// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

const (
	accessPending  = "pending"
	accessApproved = "approved"
	accessDenied   = "denied"
	accessRevoked  = "revoked"

	maxApprovalMin = 24 * 60
)

// PortalAccessRequest est une demande d'accès temporaire à une destination.
type PortalAccessRequest struct {
	ID          string `json:"id"`
	EdgeName    string `json:"edge_name"`
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	TargetID    string `json:"target_id"`
	TargetName  string `json:"target_name"`
	Reason      string `json:"reason"`
	DurationMin int    `json:"duration_min"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	DecidedBy   string `json:"decided_by,omitempty"`
	DecidedAt   string `json:"decided_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// InsertPortalAccessRequest enregistre une demande reçue d'une passerelle et retourne true si elle est nouvelle ; une demande déjà en attente
// pour le même utilisateur et la même destination n'est pas dupliquée.
func InsertPortalAccessRequest(db *sql.DB, edge, userID, username, targetID, reason string, durationMin int) bool {
	if db == nil || edge == "" || userID == "" || targetID == "" {
		return false
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_access_requests WHERE edge_name=? AND user_id=? AND target_id=? AND status=?`,
		edge, userID, targetID, accessPending).Scan(&n)
	if n > 0 {
		return false
	}
	var name string
	_ = db.QueryRow(`SELECT name FROM portal_destinations WHERE id=?`, targetID).Scan(&name)
	_, err := db.Exec(`INSERT INTO portal_access_requests
		(id, edge_name, user_id, username, target_id, target_name, reason, duration_min, status, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		uuid.NewString(), edge, userID, username, targetID, name, reason, durationMin, accessPending,
		time.Now().UTC().Format(time.RFC3339))
	return err == nil
}

// listActiveGrants retourne les accès approuvés non expirés pour les passerelles données.
func listActiveGrants(db *sql.DB, edges []string) []portal.AccessGrant {
	out := []portal.AccessGrant{}
	if db == nil || len(edges) == 0 {
		return out
	}
	now := time.Now().UTC()
	marks := strings.TrimSuffix(strings.Repeat("?,", len(edges)), ",")
	args := []any{accessApproved}
	for _, e := range edges {
		args = append(args, e)
	}
	rows, err := db.Query(`SELECT user_id, target_id, expires_at FROM portal_access_requests
		WHERE status=? AND edge_name IN (`+marks+`)`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var g portal.AccessGrant
		if rows.Scan(&g.UserID, &g.TargetID, &g.ExpiresAt) != nil {
			continue
		}
		if exp, err := time.Parse(time.RFC3339, g.ExpiresAt); err == nil && exp.After(now) {
			out = append(out, g)
		}
	}
	return out
}

func (h *PortalHandler) handleAccessRequests(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/portal/access-requests"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
			return
		}
		h.listAccessRequests(w, r)
		return
	}
	id, action, _ := strings.Cut(rest, "/")
	if r.Method != http.MethodPost || (action != "approve" && action != "deny" && action != "revoke") {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	h.decideAccessRequest(w, r, id, action)
}

func (h *PortalHandler) listAccessRequests(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	q := `SELECT id, edge_name, user_id, username, target_id, target_name, reason, duration_min, status,
		created_at, decided_by, decided_at, expires_at FROM portal_access_requests WHERE edge_name=?`
	args := []any{edge}
	if st := strings.TrimSpace(r.URL.Query().Get("status")); st != "" {
		q += ` AND status=?`
		args = append(args, st)
	}
	rows, err := h.DB.Query(q+` ORDER BY created_at DESC LIMIT 200`, args...)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	now := time.Now().UTC()
	out := []PortalAccessRequest{}
	for rows.Next() {
		var a PortalAccessRequest
		if rows.Scan(&a.ID, &a.EdgeName, &a.UserID, &a.Username, &a.TargetID, &a.TargetName, &a.Reason,
			&a.DurationMin, &a.Status, &a.CreatedAt, &a.DecidedBy, &a.DecidedAt, &a.ExpiresAt) != nil {
			continue
		}
		if a.Status == accessApproved {
			if exp, err := time.Parse(time.RFC3339, a.ExpiresAt); err == nil && !exp.After(now) {
				a.Status = "expired"
			}
		}
		out = append(out, a)
	}
	jsonOK(w, map[string]any{"requests": out})
}

func (h *PortalHandler) decideAccessRequest(w http.ResponseWriter, r *http.Request, id, action string) {
	var edge, status string
	var dur int
	err := h.DB.QueryRow(`SELECT edge_name, status, duration_min FROM portal_access_requests WHERE id=?`, id).Scan(&edge, &status, &dur)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	now := time.Now().UTC()
	actor := adminauth.ActorFromContext(r.Context())
	var newStatus, expires string
	switch action {
	case "approve":
		if status != accessPending {
			writeErr(w, r, http.StatusConflict, "api.err.conflict")
			return
		}
		var body struct {
			DurationMin int `json:"duration_min"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.DurationMin > 0 {
			dur = body.DurationMin
		}
		if dur <= 0 || dur > maxApprovalMin {
			writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
			return
		}
		newStatus, expires = accessApproved, now.Add(time.Duration(dur)*time.Minute).Format(time.RFC3339)
	case "deny":
		if status != accessPending {
			writeErr(w, r, http.StatusConflict, "api.err.conflict")
			return
		}
		newStatus = accessDenied
	case "revoke":
		if status != accessApproved {
			writeErr(w, r, http.StatusConflict, "api.err.conflict")
			return
		}
		newStatus = accessRevoked
	}
	if _, err := h.DB.Exec(`UPDATE portal_access_requests SET status=?, decided_by=?, decided_at=?,
		expires_at=CASE WHEN ?<>'' THEN ? ELSE expires_at END WHERE id=?`,
		newStatus, actor, now.Format(time.RFC3339), expires, expires, id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, actor, action, "portal_access_request", id)
	if action != "deny" {
		h.pushScope(r.Context(), h.scope(edge))
	}
	w.WriteHeader(http.StatusNoContent)
}

// PortalAccessRecipients retourne les adresses des administrateurs à prévenir d'une nouvelle demande.
func PortalAccessRecipients(db *sql.DB) []string {
	out := []string{}
	if db == nil {
		return out
	}
	rows, err := db.Query(`SELECT email FROM users WHERE role IN ('admin','superadmin') AND email LIKE '%@%' ORDER BY email`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var e string
		if rows.Scan(&e) == nil {
			out = append(out, e)
		}
	}
	return out
}
