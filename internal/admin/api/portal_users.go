// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mailer"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

// PortalUser row Admin (sans secrets).
type PortalUser struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Status    string   `json:"status"`
	Tags      []string `json:"tags"`
	HomeEdge  string   `json:"home_edge"`
	ExpiresAt string   `json:"invite_expires,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

func (h *PortalHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/portal/users")
	rest = strings.Trim(rest, "/")

	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.listPortalUsers(w, r)
	case rest == "invite" && r.Method == http.MethodPost:
		h.invitePortalUser(w, r)
	case strings.HasSuffix(rest, "/resend") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(rest, "/resend")
		id = strings.Trim(id, "/")
		h.resendPortalInvite(w, r, id)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodGet:
		h.getPortalUser(w, r, rest)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodPut:
		h.updatePortalUser(w, r, rest)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodDelete:
		h.deletePortalUser(w, r, rest)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PortalHandler) listPortalUsers(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	q := `SELECT id, email, status, tags_json, home_edge, invite_expires, created_at, updated_at FROM portal_users`
	var rows *sql.Rows
	var err error
	if edge != "" {
		rows, err = h.DB.Query(q+` WHERE home_edge=? ORDER BY email`, edge)
	} else {
		rows, err = h.DB.Query(q + ` ORDER BY home_edge, email`)
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []PortalUser{}
	for rows.Next() {
		u, err := scanPortalUser(rows)
		if err != nil {
			continue
		}
		out = append(out, u)
	}
	jsonOK(w, map[string]any{"users": out})
}

func (h *PortalHandler) getPortalUser(w http.ResponseWriter, r *http.Request, id string) {
	row := h.DB.QueryRow(`SELECT id, email, status, tags_json, home_edge, invite_expires, created_at, updated_at
		FROM portal_users WHERE id=?`, id)
	u, err := scanPortalUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, u)
}

func (h *PortalHandler) invitePortalUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string   `json:"email"`
		Tags     []string `json:"tags"`
		HomeEdge string   `json:"home_edge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	home := strings.TrimSpace(body.HomeEdge)
	if email == "" || !strings.Contains(email, "@") {
		http.Error(w, "email invalide", http.StatusBadRequest)
		return
	}
	if home == "" {
		home = portalEdgeParam(r)
	}
	if home == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	if !mailer.Load(h.DB).Configured() {
		http.Error(w, mailer.ErrNotConfigured.Error(), http.StatusBadRequest)
		return
	}
	cfg := loadPortalConfig(h.DB, home)
	if strings.TrimSpace(cfg.PublicHost) == "" {
		http.Error(w, "hôte public du portail requis (Options portail → Hôte public)", http.StatusBadRequest)
		return
	}
	rawTok, err := portal.NewInviteToken()
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	expires := portal.InviteExpiryRFC3339()
	id := uuid.NewString()
	tagsJSON, _ := json.Marshal(normalizeTags(body.Tags))
	_, err = h.DB.Exec(`INSERT INTO portal_users (id, email, status, tags_json, invite_token_hash, invite_expires, home_edge)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, email, portal.UserStatusInvited, string(tagsJSON), portal.HashInviteToken(rawTok), expires, home)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			http.Error(w, "email déjà enregistré", http.StatusConflict)
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err := h.sendInviteEmail(email, cfg.PublicHost, rawTok); err != nil {
		_, _ = h.DB.Exec(`DELETE FROM portal_users WHERE id=?`, id)
		http.Error(w, "envoi email: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "invite", "portal_user", email)
	h.pushUsersForEdge(r, home)
	u, _ := h.loadPortalUser(id)
	jsonOK(w, u)
}

func (h *PortalHandler) resendPortalInvite(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.loadPortalUser(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if u.Status == portal.UserStatusDisabled {
		http.Error(w, "compte désactivé", http.StatusBadRequest)
		return
	}
	if !mailer.Load(h.DB).Configured() {
		http.Error(w, mailer.ErrNotConfigured.Error(), http.StatusBadRequest)
		return
	}
	cfg := loadPortalConfig(h.DB, u.HomeEdge)
	if strings.TrimSpace(cfg.PublicHost) == "" {
		http.Error(w, "hôte public du portail requis", http.StatusBadRequest)
		return
	}
	rawTok, err := portal.NewInviteToken()
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	expires := portal.InviteExpiryRFC3339()
	_, err = h.DB.Exec(`UPDATE portal_users SET status=?, invite_token_hash=?, invite_expires=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		portal.UserStatusInvited, portal.HashInviteToken(rawTok), expires, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err := h.sendInviteEmail(u.Email, cfg.PublicHost, rawTok); err != nil {
		http.Error(w, "envoi email: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "resend_invite", "portal_user", u.Email)
	h.pushUsersForEdge(r, u.HomeEdge)
	out, _ := h.loadPortalUser(id)
	jsonOK(w, out)
}

func (h *PortalHandler) updatePortalUser(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.loadPortalUser(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	var body struct {
		Tags     *[]string `json:"tags"`
		Status   *string   `json:"status"`
		HomeEdge *string   `json:"home_edge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	tags := u.Tags
	if body.Tags != nil {
		tags = normalizeTags(*body.Tags)
	}
	status := u.Status
	if body.Status != nil {
		s := strings.TrimSpace(*body.Status)
		switch s {
		case portal.UserStatusActive, portal.UserStatusInvited, portal.UserStatusDisabled:
			status = s
		default:
			http.Error(w, "status invalide", http.StatusBadRequest)
			return
		}
	}
	home := u.HomeEdge
	if body.HomeEdge != nil && strings.TrimSpace(*body.HomeEdge) != "" {
		home = strings.TrimSpace(*body.HomeEdge)
	}
	tagsJSON, _ := json.Marshal(tags)
	_, err = h.DB.Exec(`UPDATE portal_users SET tags_json=?, status=?, home_edge=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		string(tagsJSON), status, home, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal_user", u.Email)
	if u.HomeEdge != home {
		h.pushUsersForEdge(r, u.HomeEdge)
	}
	h.pushUsersForEdge(r, home)
	out, _ := h.loadPortalUser(id)
	jsonOK(w, out)
}

func (h *PortalHandler) deletePortalUser(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.loadPortalUser(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_, err = h.DB.Exec(`DELETE FROM portal_users WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_user", u.Email)
	h.pushUsersForEdge(r, u.HomeEdge)
	w.WriteHeader(http.StatusNoContent)
}

func (h *PortalHandler) sendInviteEmail(email, publicHost, rawToken string) error {
	link := "https://" + strings.TrimSuffix(strings.TrimSpace(publicHost), "/") + "/?invite=" + rawToken
	subject := "Invitation GoProxify Access"
	body := "Bonjour,\n\nVous êtes invité(e) sur GoProxify Access.\n" +
		"Ouvrez ce lien pour choisir votre mot de passe (valide 72 h) :\n\n" +
		link + "\n\nSi vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
	return mailer.Send(h.DB, email, subject, body)
}

func (h *PortalHandler) pushUsersForEdge(r *http.Request, edge string) {
	if h.Pusher == nil || edge == "" {
		return
	}
	cfg := loadPortalConfig(h.DB, edge)
	h.Pusher.PushPortal(r.Context(), edge, cfg)
}

func (h *PortalHandler) loadPortalUser(id string) (PortalUser, error) {
	row := h.DB.QueryRow(`SELECT id, email, status, tags_json, home_edge, invite_expires, created_at, updated_at
		FROM portal_users WHERE id=?`, id)
	return scanPortalUser(row)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanPortalUser(row scannable) (PortalUser, error) {
	var u PortalUser
	var tagsJSON string
	var created, updated sql.NullString
	if err := row.Scan(&u.ID, &u.Email, &u.Status, &tagsJSON, &u.HomeEdge, &u.ExpiresAt, &created, &updated); err != nil {
		return u, err
	}
	_ = json.Unmarshal([]byte(tagsJSON), &u.Tags)
	if u.Tags == nil {
		u.Tags = []string{}
	}
	if created.Valid {
		u.CreatedAt = created.String
	}
	if updated.Valid {
		u.UpdatedAt = updated.String
	}
	return u, nil
}

// listSyncedUsersForEdge prépare le payload push passerelle.
func listSyncedUsersForEdge(db *sql.DB, edge string) []portal.SyncedUser {
	rows, err := db.Query(`SELECT id, email, status, tags_json, invite_token_hash, invite_expires
		FROM portal_users WHERE home_edge=?`, edge)
	if err != nil {
		return []portal.SyncedUser{}
	}
	defer rows.Close()
	out := []portal.SyncedUser{}
	for rows.Next() {
		var su portal.SyncedUser
		var tagsJSON string
		if err := rows.Scan(&su.ID, &su.Email, &su.Status, &tagsJSON, &su.InviteTokenHash, &su.InviteExpires); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(tagsJSON), &su.Tags)
		if su.Tags == nil {
			su.Tags = []string{}
		}
		if su.Status == portal.UserStatusActive {
			su.InviteTokenHash = ""
			su.InviteExpires = ""
		}
		out = append(out, su)
	}
	return out
}

// MarkPortalInviteCompleted met à jour le statut après complete-invite passerelle.
func MarkPortalInviteCompleted(db *sql.DB, userID string) {
	if db == nil || userID == "" {
		return
	}
	_, _ = db.Exec(`UPDATE portal_users SET status=?, invite_token_hash='', invite_expires='', updated_at=CURRENT_TIMESTAMP
		WHERE id=? AND status=?`, portal.UserStatusActive, userID, portal.UserStatusInvited)
}