// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// TeamsHandler gère le CRUD des équipes et de leurs membres/scopes.
// Toutes les opérations d'écriture sont réservées aux administrateurs globaux
// (le middleware RequireAdmin est appliqué dans server.go).
type TeamsHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *TeamsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/teams")
	p = strings.TrimPrefix(p, "/")
	parts := strings.SplitN(p, "/", 3)
	id := parts[0]
	sub := ""
	subID := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	if len(parts) > 2 {
		subID = parts[2]
	}

	switch {
	// Équipes
	case r.Method == http.MethodGet && id == "":
		h.listTeams(w, r)
	case r.Method == http.MethodPost && id == "":
		h.createTeam(w, r)
	case r.Method == http.MethodGet && id != "" && sub == "":
		h.getTeam(w, r, id)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.updateTeam(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.deleteTeam(w, r, id)
	// Membres
	case r.Method == http.MethodGet && sub == "members":
		h.listMembers(w, r, id)
	case r.Method == http.MethodPost && sub == "members":
		h.addMember(w, r, id)
	case r.Method == http.MethodDelete && sub == "members" && subID != "":
		h.removeMember(w, r, id, subID)
	// Scopes
	case r.Method == http.MethodGet && sub == "scopes":
		h.listScopes(w, r, id)
	case r.Method == http.MethodPost && sub == "scopes":
		h.addScope(w, r, id)
	case r.Method == http.MethodDelete && sub == "scopes" && subID != "":
		h.removeScope(w, r, id, subID)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

// --- Équipes ---

type teamRow struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
	MemberCount int       `json:"member_count"`
	ScopeCount  int       `json:"scope_count"`
}

func (h *TeamsHandler) listTeams(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT t.id, t.name, t.created_at,
		       (SELECT COUNT(*) FROM team_members WHERE team_id=t.id) as member_count,
		       (SELECT COUNT(*) FROM team_scopes   WHERE team_id=t.id) as scope_count
		FROM teams t ORDER BY t.name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]teamRow, 0)
	for rows.Next() {
		var t teamRow
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.MemberCount, &t.ScopeCount); err == nil {
			result = append(result, t)
		}
	}
	jsonOK(w, result)
}

func (h *TeamsHandler) createTeam(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	t := teamRow{ID: uuid.New().String(), Name: req.Name}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO teams (id, name) VALUES (?, ?)`, t.ID, t.Name); err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "team:"+t.ID, t.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(t)
}

func (h *TeamsHandler) getTeam(w http.ResponseWriter, r *http.Request, id string) {
	var t teamRow
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, created_at FROM teams WHERE id=?`, id).Scan(&t.ID, &t.Name, &t.CreatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, t)
}

func (h *TeamsHandler) updateTeam(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE teams SET name=? WHERE id=?`, req.Name, id)
	if err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "team:"+id, req.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamsHandler) deleteTeam(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM teams WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	// Cascade manuelle (SQLite sans FK activées)
	h.DB.ExecContext(r.Context(), `DELETE FROM team_members WHERE team_id=?`, id) //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM team_scopes WHERE team_id=?`, id)  //nolint:errcheck
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "team:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- Membres ---

type memberRow struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

func (h *TeamsHandler) listMembers(w http.ResponseWriter, r *http.Request, teamID string) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT tm.user_id, u.email
		FROM team_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = ?
		ORDER BY u.email`, teamID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]memberRow, 0)
	for rows.Next() {
		var m memberRow
		if err := rows.Scan(&m.UserID, &m.Email); err == nil {
			result = append(result, m)
		}
	}
	jsonOK(w, result)
}

func (h *TeamsHandler) addMember(w http.ResponseWriter, r *http.Request, teamID string) {
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"` // ignoré (compat) — héritage intégral des grants équipe
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id requis", http.StatusBadRequest)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT OR REPLACE INTO team_members (team_id, user_id) VALUES (?, ?)`,
		teamID, req.UserID); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "add_member", "team:"+teamID, req.UserID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamsHandler) removeMember(w http.ResponseWriter, r *http.Request, teamID, userID string) {
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM team_members WHERE team_id=? AND user_id=?`, teamID, userID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "membre introuvable", http.StatusNotFound)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "remove_member", "team:"+teamID, userID)
	w.WriteHeader(http.StatusNoContent)
}

// --- Scopes ---

type scopeRow struct {
	ID         string `json:"id"`
	ScopeType  string `json:"scope_type"`
	Value      string `json:"value"`
	AccessMode string `json:"access_mode"`
}

func (h *TeamsHandler) listScopes(w http.ResponseWriter, r *http.Request, teamID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, scope_type, scope_value, access_mode FROM team_scopes WHERE team_id=? ORDER BY scope_type, scope_value`,
		teamID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]scopeRow, 0)
	for rows.Next() {
		var s scopeRow
		if err := rows.Scan(&s.ID, &s.ScopeType, &s.Value, &s.AccessMode); err == nil {
			result = append(result, s)
		}
	}
	jsonOK(w, result)
}

func (h *TeamsHandler) addScope(w http.ResponseWriter, r *http.Request, teamID string) {
	var req struct {
		ScopeType  string `json:"scope_type"`
		Value      string `json:"value"`
		AccessMode string `json:"access_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.ScopeType != "domain" && req.ScopeType != "server" && req.ScopeType != "proxy" && req.ScopeType != "core" {
		writeErr(w, r, http.StatusBadRequest, "api.err.scope_type")
		return
	}
	if req.Value == "" {
		http.Error(w, "value requis", http.StatusBadRequest)
		return
	}
	mode := "read"
	if req.AccessMode == "write" {
		mode = "write"
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO team_scopes (id, team_id, scope_type, scope_value, access_mode) VALUES (?, ?, ?, ?, ?)`,
		id, teamID, req.ScopeType, req.Value, mode); err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.scope_exists")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "add_scope", "team:"+teamID, req.ScopeType+":"+req.Value+":"+mode)
	s := scopeRow{ID: id, ScopeType: req.ScopeType, Value: req.Value, AccessMode: mode}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(s)
}

func (h *TeamsHandler) removeScope(w http.ResponseWriter, r *http.Request, teamID, scopeID string) {
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM team_scopes WHERE id=? AND team_id=?`, scopeID, teamID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "scope introuvable", http.StatusNotFound)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "remove_scope", "team:"+teamID, scopeID)
	w.WriteHeader(http.StatusNoContent)
}
