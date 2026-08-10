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
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// UserTokensHandler gère /api/v1/me/tokens — PAT self-service.
type UserTokensHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type userTokenRow struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Revoked    bool       `json:"revoked"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (h *UserTokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID := adminauth.UserIDFromContext(r.Context())
	if userID == "" {
		writeErr(w, r, http.StatusUnauthorized, "api.err.unauth")
		return
	}
	// Création / liste / révocation réservées à la session UI (JWT), pas aux PAT.
	if adminauth.IsPATAuth(r.Context()) {
		writeErr(w, r, http.StatusForbidden, "api.err.tokens_ui_only")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/me/tokens")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "scopes":
		h.listAvailableScopes(w, r, userID)
	case r.Method == http.MethodGet && path == "":
		h.list(w, r, userID)
	case r.Method == http.MethodPost && path == "":
		h.create(w, r, userID)
	case r.Method == http.MethodDelete && path != "":
		h.revoke(w, r, userID, path)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *UserTokensHandler) listAvailableScopes(w http.ResponseWriter, r *http.Request, userID string) {
	available := rbac.AvailableScopesForUser(r.Context(), h.DB, userID)
	availSet := map[string]bool{}
	for _, s := range available {
		availSet[s] = true
	}
	catalog := rbac.ScopeCatalog()
	type item struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Available   bool   `json:"available"`
	}
	out := make([]item, 0, len(catalog))
	for _, c := range catalog {
		out = append(out, item{ID: c.ID, Description: c.Description, Available: availSet[c.ID]})
	}
	jsonOK(w, out)
}

func (h *UserTokensHandler) list(w http.ResponseWriter, r *http.Request, userID string) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id, label, token_prefix, expires_at, revoked, last_used_at, created_at
		FROM user_api_tokens
		WHERE user_id = ?
		ORDER BY created_at DESC`, userID)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("user_tokens: list", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]userTokenRow, 0)
	for rows.Next() {
		var t userTokenRow
		var revoked int
		var expires, lastUsed sql.NullTime
		if err := rows.Scan(&t.ID, &t.Label, &t.Prefix, &expires, &revoked, &lastUsed, &t.CreatedAt); err != nil {
			continue
		}
		t.Revoked = revoked == 1
		if expires.Valid {
			t.ExpiresAt = &expires.Time
		}
		if lastUsed.Valid {
			t.LastUsedAt = &lastUsed.Time
		}
		t.Scopes = h.loadScopes(r, t.ID)
		result = append(result, t)
	}
	jsonOK(w, result)
}

func (h *UserTokensHandler) loadScopes(r *http.Request, tokenID string) []string {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT scope FROM user_api_token_scopes WHERE token_id = ? ORDER BY scope`, tokenID)
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	return out
}

type createUserTokenReq struct {
	Label     string   `json:"label"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"` // RFC3339 ou null
}

func (h *UserTokensHandler) create(w http.ResponseWriter, r *http.Request, userID string) {
	var req createUserTokenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		http.Error(w, "label requis", http.StatusBadRequest)
		return
	}
	if len(req.Scopes) == 0 {
		http.Error(w, "au moins un scope requis", http.StatusBadRequest)
		return
	}

	seen := map[string]bool{}
	var scopes []string
	for _, s := range req.Scopes {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if !rbac.IsKnownScope(s) {
			http.Error(w, "scope inconnu: "+s, http.StatusBadRequest)
			return
		}
		if !rbac.UserCanHoldScope(r.Context(), h.DB, userID, s) {
			http.Error(w, "scope non autorisé pour votre compte: "+s, http.StatusForbidden)
			return
		}
		seen[s] = true
		scopes = append(scopes, s)
	}
	if len(scopes) == 0 {
		http.Error(w, "au moins un scope requis", http.StatusBadRequest)
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil && strings.TrimSpace(*req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.ExpiresAt))
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "api.err.expires_rfc3339")
			return
		}
		if !t.After(time.Now().UTC()) {
			writeErr(w, r, http.StatusBadRequest, "api.err.expires_future")
			return
		}
		expiresAt = &t
	}

	plain := adminauth.GeneratePAT()
	hash := adminauth.HashPAT(plain)
	prefix := adminauth.PATPreview(plain)
	id := uuid.New().String()

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, label, hash, prefix, expiresAt)
	if err != nil {
		h.Log.Error("user_tokens: insert", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	for _, s := range scopes {
		if _, err := tx.ExecContext(r.Context(),
			`INSERT INTO user_api_token_scopes (token_id, scope) VALUES (?, ?)`, id, s); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	_ = admindb.WriteAudit(h.DB, userID, "create", "user_api_token:"+id, label)

	resp := map[string]any{
		"id":         id,
		"label":      label,
		"prefix":     prefix,
		"scopes":     scopes,
		"token":      plain, // une seule fois
		"expires_at": expiresAt,
		"created_at": time.Now().UTC(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func (h *UserTokensHandler) revoke(w http.ResponseWriter, r *http.Request, userID, id string) {
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE user_api_tokens SET revoked = 1 WHERE id = ? AND user_id = ? AND revoked = 0`,
		id, userID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.token_not_found")
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "revoke", "user_api_token:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}
