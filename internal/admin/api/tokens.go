// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// TokensHandler gère la création, la liste, la révocation des tokens d'appairage
// et la gestion des scopes RBAC par token.
type TokensHandler struct {
	DB            *sql.DB
	Log           *slog.Logger
	Cores         CoreConnector // optionnel — enregistre les Cores WS dès qu'un endpoint est fourni
	Pusher        ScopePusher   // optionnel — re-pousse routes/certs après mutation de périmètre
	OnAgentRevoke func(agentID string) // optionnel — ferme la WS Agent sur les Cores
}

// CoreConnector est implémenté par corews.Manager.
type CoreConnector interface {
	Register(coreID, nodeName, endpoint, rbacRole string)
	Unregister(coreID string)
}

// ScopePusher resynchronise les Cores après un changement de token_scopes.
type ScopePusher interface {
	PushRoutes(ctx context.Context)
	PushCerts(ctx context.Context)
}

func (h *TokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens")
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
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPost && id == "purge-expired":
		h.purgeExpired(w, r)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		if r.URL.Query().Get("permanent") == "true" {
			h.deletePermanent(w, r, id)
		} else {
			h.revoke(w, r, id)
		}
	// Scopes RBAC du token
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

type tokenRow struct {
	ID           string     `json:"id"`
	Token        string     `json:"token"`
	Role         string     `json:"role"`
	RBACRole     string     `json:"rbac_role"`
	NodeName     string     `json:"node_name"`
	NodeEndpoint string     `json:"node_endpoint,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	Revoked      bool       `json:"revoked"`
}

func (h *TokensHandler) list(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")

	q := `SELECT id, token, role, COALESCE(rbac_role,'admin'), node_name,
	             COALESCE(node_endpoint,''), expires_at, created_at, revoked
	      FROM tokens`
	args := []any{}
	if role != "" {
		q += ` WHERE role = ?`
		args = append(args, role)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := h.DB.QueryContext(r.Context(), q, args...)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("tokens: list", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]tokenRow, 0)
	for rows.Next() {
		var t tokenRow
		var revoked int
		var expiresAt sql.NullTime
		if err := rows.Scan(&t.ID, &t.Token, &t.Role, &t.RBACRole, &t.NodeName,
			&t.NodeEndpoint, &expiresAt, &t.CreatedAt, &revoked); err != nil {
			continue
		}
		t.Revoked = revoked == 1
		if expiresAt.Valid {
			t.ExpiresAt = &expiresAt.Time
		}
		// Ne jamais renvoyer le secret (clair ou chiffré) en liste — visible à la création seulement.
		t.Token = ""
		result = append(result, t)
	}
	jsonOK(w, result)
}

type createTokenRequest struct {
	Role         string `json:"role"`
	RBACRole     string `json:"rbac_role"`
	NodeName     string `json:"node_name"`
	NodeEndpoint string `json:"node_endpoint"`
	TTLHours     int    `json:"ttl_hours"`
}

func (h *TokensHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.Role != "core" && req.Role != "agent" {
		writeErr(w, r, http.StatusBadRequest, "api.err.role_core_agent")
		return
	}
	if req.NodeName == "" {
		http.Error(w, "node_name requis", http.StatusBadRequest)
		return
	}
	if req.RBACRole == "" {
		req.RBACRole = "admin"
	}
	if req.RBACRole != "admin" && req.RBACRole != "operator" && req.RBACRole != "viewer" {
		writeErr(w, r, http.StatusBadRequest, "api.err.rbac_role")
		return
	}

	tok := adminauth.GenerateToken(req.Role, req.NodeName)
	id := uuid.New().String()

	endpoint := normalizeCoreEndpoint(req.NodeEndpoint)

	var expiresAt *time.Time
	if req.TTLHours > 0 {
		t := time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
		expiresAt = &t
	}

	stored, hash := adminauth.PrepareNodeTokenForStore(tok)
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name, node_endpoint, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, stored, hash, req.Role, req.RBACRole, req.NodeName, endpoint, expiresAt,
	)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("tokens: create", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	if h.Cores != nil && req.Role == "core" && endpoint != "" {
		h.Cores.Register(id, req.NodeName, endpoint, req.RBACRole)
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "token:"+id, req.Role+"/"+req.NodeName+"/"+req.RBACRole)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(tokenRow{
		ID:           id,
		Token:        tok,
		Role:         req.Role,
		RBACRole:     req.RBACRole,
		NodeName:     req.NodeName,
		NodeEndpoint: endpoint,
		ExpiresAt:    expiresAt,
	})
}

// normalizeCoreEndpoint accepte "10.0.0.1", "10.0.0.1:8000" ou une URL complète.
func normalizeCoreEndpoint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		if !strings.Contains(raw, ":") {
			raw = raw + ":8000"
		}
		raw = "http://" + raw
	}
	return raw
}

func (h *TokensHandler) revoke(w http.ResponseWriter, r *http.Request, id string) {
	var role, nodeName string
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT role, COALESCE(node_name,'') FROM tokens WHERE id=?`, id,
	).Scan(&role, &nodeName)

	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE tokens SET revoked=1 WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("tokens: revoke", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.token_not_found")
		return
	}
	if h.Cores != nil {
		h.Cores.Unregister(id)
	}
	if role == "agent" && h.OnAgentRevoke != nil {
		agentID := nodeName
		if agentID == "" {
			agentID = id
		}
		h.OnAgentRevoke(agentID)
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "revoke", "token:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *TokensHandler) deletePermanent(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM tokens WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("tokens: delete permanent", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.token_not_found")
		return
	}
	if h.Cores != nil {
		h.Cores.Unregister(id)
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete_permanent", "token:"+id, "")

	w.WriteHeader(http.StatusNoContent)
}

type purgeExpiredRequest struct {
	Days int `json:"days"`
}

func (h *TokensHandler) purgeExpired(w http.ResponseWriter, r *http.Request) {
	var req purgeExpiredRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Days < 1 {
		writeErr(w, r, http.StatusBadRequest, "api.err.days_min")
		return
	}
	cutoff := time.Now().AddDate(0, 0, -req.Days)
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM tokens WHERE
		   (revoked=1 AND created_at < ?)
		   OR (expires_at IS NOT NULL AND expires_at < ?)`,
		cutoff, cutoff,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("tokens: purge expired", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "purge_expired_tokens", "tokens",
		fmt.Sprintf("deleted=%d days=%d", n, req.Days))

	jsonOK(w, map[string]any{"deleted": n})
}

// --- Scopes RBAC d'un token ---

type tokenScopeRow struct {
	ID        string `json:"id"`
	ScopeType string `json:"scope_type"`
	Value     string `json:"value"`
}

func (h *TokensHandler) listScopes(w http.ResponseWriter, r *http.Request, tokenID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, scope_type, scope_value FROM token_scopes WHERE token_id=?
		 ORDER BY scope_type, scope_value`, tokenID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]tokenScopeRow, 0)
	for rows.Next() {
		var s tokenScopeRow
		if err := rows.Scan(&s.ID, &s.ScopeType, &s.Value); err == nil {
			result = append(result, s)
		}
	}
	jsonOK(w, result)
}

func (h *TokensHandler) addScope(w http.ResponseWriter, r *http.Request, tokenID string) {
	var req struct {
		ScopeType string `json:"scope_type"`
		Value     string `json:"value"`
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
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO token_scopes (id, token_id, scope_type, scope_value) VALUES (?, ?, ?, ?)`,
		id, tokenID, req.ScopeType, req.Value); err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.scope_exists")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "add_token_scope", "token:"+tokenID, req.ScopeType+":"+req.Value)
	h.resyncAfterScopeChange()
	s := tokenScopeRow{ID: id, ScopeType: req.ScopeType, Value: req.Value}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(s)
}

func (h *TokensHandler) removeScope(w http.ResponseWriter, r *http.Request, tokenID, scopeID string) {
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM token_scopes WHERE id=? AND token_id=?`, scopeID, tokenID)
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
	_ = admindb.WriteAudit(h.DB, actor, "remove_token_scope", "token:"+tokenID, scopeID)
	h.resyncAfterScopeChange()
	w.WriteHeader(http.StatusNoContent)
}

// resyncAfterScopeChange pousse routes + certs filtrés aux Cores (périmètre à jour).
func (h *TokensHandler) resyncAfterScopeChange() {
	if h.Pusher == nil {
		return
	}
	go func() {
		ctx := context.Background()
		h.Pusher.PushRoutes(ctx)
		h.Pusher.PushCerts(ctx)
	}()
}
