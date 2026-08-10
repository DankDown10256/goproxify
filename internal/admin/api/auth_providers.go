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

// AuthProvider est un fournisseur SSO/Auth partagé entre proxies.
type AuthProvider struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Provider  string          `json:"provider"` // oidc | github | ldap | ldap_ad | saml | basic | forward | authentik | authelia | ...
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// AuthProvidersHandler gère le CRUD HTTP des fournisseurs SSO.
type AuthProvidersHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *AuthProvidersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/auth-providers")
	path = strings.TrimPrefix(path, "/")
	id := strings.Split(path, "/")[0]

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodGet && id != "":
		h.get(w, r, id)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPut && id != "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *AuthProvidersHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, provider, config, enabled, created_at, updated_at FROM auth_providers ORDER BY name`)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: list", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]AuthProvider, 0)
	for rows.Next() {
		var ap AuthProvider
		var cfg string
		var enabled int
		if err := rows.Scan(&ap.ID, &ap.Name, &ap.Provider, &cfg, &enabled, &ap.CreatedAt, &ap.UpdatedAt); err != nil {
			continue
		}
		ap.Config = json.RawMessage(cfg)
		ap.Enabled = enabled == 1
		result = append(result, ap)
	}
	jsonOK(w, result)
}

func (h *AuthProvidersHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var ap AuthProvider
	var cfg string
	var enabled int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, provider, config, enabled, created_at, updated_at FROM auth_providers WHERE id=?`, id,
	).Scan(&ap.ID, &ap.Name, &ap.Provider, &cfg, &enabled, &ap.CreatedAt, &ap.UpdatedAt)
	if err == sql.ErrNoRows {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	ap.Config = json.RawMessage(cfg)
	ap.Enabled = enabled == 1
	jsonOK(w, ap)
}

type authProviderRequest struct {
	Name     string          `json:"name"`
	Provider string          `json:"provider"`
	Config   json.RawMessage `json:"config"`
	Enabled  *bool           `json:"enabled"`
}

func (h *AuthProvidersHandler) create(w http.ResponseWriter, r *http.Request) {
	var req authProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.Name == "" || req.Provider == "" {
		http.Error(w, "name et provider sont requis", http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	enabled := 1
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}

	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO auth_providers (id, name, provider, config, enabled) VALUES (?, ?, ?, ?, ?)`,
		id, req.Name, req.Provider, cfg, enabled,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: create", "err", err) }
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "auth_provider:"+id, req.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthProvider{ //nolint:errcheck
		ID: id, Name: req.Name, Provider: req.Provider,
		Config: req.Config, Enabled: enabled == 1,
	})
}

func (h *AuthProvidersHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req authProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}

	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	enabled := 1
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}

	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE auth_providers SET name=?, provider=?, config=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		req.Name, req.Provider, cfg, enabled, id,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: update", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "auth_provider:"+id, req.Name)

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthProvidersHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM auth_providers WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: delete", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "auth_provider:"+id, "")

	w.WriteHeader(http.StatusNoContent)
}
