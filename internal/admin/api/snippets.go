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

// Snippet est un profil réutilisable (IP, TLS, rate-limit, CORS, headers...).
// Il est référencé par son nom dans la config d'un proxy.
type Snippet struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`   // ip_filter | rate_limit | cors | headers | tls | geo_ip | bot | waf
	Config    json.RawMessage `json:"config"` // JSON libre selon le type
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// SnippetsHandler gère le CRUD HTTP des snippets.
type SnippetsHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *SnippetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/snippets")
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

func (h *SnippetsHandler) list(w http.ResponseWriter, r *http.Request) {
	typeFilter := r.URL.Query().Get("type")
	var (
		rows *sql.Rows
		err  error
	)
	if typeFilter != "" {
		rows, err = h.DB.QueryContext(r.Context(),
			`SELECT id, name, type, config, created_at, updated_at FROM snippets WHERE type=? ORDER BY name`,
			typeFilter)
	} else {
		rows, err = h.DB.QueryContext(r.Context(),
			`SELECT id, name, type, config, created_at, updated_at FROM snippets ORDER BY name`)
	}
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("snippets: list", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]Snippet, 0)
	for rows.Next() {
		var s Snippet
		var cfg string
		if err := rows.Scan(&s.ID, &s.Name, &s.Type, &cfg, &s.CreatedAt, &s.UpdatedAt); err != nil {
			continue
		}
		s.Config = json.RawMessage(cfg)
		result = append(result, s)
	}
	jsonOK(w, result)
}

func (h *SnippetsHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var s Snippet
	var cfg string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, type, config, created_at, updated_at FROM snippets WHERE id=?`, id,
	).Scan(&s.ID, &s.Name, &s.Type, &cfg, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	s.Config = json.RawMessage(cfg)
	jsonOK(w, s)
}

type snippetRequest struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

var validSnippetTypes = map[string]bool{
	"ip_filter": true, "rate_limit": true, "cors": true,
	"headers": true, "tls": true, "geo_ip": true, "bot": true, "waf": true,
}

func (h *SnippetsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req snippetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.Name == "" || !validSnippetTypes[req.Type] {
		http.Error(w, "name requis et type doit être : ip_filter | rate_limit | cors | headers | tls | geo_ip | bot | waf", http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO snippets (id, name, type, config) VALUES (?, ?, ?, ?)`,
		id, req.Name, req.Type, cfg,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("snippets: create", "err", err) }
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "snippet:"+id, req.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Snippet{ID: id, Name: req.Name, Type: req.Type, Config: req.Config}) //nolint:errcheck
}

func (h *SnippetsHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req snippetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}

	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE snippets SET name=?, type=?, config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		req.Name, req.Type, cfg, id,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("snippets: update", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "snippet:"+id, req.Name)

	w.WriteHeader(http.StatusNoContent)
}

func (h *SnippetsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM snippets WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("snippets: delete", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "snippet:"+id, "")

	w.WriteHeader(http.StatusNoContent)
}
