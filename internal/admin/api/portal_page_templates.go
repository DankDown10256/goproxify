// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/core/portal"
)

// PortalPageTemplatePusher pousse les templates Access vers les Cores.
type PortalPageTemplatePusher interface {
	PushPortalTemplates(ctx context.Context)
}

// PortalPageTemplateDTO ligne Admin.
type PortalPageTemplateDTO struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Body      string    `json:"body"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PortalPageTemplatesHandler CRUD clés stables + sync Core.
type PortalPageTemplatesHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Pusher PortalPageTemplatePusher
}

func (h *PortalPageTemplatesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/portal-page-templates")
	path = strings.Trim(path, "/")
	if path == "push" && r.Method == http.MethodPost {
		h.push(w, r)
		return
	}
	parts := strings.Split(path, "/")
	key := parts[0]

	switch {
	case r.Method == http.MethodGet && key == "":
		h.list(w, r)
	case r.Method == http.MethodGet && key != "" && len(parts) == 1:
		h.get(w, r, key)
	case r.Method == http.MethodPut && key != "" && len(parts) == 1:
		h.put(w, r, key)
	case r.Method == http.MethodDelete && key != "" && len(parts) == 1:
		h.delete(w, r, key)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PortalPageTemplatesHandler) list(w http.ResponseWriter, r *http.Request) {
	byKey := loadPortalPageTemplatesMap(h.DB)
	out := make([]PortalPageTemplateDTO, 0, len(portal.PageTemplateKeys))
	for _, k := range portal.PageTemplateKeys {
		dto := PortalPageTemplateDTO{Key: k, Name: k}
		if t, ok := byKey[k]; ok {
			dto = t
		}
		out = append(out, dto)
	}
	jsonOK(w, map[string]any{"templates": out, "keys": portal.PageTemplateKeys})
}

func (h *PortalPageTemplatesHandler) get(w http.ResponseWriter, r *http.Request, key string) {
	if !portal.IsKnownPageKey(key) {
		http.Error(w, "clé inconnue", http.StatusBadRequest)
		return
	}
	byKey := loadPortalPageTemplatesMap(h.DB)
	if t, ok := byKey[key]; ok {
		jsonOK(w, t)
		return
	}
	jsonOK(w, PortalPageTemplateDTO{Key: key, Name: key, Body: ""})
}

func (h *PortalPageTemplatesHandler) put(w http.ResponseWriter, r *http.Request, key string) {
	if !portal.IsKnownPageKey(key) {
		http.Error(w, "clé inconnue", http.StatusBadRequest)
		return
	}
	var body struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = key
	}
	_, err := h.DB.Exec(`INSERT INTO portal_page_templates (page_key, name, body, updated_at)
		VALUES (?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(page_key) DO UPDATE SET name=excluded.name, body=excluded.body, updated_at=CURRENT_TIMESTAMP`,
		key, name, body.Body)
	if err != nil {
		h.Log.Error("portal-page-templates: put", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal_page_template", key)
	if h.Pusher != nil {
		h.Pusher.PushPortalTemplates(r.Context())
	}
	h.get(w, r, key)
}

func (h *PortalPageTemplatesHandler) delete(w http.ResponseWriter, r *http.Request, key string) {
	if !portal.IsKnownPageKey(key) {
		http.Error(w, "clé inconnue", http.StatusBadRequest)
		return
	}
	_, _ = h.DB.Exec(`DELETE FROM portal_page_templates WHERE page_key=?`, key)
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_page_template", key)
	if h.Pusher != nil {
		h.Pusher.PushPortalTemplates(r.Context())
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PortalPageTemplatesHandler) push(w http.ResponseWriter, r *http.Request) {
	if h.Pusher != nil {
		h.Pusher.PushPortalTemplates(r.Context())
	}
	jsonOK(w, map[string]any{"pushed": true})
}

func loadPortalPageTemplatesMap(db *sql.DB) map[string]PortalPageTemplateDTO {
	out := map[string]PortalPageTemplateDTO{}
	if db == nil {
		return out
	}
	rows, err := db.Query(`SELECT page_key, name, body, updated_at FROM portal_page_templates`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var t PortalPageTemplateDTO
		var updated sql.NullTime
		if err := rows.Scan(&t.Key, &t.Name, &t.Body, &updated); err != nil {
			continue
		}
		if updated.Valid {
			t.UpdatedAt = updated.Time
		}
		out[t.Key] = t
	}
	return out
}

// LoadPortalPageTemplatesForPush charge le payload WS.
func LoadPortalPageTemplatesForPush(db *sql.DB) []portal.PageTemplate {
	m := loadPortalPageTemplatesMap(db)
	out := make([]portal.PageTemplate, 0, len(portal.PageTemplateKeys))
	for _, k := range portal.PageTemplateKeys {
		t := portal.PageTemplate{Key: k, Name: k}
		if v, ok := m[k]; ok {
			t.Name = v.Name
			t.Body = v.Body
		}
		if strings.TrimSpace(t.Body) == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}
