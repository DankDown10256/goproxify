// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/mailer"
)

// SMTPSettingsHandler GET/PUT /api/v1/settings/smtp (+ POST .../test).
type SMTPSettingsHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *SMTPSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/settings/smtp")
	path = strings.Trim(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.get(w, r)
	case path == "" && r.Method == http.MethodPut:
		h.put(w, r)
	case path == "test" && r.Method == http.MethodPost:
		h.test(w, r)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

func (h *SMTPSettingsHandler) get(w http.ResponseWriter, r *http.Request) {
	cfg := mailer.Load(h.DB)
	jsonOK(w, map[string]any{
		"configured": cfg.Configured(),
		"smtp":       cfg.PublicView(),
	})
}

func (h *SMTPSettingsHandler) put(w http.ResponseWriter, r *http.Request) {
	var body mailer.Config
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	if body.Password == "••••••••" {
		existing := mailer.Load(h.DB)
		body.Password = existing.Password
	}
	if err := mailer.Save(h.DB, body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := mailer.Load(h.DB)
	jsonOK(w, map[string]any{
		"configured": cfg.Configured(),
		"smtp":       cfg.PublicView(),
	})
}

func (h *SMTPSettingsHandler) test(w http.ResponseWriter, r *http.Request) {
	var body struct {
		To string `json:"to"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	to := strings.TrimSpace(body.To)
	if to == "" {
		http.Error(w, "destinataire (to) requis", http.StatusBadRequest)
		return
	}
	cfg := mailer.Load(h.DB)
	if !cfg.Configured() {
		http.Error(w, mailer.ErrNotConfigured.Error(), http.StatusServiceUnavailable)
		return
	}
	if err := mailer.SendWith(cfg, to, "[Goproxify] Test SMTP", "Ceci est un email de test SMTP Goproxify.\n"); err != nil {
		if h.Log != nil {
			h.Log.Warn("smtp test", "err", err)
		}
		http.Error(w, "envoi échoué: "+err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}
