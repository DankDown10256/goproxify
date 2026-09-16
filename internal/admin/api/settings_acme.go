// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/acme"
)

// ACMESettingsHandler GET/PUT /api/v1/settings/acme.
type ACMESettingsHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	OnUpdate func(cfg acme.DBConfig) // appelé après PUT ; permet de réinitialiser le Manager
}

func (h *ACMESettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPut:
		h.put(w, r)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method_not_allowed")
	}
}

func (h *ACMESettingsHandler) get(w http.ResponseWriter, r *http.Request) {
	cfg := acme.LoadConfig(h.DB)
	jsonOK(w, map[string]any{
		"enabled":       cfg.Enabled,
		"email":         cfg.Email,
		"directory_url": cfg.DirectoryURL,
		"dns_type":      cfg.DNSType,
	})
}

func (h *ACMESettingsHandler) put(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled      bool   `json:"enabled"`
		Email        string `json:"email"`
		DirectoryURL string `json:"directory_url"`
		DNSType      string `json:"dns_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	cfg := acme.DBConfig{
		Enabled:      body.Enabled,
		Email:        body.Email,
		DirectoryURL: body.DirectoryURL,
		DNSType:      body.DNSType,
	}
	if err := acme.SaveConfig(h.DB, cfg); err != nil {
		h.Log.Error("acme settings: sauvegarde DB", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.OnUpdate != nil {
		h.OnUpdate(cfg)
	}
	h.Log.Info("acme settings: mis à jour", "enabled", cfg.Enabled, "email", cfg.Email)
	w.WriteHeader(http.StatusNoContent)
}
