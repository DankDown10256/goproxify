// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mfa"
)

// MFASettingsHandler gère la configuration SMS et WebAuthn (admin uniquement).
type MFASettingsHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *MFASettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/settings/mfa")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "sms" && r.Method == http.MethodGet:
		h.getSMS(w, r)
	case path == "sms" && r.Method == http.MethodPut:
		h.putSMS(w, r)
	case path == "webauthn" && r.Method == http.MethodGet:
		h.getWebAuthn(w, r)
	case path == "webauthn" && r.Method == http.MethodPut:
		h.putWebAuthn(w, r)
	default:
		http.Error(w, "route inconnue", http.StatusNotFound)
	}
}

func (h *MFASettingsHandler) getSMS(w http.ResponseWriter, r *http.Request) {
	raw := admindb.GetSetting(h.DB, "mfa.sms", "{}")
	var cfg mfa.SMSConfig
	json.Unmarshal([]byte(raw), &cfg) //nolint:errcheck
	// Masquer la clé secrète dans la réponse
	if cfg.APISecret != "" {
		cfg.APISecret = "••••••••"
	}
	jsonOK(w, cfg)
}

func (h *MFASettingsHandler) putSMS(w http.ResponseWriter, r *http.Request) {
	var cfg mfa.SMSConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	// Si le secret est masqué (non modifié), on recharge l'existant
	if cfg.APISecret == "••••••••" {
		raw := admindb.GetSetting(h.DB, "mfa.sms", "{}")
		var existing mfa.SMSConfig
		json.Unmarshal([]byte(raw), &existing) //nolint:errcheck
		cfg.APISecret = existing.APISecret
	}
	b, _ := json.Marshal(cfg)
	if err := admindb.SetSetting(h.DB, "mfa.sms", string(b)); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type webAuthnSettings struct {
	RPID        string `json:"rp_id"`
	RPOrigin    string `json:"rp_origin"`
	DisplayName string `json:"display_name"`
}

func (h *MFASettingsHandler) getWebAuthn(w http.ResponseWriter, r *http.Request) {
	raw := admindb.GetSetting(h.DB, "mfa.webauthn", "{}")
	var cfg webAuthnSettings
	json.Unmarshal([]byte(raw), &cfg) //nolint:errcheck
	jsonOK(w, cfg)
}

func (h *MFASettingsHandler) putWebAuthn(w http.ResponseWriter, r *http.Request) {
	var cfg webAuthnSettings
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	b, _ := json.Marshal(cfg)
	if err := admindb.SetSetting(h.DB, "mfa.webauthn", string(b)); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	// Stocker aussi séparément pour que le server.go les lise au démarrage
	admindb.SetSetting(h.DB, "mfa.webauthn.rpid", cfg.RPID)       //nolint:errcheck
	admindb.SetSetting(h.DB, "mfa.webauthn.origin", cfg.RPOrigin) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}
