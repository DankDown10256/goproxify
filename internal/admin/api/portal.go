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

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/core/portal"
)

const settingPortalConfigPrefix = "portal.config."
const settingPortalConfigLegacy = "portal.config" // global pré-scopage ; lu une fois en fallback

// PortalConfig est la config Admin du portail d'accès pour un Core.
type PortalConfig struct {
	Enabled              bool                   `json:"enabled"`
	SSHPort              int                    `json:"ssh_port"`
	HTTPPort             int                    `json:"http_port"`
	PublicHost           string                 `json:"public_host"`
	AuthProviderID       string                 `json:"auth_provider_id"`
	AllowPersonalTargets bool                   `json:"allow_personal_targets"`
	Require2FA           bool                   `json:"require_2fa"`
	SessionTTLSec        int                    `json:"session_ttl_sec"`
	SessionMode          string                 `json:"session_mode"`
	Catalog              []portal.CatalogTarget `json:"catalog"`
	Users                []portal.SyncedUser    `json:"users,omitempty"`
	CoreName             string                 `json:"core_name,omitempty"` // Core cible (echo)
}

// PortalPusher pousse la config portail vers un Core précis.
type PortalPusher interface {
	PushPortal(ctx context.Context, coreName string, payload any)
}

// PortalHandler gère GET/PUT /api/v1/portal?core=<node_name>
// et /api/v1/portal/destinations…
type PortalHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Pusher PortalPusher
}

func (h *PortalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/v1/portal/users") {
		h.handleUsers(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/portal/destinations") {
		h.handleDestinations(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/portal/audit") {
		h.handleAudit(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPut:
		h.put(w, r)
	case http.MethodPost:
		if r.URL.Path == "/api/v1/portal/push" || r.URL.Path == "/api/v1/portal/push/" {
			h.push(w, r)
			return
		}
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func portalCoreParam(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("core"))
}

func (h *PortalHandler) get(w http.ResponseWriter, r *http.Request) {
	core := portalCoreParam(r)
	if core == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.core_required")
		return
	}
	cfg := loadPortalConfig(h.DB, core)
	jsonOK(w, cfg)
}

func (h *PortalHandler) put(w http.ResponseWriter, r *http.Request) {
	core := portalCoreParam(r)
	if core == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.core_required")
		return
	}
	var cfg PortalConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	cfg.CoreName = core
	normalizePortalConfig(&cfg)
	// Ne plus accepter catalog JSON comme source de vérité : synchro table → settings.
	migrateLegacyCatalogIntoDestinations(h.DB, core, cfg.Catalog)
	cfg.Catalog = listDestinationsAsCatalog(h.DB, core)
	raw, err := json.Marshal(cfg)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err := admindb.SetSetting(h.DB, settingPortalConfigPrefix+core, string(raw)); err != nil {
		h.Log.Error("portal: save", "core", core, "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal", core)
	if h.Pusher != nil {
		h.Pusher.PushPortal(r.Context(), core, cfg)
	}
	jsonOK(w, cfg)
}

func (h *PortalHandler) push(w http.ResponseWriter, r *http.Request) {
	core := portalCoreParam(r)
	if core == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.core_required")
		return
	}
	cfg := loadPortalConfig(h.DB, core)
	if h.Pusher != nil {
		h.Pusher.PushPortal(r.Context(), core, cfg)
	}
	jsonOK(w, map[string]any{"pushed": true, "config": cfg})
}

func normalizePortalConfig(cfg *PortalConfig) {
	if cfg.SSHPort <= 0 {
		cfg.SSHPort = 2222
	}
	if cfg.HTTPPort <= 0 {
		cfg.HTTPPort = 8444
	}
	if cfg.SessionTTLSec <= 0 {
		cfg.SessionTTLSec = 60
	}
	if cfg.SessionMode != portal.SessionModeMulti {
		cfg.SessionMode = portal.SessionModeOneShot
	}
}

func loadPortalConfig(db *sql.DB, coreName string) PortalConfig {
	cfg := PortalConfig{SSHPort: 2222, HTTPPort: 8444, CoreName: coreName}
	raw := admindb.GetSetting(db, settingPortalConfigPrefix+coreName, "")
	if raw == "" {
		// Fallback one-shot : ancienne config globale (avant scopage par Core).
		raw = admindb.GetSetting(db, settingPortalConfigLegacy, "")
	}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	cfg.CoreName = coreName
	normalizePortalConfig(&cfg)
	migrateLegacyCatalogIntoDestinations(db, coreName, cfg.Catalog)
	if dest := listDestinationsAsCatalog(db, coreName); dest != nil {
		cfg.Catalog = dest
	} else {
		cfg.Catalog = []portal.CatalogTarget{}
	}
	cfg.Users = listSyncedUsersForCore(db, coreName)
	return cfg
}

// LoadPortalConfigForCore expose la config pour le full_sync WS.
func LoadPortalConfigForCore(db *sql.DB, coreName string) PortalConfig {
	return loadPortalConfig(db, coreName)
}
