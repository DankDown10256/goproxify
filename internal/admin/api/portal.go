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
	"github.com/vincamok/goproxify/internal/edge/portal"
)

const settingPortalConfigPrefix = "portal.config."
const settingPortalConfigLegacy = "portal.config" // global pré-scopage ; lu une fois en fallback

// PortalConfig est la config Admin du portail d'accès pour une passerelle.
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
	EdgeName             string                 `json:"edge_name,omitempty"` // Passerelle cible (echo)
}

// PortalPusher pousse la config portail vers une passerelle précis.
type PortalPusher interface {
	PushPortal(ctx context.Context, edgeName string, payload any)
}

// PortalHandler gère GET/PUT /api/v1/portal?edge=<node_name>
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
	if r.URL.Path == "/api/v1/portal/enabled" || r.URL.Path == "/api/v1/portal/enabled/" {
		h.handleEnabled(w, r)
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

func portalEdgeParam(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("edge"))
}

func (h *PortalHandler) get(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	cfg := loadPortalConfig(h.DB, edge)
	jsonOK(w, cfg)
}

func (h *PortalHandler) put(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	var cfg PortalConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	cfg.EdgeName = edge
	normalizePortalConfig(&cfg)
	// Ne plus accepter catalog JSON comme source de vérité : synchro table → settings.
	migrateLegacyCatalogIntoDestinations(h.DB, edge, cfg.Catalog)
	cfg.Catalog = listDestinationsAsCatalog(h.DB, edge)
	raw, err := json.Marshal(cfg)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err := admindb.SetSetting(h.DB, settingPortalConfigPrefix+edge, string(raw)); err != nil {
		h.Log.Error("portal: save", "edge", edge, "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal", edge)
	if h.Pusher != nil {
		h.Pusher.PushPortal(r.Context(), edge, cfg)
	}
	jsonOK(w, cfg)
}

func (h *PortalHandler) push(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	cfg := loadPortalConfig(h.DB, edge)
	if h.Pusher != nil {
		h.Pusher.PushPortal(r.Context(), edge, cfg)
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

func loadPortalConfig(db *sql.DB, edgeName string) PortalConfig {
	cfg := PortalConfig{SSHPort: 2222, HTTPPort: 8444, EdgeName: edgeName}
	raw := admindb.GetSetting(db, settingPortalConfigPrefix+edgeName, "")
	if raw == "" {
		// Fallback one-shot : ancienne config globale (avant scopage par passerelle).
		raw = admindb.GetSetting(db, settingPortalConfigLegacy, "")
	}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	cfg.EdgeName = edgeName
	normalizePortalConfig(&cfg)
	migrateLegacyCatalogIntoDestinations(db, edgeName, cfg.Catalog)
	if dest := listDestinationsAsCatalog(db, edgeName); dest != nil {
		cfg.Catalog = dest
	} else {
		cfg.Catalog = []portal.CatalogTarget{}
	}
	cfg.Users = listSyncedUsersForEdge(db, edgeName)
	return cfg
}

// handleEnabled retourne {edges: {edgeName: true/false}} pour toutes les passerelles configurées.
func (h *PortalHandler) handleEnabled(w http.ResponseWriter, r *http.Request) {
	all := admindb.ListSettingsByPrefix(h.DB, settingPortalConfigPrefix)
	result := map[string]bool{}
	prefix := settingPortalConfigPrefix
	for key, raw := range all {
		edgeName := strings.TrimPrefix(key, prefix)
		if edgeName == "" {
			continue
		}
		var cfg PortalConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err == nil {
			result[edgeName] = cfg.Enabled
		}
	}
	jsonOK(w, map[string]any{"edges": result})
}

// LoadPortalConfigForEdge expose la config pour le full_sync WS.
func LoadPortalConfigForEdge(db *sql.DB, edgeName string) PortalConfig {
	return loadPortalConfig(db, edgeName)
}
