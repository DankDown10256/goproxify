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

	"github.com/vincamok/goproxify/internal/admin/backup"
	"github.com/vincamok/goproxify/internal/admin/importer"
)

// BackupHandler gère les sauvegardes planifiées et l'historique des proxies.
type BackupHandler struct {
	DB        *sql.DB
	Log       *slog.Logger
	Scheduler *backup.Scheduler
	Pusher    RoutePusher
}

func (h *BackupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/backups")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	sub := parts[0]
	id := ""
	if len(parts) >= 2 {
		id = parts[1]
	}
	action := ""
	if len(parts) == 3 {
		action = parts[2]
	}

	switch {
	// Schedule
	case r.Method == http.MethodGet && sub == "schedule":
		h.getSchedule(w, r)
	case r.Method == http.MethodPut && sub == "schedule":
		h.putSchedule(w, r)
	// Snapshots
	case r.Method == http.MethodGet && sub == "snapshots" && id == "":
		h.listSnapshots(w, r)
	case r.Method == http.MethodPost && sub == "snapshots" && id == "":
		h.createSnapshot(w, r)
	case r.Method == http.MethodGet && sub == "snapshots" && id != "" && action == "":
		h.downloadSnapshot(w, r, id)
	case r.Method == http.MethodDelete && sub == "snapshots" && id != "" && action == "":
		h.deleteSnapshot(w, r, id)
	case r.Method == http.MethodPost && sub == "snapshots" && id != "" && action == "restore":
		h.restoreSnapshot(w, r, id)
	// Core routing table export
	case r.Method == http.MethodGet && sub == "core":
		h.exportCoreRoutes(w, r)
	// Proxy history
	case r.Method == http.MethodGet && sub == "proxy-history" && id != "" && action == "":
		h.listProxyHistory(w, r, id)
	case r.Method == http.MethodPost && sub == "proxy-history" && id != "" && action != "":
		h.restoreProxyVersion(w, r, action)
	default:
		http.NotFound(w, r)
	}
}

// ── Schedule ──────────────────────────────────────────────────────────────────

func (h *BackupHandler) getSchedule(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, h.Scheduler.GetConfig())
}

func (h *BackupHandler) putSchedule(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}

	// Format multi-planifications : {"schedules":[...]}
	var cfg backup.ScheduleConfig
	if err := json.Unmarshal(body, &cfg); err == nil && (cfg.Schedules != nil || strings.Contains(string(body), `"schedules"`)) {
		if err := h.Scheduler.SaveConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Compat ancien format mono-planning.
	var sched backup.Schedule
	if err := json.Unmarshal(body, &sched); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if err := h.Scheduler.SaveSchedule(sched); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

func (h *BackupHandler) listSnapshots(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, h.Scheduler.ListSnapshots())
}

func (h *BackupHandler) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "manuel-" + time.Now().Format("20060102-150405")
	}
	if err := h.Scheduler.TakeSnapshot(name, "", 0); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (h *BackupHandler) downloadSnapshot(w http.ResponseWriter, _ *http.Request, id string) {
	data, name, err := h.Scheduler.GetSnapshotData(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	fname := strings.ReplaceAll(name, " ", "-") + ".gpx-admin-backup"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+fname)
	w.Write(data) //nolint:errcheck
}

func (h *BackupHandler) deleteSnapshot(w http.ResponseWriter, _ *http.Request, id string) {
	if err := h.Scheduler.DeleteSnapshot(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BackupHandler) restoreSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	data, _, err := h.Scheduler.GetSnapshotData(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	bk, _, err := importer.SummarizeBackup(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sel := importer.ImportSelection{
		ImportUsers:    true,
		ImportTokens:   true,
		ImportSnippets: true,
		ImportChannels: true,
		ImportRules:    true,
		OnConflict:     "overwrite",
	}
	result := importer.Apply(h.DB, bk, sel)
	if h.Pusher != nil {
		go h.Pusher.PushRoutes(context.Background())
	}
	jsonOK(w, result)
}

// ── Core routing table export ─────────────────────────────────────────────────

func (h *BackupHandler) exportCoreRoutes(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `SELECT id, name, config, enabled FROM proxies ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type routeEntry struct {
		ID      string          `json:"id"`
		Name    string          `json:"name"`
		Config  json.RawMessage `json:"config"`
		Enabled bool            `json:"enabled"`
	}
	var routes []routeEntry
	for rows.Next() {
		var e routeEntry
		var cfg string
		var enabled int
		if rows.Scan(&e.ID, &e.Name, &cfg, &enabled) != nil {
			continue
		}
		e.Config = json.RawMessage(cfg)
		e.Enabled = enabled == 1
		routes = append(routes, e)
	}
	if routes == nil {
		routes = []routeEntry{}
	}
	payload := map[string]any{
		"version":    "1",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"routes":     routes,
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	ts := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=goproxify-routing-"+ts+".gpx-core-backup")
	w.Write(data) //nolint:errcheck
}

// ── Proxy history ─────────────────────────────────────────────────────────────

func (h *BackupHandler) listProxyHistory(w http.ResponseWriter, _ *http.Request, proxyID string) {
	jsonOK(w, h.Scheduler.ListProxyVersions(h.DB, proxyID))
}

func (h *BackupHandler) restoreProxyVersion(w http.ResponseWriter, r *http.Request, versionID string) {
	v, err := h.Scheduler.GetProxyVersion(h.DB, versionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_, err = h.DB.ExecContext(r.Context(),
		`UPDATE proxies SET config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		v.Config, v.ProxyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.Pusher != nil {
		go h.Pusher.PushRoutes(context.Background())
	}
	jsonOK(w, map[string]string{"proxy_id": v.ProxyID, "restored_version": versionID})
}
