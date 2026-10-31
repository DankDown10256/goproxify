// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/audit"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/backup"
	"github.com/vincamok/goproxify/internal/admin/routesecrets"
	"github.com/vincamok/goproxify/internal/admin/importer"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// BackupHandler gère les sauvegardes planifiées et l'historique des proxies.
type BackupHandler struct {
	DB        *sql.DB
	Log       *slog.Logger
	Scheduler *backup.Scheduler
	Pusher    RoutePusher
	Keys      *backup.KeyStore // clé de chiffrement des sauvegardes gérée depuis l'interface
	Auditor   *audit.Logger
	// LauncherImage est l'image du launcher que l'installation utilise (GPX_DEPLOY_REGISTRY, GPX_DEPLOY_TAG) : la page
	// Sauvegardes en tire la commande qui reconstruit un Admin perdu.
	LauncherImage string
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
	case r.Method == http.MethodGet && sub == "snapshots" && id != "" && action == "summary":
		h.snapshotSummary(w, r, id)
	case r.Method == http.MethodPost && sub == "snapshots" && id != "" && action == "restore":
		h.restoreSnapshot(w, r, id)
	case r.Method == http.MethodPost && sub == "snapshots" && id != "" && action == "verify":
		h.verifySnapshot(w, r, id)
	// Clé de chiffrement
	case r.Method == http.MethodGet && sub == "key" && id == "":
		h.keyStatus(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut) && sub == "key" && id == "":
		h.setKey(w, r)
	case r.Method == http.MethodDelete && sub == "key" && id == "":
		h.deleteKey(w, r)
	case r.Method == http.MethodPost && sub == "key" && id == "retired" && action == "":
		h.addRetiredKey(w, r)
	case r.Method == http.MethodDelete && sub == "key" && id == "retired" && action != "":
		h.forgetRetiredKey(w, r, action)
	case r.Method == http.MethodPost && sub == "key" && id == "reveal":
		h.revealKey(w, r)
	// Destinations externes et état
	case r.Method == http.MethodGet && sub == "status":
		h.status(w, r)
	case r.Method == http.MethodGet && sub == "destinations" && id == "":
		h.listDestinations(w, r)
	case r.Method == http.MethodPost && sub == "destinations" && id == "":
		h.saveDestination(w, r, "")
	case r.Method == http.MethodPut && sub == "destinations" && id != "" && action == "":
		h.saveDestination(w, r, id)
	case r.Method == http.MethodDelete && sub == "destinations" && id != "" && action == "":
		h.deleteDestination(w, r, id)
	case r.Method == http.MethodPost && sub == "destinations" && id != "" && action == "test":
		h.testDestination(w, r, id)
	// Proxy history
	case r.Method == http.MethodGet && sub == "proxy-history" && id != "" && action == "":
		h.listProxyHistory(w, r, id)
	case r.Method == http.MethodGet && sub == "proxy-history" && id != "" && action == "config":
		h.getProxyVersionConfig(w, r, id)
	case r.Method == http.MethodPost && sub == "proxy-history" && id != "" && action != "":
		h.restoreProxyVersion(w, r, action)
	default:
		http.NotFound(w, r)
	}
}

// status : l'état des sauvegardes, avec l'image du launcher pour la commande de reconstruction de l'Admin.
func (h *BackupHandler) status(w http.ResponseWriter, _ *http.Request) {
	raw, err := json.Marshal(h.Scheduler.Status())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.LauncherImage != "" {
		out["launcher_image"] = h.LauncherImage
	}
	jsonOK(w, out)
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
		Name    string `json:"name"`
		History bool   `json:"history"`
	}
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "manuel-" + time.Now().Format("20060102-150405")
	}
	// Une sauvegarde complète (secrets, passerelles, historique) peut durer plusieurs dizaines de
	// secondes : la requête ne l'attend pas, sous peine d'expirer chez le reverse proxy (502/504).
	// L'avancement et le résultat sont dans GET /backups/status (running, last_run).
	if h.Scheduler.Running() != nil && h.Scheduler.Running().Name != "" {
		http.Error(w, "une sauvegarde est déjà en cours", http.StatusConflict)
		return
	}
	go func() {
		if err := h.Scheduler.TakeSnapshotWith(name, "", 0, body.History); err != nil {
			h.Log.Error("backup: snapshot manuel échoué", "name", name, "err", err)
		}
	}()
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]string{"status": "started", "name": name})
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

func (h *BackupHandler) snapshotSummary(w http.ResponseWriter, _ *http.Request, id string) {
	data, _, err := h.Scheduler.GetSnapshotData(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_, sum, err := importer.SummarizeBackup(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, sum)
}

func (h *BackupHandler) restoreSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	data, _, err := h.Scheduler.GetSnapshotData(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	bk, err := importer.ParseBackup(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Sans corps : restauration complète. Un corps {"selection":{…}} permet de restreindre.
	sel := importer.ImportSelection{
		ImportUsers:    true,
		ImportTokens:   true,
		ImportPATs:     true,
		ImportSnippets: true,
		ImportChannels: true,
		ImportRules:    true,
		ImportConfig:   true,
		OnConflict:     "overwrite",
	}
	superadmin := rbac.IsSuperAdmin(r.Context(), h.DB, adminauth.UserIDFromContext(r.Context()))
	sel.ImportSecrets = bk.Secrets != "" && superadmin
	sel.ImportHistory = bk.History != "" && superadmin
	var body struct {
		Selection *importer.ImportSelection `json:"selection"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body) == nil && body.Selection != nil {
		sel = *body.Selection
	}
	sel.SecretDirs = h.Scheduler.SecretDirs()
	// Filet de sécurité : état courant sauvegardé avant d'écraser quoi que ce soit.
	if sel.OnConflict == "overwrite" {
		if err := h.Scheduler.TakeSnapshot("avant-restauration-"+time.Now().Format("20060102-150405"), "", 0); err != nil {
			http.Error(w, "snapshot de sécurité impossible, restauration annulée : "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	sel.AllowPrivileged = superadmin
	result := importer.Apply(h.DB, bk, sel)
	if sel.ImportConfig {
		h.Scheduler.Reload()
	}
	if h.Pusher != nil {
		go h.Pusher.PushRoutes(context.Background())
	}
	jsonOK(w, result)
}

// ── Proxy history ─────────────────────────────────────────────────────────────

func (h *BackupHandler) listProxyHistory(w http.ResponseWriter, _ *http.Request, proxyID string) {
	jsonOK(w, h.Scheduler.ListProxyVersions(h.DB, proxyID))
}

func (h *BackupHandler) getProxyVersionConfig(w http.ResponseWriter, _ *http.Request, versionID string) {
	v, err := h.Scheduler.GetProxyVersion(h.DB, versionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(routesecrets.Mask([]byte(v.Config), routesecrets.FromDB(h.DB)))
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

// ── Destinations externes et vérification ─────────────────────────────────────

func (h *BackupHandler) verifySnapshot(w http.ResponseWriter, _ *http.Request, id string) {
	if err := h.Scheduler.VerifySnapshot(id); err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

func (h *BackupHandler) listDestinations(w http.ResponseWriter, _ *http.Request) {
	ds, err := h.Scheduler.ListDestinations()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, ds)
}

func (h *BackupHandler) saveDestination(w http.ResponseWriter, r *http.Request, id string) {
	var d backup.Destination
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&d); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	d.ID = id
	saved, err := h.Scheduler.SaveDestination(d)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if id == "" {
		w.WriteHeader(http.StatusCreated)
	}
	jsonOK(w, saved)
}

func (h *BackupHandler) deleteDestination(w http.ResponseWriter, _ *http.Request, id string) {
	if err := h.Scheduler.DeleteDestination(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BackupHandler) testDestination(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Scheduler.TestDestination(r.Context(), id); err != nil {
		jsonOK(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}
