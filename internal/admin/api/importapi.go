// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"database/sql"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/importer"
	"github.com/vincamok/goproxify/internal/core/router"
)

// ImportHandler gère l'import de sauvegardes et la migration de configs.
type ImportHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *ImportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/import")
	path = strings.TrimPrefix(path, "/")

	switch {
	// Backup
	case r.Method == http.MethodPost && path == "backup/preview":
		h.backupPreview(w, r)
	case r.Method == http.MethodPost && path == "backup/apply":
		h.backupApply(w, r)
	// Config migration
	case r.Method == http.MethodPost && path == "config/parse":
		h.configParse(w, r)
	case r.Method == http.MethodPost && path == "config/apply":
		h.configApply(w, r)
	// Export
	case r.Method == http.MethodGet && path == "export":
		h.exportBackup(w, r)
	default:
		http.NotFound(w, r)
	}
}

// backupPreview parse le JSON de sauvegarde et retourne le résumé (sans écrire en DB).
func (h *ImportHandler) backupPreview(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 32<<20)) // 32 MB max
	if err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	_, sum, err := importer.SummarizeBackup(data)
	if err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	jsonOK(w, sum)
}

// backupApply applique les entités sélectionnées depuis la sauvegarde.
func (h *ImportHandler) backupApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Data      json.RawMessage         `json:"data"`
		Selection importer.ImportSelection `json:"selection"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	b, _, err := importer.SummarizeBackup(body.Data)
	if err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	result := importer.Apply(h.DB, b, body.Selection)
	jsonOK(w, result)
}

// configParse détecte le format et extrait les proxies.
func (h *ImportHandler) configParse(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format  string `json:"format"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	proxies, err := importer.ParseConfig(body.Format, body.Content)
	if err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	if proxies == nil {
		proxies = []importer.DetectedProxy{}
	}
	jsonOK(w, map[string]any{"proxies": proxies, "count": len(proxies)})
}

// configApply insère les proxies sélectionnés en DB.
func (h *ImportHandler) configApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Proxies    []importer.DetectedProxy `json:"proxies"`
		OnConflict string                   `json:"on_conflict"` // skip | overwrite
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		importJSONErr(w, err, http.StatusBadRequest)
		return
	}
	imported, skipped, errs := 0, 0, 0
	for _, p := range body.Proxies {
		if p.Host == "" {
			continue
		}
		var backends []router.Backend
		for _, b := range p.Backends {
			backends = append(backends, router.Backend{URL: b})
		}
		routeType := router.RouteHTTP
		if p.TLS {
			routeType = "https"
		}
		var hdrs *router.HeadersConfig
		if p.HSTS || p.XFrameOptions != "" || len(p.CustomHeaders) > 0 {
			hdrs = &router.HeadersConfig{
				HSTS:          p.HSTS,
				HSTSMaxAge:    p.HSTSMaxAge,
				XFrameOptions: p.XFrameOptions,
				Custom:        p.CustomHeaders,
			}
		}
		var locations []router.Location
		for _, l := range p.Locations {
			var lBackends []router.Backend
			for _, b := range l.Backends {
				lBackends = append(lBackends, router.Backend{URL: b})
			}
			var lHdrs *router.HeadersConfig
			if l.HSTS || l.XFrameOptions != "" || len(l.CustomHeaders) > 0 {
				lHdrs = &router.HeadersConfig{
					HSTS: l.HSTS, HSTSMaxAge: l.HSTSMaxAge,
					XFrameOptions: l.XFrameOptions, Custom: l.CustomHeaders,
				}
			}
			pt := l.PathType
			if pt == "" {
				pt = "prefix"
			}
			locations = append(locations, router.Location{
				Path:            l.Path,
				PathType:        pt,
				Backends:        lBackends,
				Headers:         lHdrs,
				ConnectTimeout:  time.Duration(l.ConnectTimeout) * time.Second,
				ResponseTimeout: time.Duration(l.ResponseTimeout) * time.Second,
				SendTimeout:     time.Duration(l.SendTimeout) * time.Second,
				MaxBodySize:     l.MaxBodySize,
			})
		}
		cfg := router.Route{
			ID:              uuid.New().String(),
			Host:            p.Host,
			Type:            routeType,
			Backends:        backends,
			TLSEnabled:      p.TLS,
			Headers:         hdrs,
			Locations:       locations,
			ConnectTimeout:  time.Duration(p.ConnectTimeout) * time.Second,
			ResponseTimeout: time.Duration(p.ResponseTimeout) * time.Second,
			SendTimeout:     time.Duration(p.SendTimeout) * time.Second,
			BufferSize:      p.BufferSize,
			MaxBodySize:     p.MaxBodySize,
			UpdatedAt:       time.Now(),
		}
		// Injecter tls_mode et cert_name dans le JSON brut (champs UI non portés par router.Route).
		// Un proxy importé en HTTPS utilise le mode "manual" avec détection automatique par SNI.
		var cfgMap map[string]any
		raw, _ := json.Marshal(cfg)
		_ = json.Unmarshal(raw, &cfgMap)
		if p.TLS {
			cfgMap["tls_mode"] = "manual"
			cfgMap["cert_name"] = ""
		}
		cfgJSON, _ := json.Marshal(cfgMap)
		name := p.Host
		if name == "" {
			name = "imported-proxy"
		}
		verb := "INSERT OR IGNORE"
		if body.OnConflict == "overwrite" {
			verb = "INSERT OR REPLACE"
		}
		_, err := h.DB.Exec(
			verb+` INTO proxies (id, name, config, enabled) VALUES (?,?,?,1)`,
			cfg.ID, name, string(cfgJSON),
		)
		if err == nil {
			imported++
		} else if strings.Contains(err.Error(), "UNIQUE") {
			skipped++
		} else {
			errs++
		}
	}
	jsonOK(w, map[string]any{"imported": imported, "skipped": skipped, "errors": errs})
}

// exportBackup exporte la DB complète en JSON.
func (h *ImportHandler) exportBackup(w http.ResponseWriter, r *http.Request) {
	b, err := importer.ExportBackup(h.DB)
	if err != nil {
		importJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		importJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	ts := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=goproxify-backup-"+ts+".gpx-admin-backup")
	w.Write(data) //nolint:errcheck
}

func importJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
