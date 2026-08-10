// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package api contient les handlers HTTP de l'API REST Administration.
package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/tz"
)

// HealthHandler gère GET /api/v1/health.
type HealthHandler struct {
	DB      *sql.DB
	Version string
	Webapp  string
	Commit  string
	Built   string
	Log     *slog.Logger
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	if err := h.DB.PingContext(r.Context()); err != nil {
		dbStatus = "error"
		if !isCtxErr(err) {
			h.Log.Error("health: ping DB échoué", "err", err)
		}
	}
	now := time.Now()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"version":   h.Version,
		"webapp":    h.Webapp,
		"commit":    h.Commit,
		"built":     h.Built,
		"db":        dbStatus,
		"timezone":  tz.Name(),
		"time":      now.Format(time.RFC3339),
		"time_utc":  now.UTC().Format(time.RFC3339),
	})
}

// RoutesHandler gère GET /internal/v1/routes — retourne les routes activées pour les Cores.
type RoutesHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *RoutesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT config FROM proxies WHERE enabled = 1`)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("routes: lecture DB", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	routes := make([]router.Route, 0)
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		var route router.Route
		if err := json.Unmarshal([]byte(cfg), &route); err != nil {
			h.Log.Warn("routes: désérialisation", "err", err)
			continue
		}
		routes = append(routes, route)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(routes)
}
