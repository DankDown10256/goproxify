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

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/router"
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

// RoutesHandler gère GET /internal/v1/routes — retourne les routes activées pour les passerelles.
type RoutesHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *RoutesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	routesPtr, err := edgeproxy.LoadEnabledRoutes(r.Context(), h.DB)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("routes: lecture", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	routes := make([]router.Route, 0, len(routesPtr))
	for _, rt := range routesPtr {
		if rt != nil {
			routes = append(routes, *rt)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(routes)
}
