// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

// AlertEventsHandler expose l'historique des alertes déclenchées (30 jours, purge par le moteur).
type AlertEventsHandler struct {
	DB *sql.DB
}

// ServeHTTP : GET /api/v1/alert-events?[limit=100&trigger=slo_burn&node=paris-01&days=7]
func (h *AlertEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	days, _ := strconv.Atoi(q.Get("days"))
	out, err := alerting.RecentEvents(r.Context(), h.DB, days, limit, q.Get("trigger"), q.Get("node"))
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, out)
}
