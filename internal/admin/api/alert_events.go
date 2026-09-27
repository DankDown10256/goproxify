// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

// AlertEventsHandler expose l'historique des alertes déclenchées (30 jours, purge par le moteur).
type AlertEventsHandler struct {
	DB *sql.DB
}

// ServeHTTP :
//
//	GET  /api/v1/alert-events?[limit=100&trigger=slo_burn&node=paris-01&days=7]
//	POST /api/v1/alert-events/{id}/ack — accuse réception, stoppe les paliers d'escalade restants
func (h *AlertEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alert-events")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		days, _ := strconv.Atoi(q.Get("days"))
		out, err := alerting.RecentEvents(r.Context(), h.DB, days, limit, q.Get("trigger"), q.Get("node"))
		if err != nil {
			alertJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		jsonOK(w, out)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/ack"):
		h.ack(w, r, strings.TrimSuffix(path, "/ack"))
	default:
		http.NotFound(w, r)
	}
}

// ack marque un événement comme acquitté : les paliers d'escalade déjà
// programmés le revérifient à leur échéance et ne renotifient plus.
func (h *AlertEventsHandler) ack(w http.ResponseWriter, r *http.Request, id string) {
	actor := adminauth.ActorFromContext(r.Context())
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE alert_events SET acked=1, acked_at=CURRENT_TIMESTAMP, acked_by=? WHERE id=?`, actor, id)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
