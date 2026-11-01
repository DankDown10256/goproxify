// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

// TrafficReference retourne, par passerelle, la référence saisonnière du trafic de chaque route (débit réel contre bande attendue du
// créneau) et ses alertes (ADR 0020, étape 3). Les passerelles décident seules : l'Admin affiche.
func TrafficReference(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.Seasonal(ctx, gatewayName(ctx, db, edgeParam))
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// getTrafficReference : GET /api/v1/security/traffic-reference[?edge=<passerelle>].
func (h *SecurityHandler) getTrafficReference(w http.ResponseWriter, r *http.Request) {
	out, err := TrafficReference(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"))
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}
