// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

// Rejections retourne, par passerelle, ce que son entrée a refusé depuis son démarrage : poignées de main TLS ratées (accès par l'IP,
// nom sans certificat, pas du TLS…), connexions coupées avant le ClientHello, requêtes HTTP sur un hôte sans route (ADR 0020, étape
// 1.c). Les classements sont tenus en mémoire par chaque passerelle et repartent de zéro à son redémarrage.
func Rejections(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.Rejections(ctx, gatewayName(ctx, db, edgeParam))
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// getRejections : GET /api/v1/security/rejections[?edge=<passerelle>] — le trafic refusé à l'entrée des passerelles.
func (h *SecurityHandler) getRejections(w http.ResponseWriter, r *http.Request) {
	out, err := Rejections(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"))
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}
