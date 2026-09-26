// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
)

func init() {
	tools = append(tools,
		map[string]any{
			"name":        "get_prism_anomalies",
			"description": "Anomalies détectées par Prism sur la période : pic d'erreurs, IP dominante, pays en erreur, backend en difficulté, part de bots élevée.",
			"inputSchema": schema(
				opt("hours", "number", "Fenêtre analysée en heures (défaut 24, max 720)"),
				opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; omis = toutes"),
				opt("proxy", "string", "Domaine du proxy ; omis = tous"),
			),
		},
		map[string]any{
			"name":        "get_prism_geo",
			"description": "Trafic par pays (requêtes, erreurs, taux d'erreur, IPs bannies) ou par ville (position approximative issue de la géolocalisation IP).",
			"inputSchema": schema(
				opt("level", "string", "country (défaut) ou city"),
				opt("hours", "number", "Fenêtre analysée en heures (défaut 24, max 720)"),
				opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; omis = toutes"),
				opt("proxy", "string", "Domaine du proxy ; omis = tous"),
				opt("limit", "number", "Nombre de villes retournées (défaut 300, max 1000) ; ignoré au niveau pays"),
			),
		},
	)
}

// prismToolParams traduit les arguments d'un outil Prism en fenêtre d'analyse.
func (h *Handler) prismToolParams(r *http.Request, args map[string]any) analytics.Params {
	hours := 24.0
	if v, ok := args["hours"].(float64); ok && v > 0 {
		hours = v
	}
	if hours > 720 {
		hours = 720
	}
	to := time.Now()
	p := analytics.Params{From: to.Add(-time.Duration(hours * float64(time.Hour))), To: to}
	p.Proxy, _ = args["proxy"].(string)
	if edge, _ := args["edge"].(string); edge != "" {
		var node string
		if h.DB.QueryRowContext(r.Context(), `SELECT node_name FROM tokens WHERE id=? OR node_name=? LIMIT 1`, edge, edge).Scan(&node) == nil && node != "" {
			edge = node
		}
		p.NodeName = edge
	}
	return p
}

func (h *Handler) toolGetPrismAnomalies(r *http.Request, args map[string]any) (any, error) {
	return analytics.DetectAnomalies(r.Context(), h.DB, h.prismToolParams(r, args)), nil
}

func (h *Handler) toolGetPrismGeo(r *http.Request, args map[string]any) (any, error) {
	p := h.prismToolParams(r, args)
	if level, _ := args["level"].(string); level == "city" {
		limit := 0
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		return analytics.GetGeoPoints(h.DB, p, limit), nil
	}
	entries := analytics.GetGeoBreakdown(h.DB, p)
	if entries == nil {
		entries = []analytics.GeoEntry{}
	}
	return entries, nil
}
