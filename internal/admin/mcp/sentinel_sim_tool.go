// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func sentinelSimTools() []map[string]any {
	return []map[string]any{{
		"name": "simulate_sentinel_config",
		"description": "Dry-run Sentinel : rejoue les access logs récents contre une config candidate (surchargée sur la config actuelle) " +
			"et la compare à la config actuelle. Ne modifie rien. Retourne requêtes bloquées, bans, IP les plus touchées et " +
			"legit_blocked (requêtes bloquées qui avaient abouti, indicateur de faux positifs). " +
			"Non simulé : listes par défaut, global_rps, règles User-Agent (l'UA n'est pas conservé dans les logs) ; les IP pseudonymisées ou tronquées (anonymisation RGPD) sont ignorées.",
		"inputSchema": schema(
			req("config", "object", "Champs Sentinel à surcharger (ex: {\"rate_limit\":20,\"custom_lists\":{\"paths\":[\"/wp-admin\"]}}), mêmes noms que threat-config"),
			opt("hours", "number", "Fenêtre de logs rejouée en heures (défaut 1, max 24)"),
			opt("domain", "string", "Limiter le rejeu à un domaine"),
			opt("edge", "string", "ID de la passerelle dont la config actuelle sert de base (défaut: config globale)"),
		),
	}}
}

func init() { tools = append(tools, sentinelSimTools()...) }

func (h *Handler) toolSimulateSentinel(r *http.Request, args map[string]any) (any, error) {
	override, ok := args["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config requis (objet)")
	}
	hours := api.SimDefaultHours
	if v, ok := args["hours"].(float64); ok && v > 0 {
		hours = int(v)
	}
	domain, _ := args["domain"].(string)
	edgeID, _ := args["edge"].(string)
	return api.SimulateSentinel(r.Context(), h.DB, h.threatConfigKey(edgeID), override, hours, domain)
}

