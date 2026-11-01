// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

func init() {
	tools = append(tools, map[string]any{
		"name": "get_tls_reputation",
		"description": "La réputation apprise des empreintes TLS (JA4) de chaque passerelle (ADR 0020, étape 4.c) et les empreintes qu'elle PROPOSE pour " +
			"custom_lists.tls_fingerprints d'Ephor. Par passerelle : empreintes suivies, piles de navigateurs connues (jamais proposées) et, pour chaque proposition, ses preuves : " +
			"IP distinctes qui la partagent, requêtes vues, part de requêtes mauvaises (marquées par le WAF ou en erreur), part marquée par le WAF, part en erreur, " +
			"première et dernière vue. Une empreinte n'est proposée que si beaucoup d'IP la partagent, que la plupart de ses requêtes sont mauvaises et que le WAF " +
			"en a marqué une part. Rien n'est jamais bloqué automatiquement ; l'acceptation est un geste de l'administrateur (POST /api/v1/security/tls-reputation/accept " +
			"ou `goproxify security tls-reputation accept`). Ne modifie rien.",
		"inputSchema": schema(
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	})
}

func (h *Handler) toolGetTLSReputation(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	return api.TLSReputation(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID)
}
