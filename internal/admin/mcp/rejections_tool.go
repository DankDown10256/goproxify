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
		"name": "get_entry_rejections",
		"description": "Ce que l'entrée de chaque passerelle a refusé depuis son démarrage (ADR 0020, étape 1.c) : poignées de main TLS ratées (accès par l'IP, " +
			"nom sans certificat, pas du TLS), connexions coupées avant le ClientHello, requêtes HTTP sur un hôte sans route. Par passerelle : totaux par raison " +
			"(unknown_sni, no_sni, ip_literal, not_tls, bad_clienthello, timeout, too_many_pending, handshake_failed, unknown_host), premiers noms demandés avec le " +
			"nombre d'IP distinctes qui les demandent (un nom demandé par beaucoup d'IP est plutôt un proxy oublié qu'un scanner), premières IP, premières " +
			"empreintes JA4 et probes (IP à cadence régulière : sondes probables à exempter). Classements approchés, tenus en mémoire : ils repartent de zéro au redémarrage de la passerelle. Ne modifie rien et ne bannit rien.",
		"inputSchema": schema(
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	})
}

func (h *Handler) toolGetEntryRejections(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	return api.Rejections(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID)
}
