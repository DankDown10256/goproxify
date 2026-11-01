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
		"name": "get_traffic_reference",
		"description": "La référence saisonnière du trafic de chaque passerelle (ADR 0020, étape 3) : pour chaque route et pour l'entrée (hôtes inconnus, TLS refusé), " +
			"le débit réel de la dernière minute, le débit attendu à cette heure de cette journée (moyenne) et sa borne haute, les IP distinctes, si le créneau est assez " +
			"observé pour être cru (warm) ou encore froid, et le niveau d'alerte (none, warning = écart de volume seul, probable = écart de volume accompagné d'un écart de nature : " +
			"IP jamais vues, erreurs, un seul chemin). Donne aussi les alertes en cours et les derniers changements d'état. Cet outil ne décide rien : chaque passerelle agit seule (en mode block, une route en attaque probable est durcie, champ hardened). " +
			"Ne modifie rien et ne bannit rien.",
		"inputSchema": schema(
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	})
}

func (h *Handler) toolGetTrafficReference(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	return api.TrafficReference(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID)
}
