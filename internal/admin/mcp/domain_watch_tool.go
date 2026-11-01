// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/domainwatch"
)

func init() {
	tools = append(tools, map[string]any{
		"name": "get_domain_watch",
		"description": "La surveillance des domaines déclarés dans l'Admin (ADR 0020, étape 4.d), indépendante du trafic : configuration (désactivée par défaut, chaque vérification " +
			"s'active séparément car elle envoie des noms de domaine à un service extérieur), état de la dernière analyse et constats. Vérifications : ct (un certificat est émis " +
			"pour un domaine déclaré hors de GoProxify, d'après un journal de transparence ; les certificats déjà présents à la première analyse sont listés en baseline sans " +
			"alerte), caa (enregistrements CAA absents, trop larges, ou qui n'autoriseraient pas l'autorité de GoProxify : les renouvellements échoueraient), dangling (un nom dont " +
			"le CNAME pointe vers une cible qui n'existe plus : risque de détournement). Chaque constat porte son statut (open, resolved, baseline, ours, trusted, accepted), " +
			"sa gravité et sa preuve. Ne modifie rien et n'envoie aucun nom : l'analyse tourne sur la cadence configurée, ou à la demande par l'API ou la CLI.",
		"inputSchema": schema(),
	})
}

func (h *Handler) toolGetDomainWatch(r *http.Request, args map[string]any) (any, error) {
	return api.DomainWatchView(&domainwatch.Watcher{DB: h.DB})
}
