// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"strconv"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

func ipTraceTools() []map[string]any {
	return []map[string]any{{
		"name": "trace_ip",
		"description": "Parcours complet d'une IP ou d'un CIDR sur une longue période : requêtes d'accès regroupées en épisodes " +
			"(domaines, chemins, statuts, catégories WAF, signaux Ephor), détections CrowdSec/Ephor, bans et débans, bans en cours " +
			"et profils IP qui contiennent la cible. Retourne une synthèse (totaux, première/dernière vue, activité par jour) et les " +
			"étapes, le plus récent d'abord par défaut ; chaque ban dit pourquoi (signaux) et quel User-Agent l'a provoqué. Les requêtes remontent aussi loin que la rétention des logs d'accès ; les IP " +
			"pseudonymisées ou tronquées (RGPD) ne sont pas retrouvées. Si la base ASN est installée, la réponse contient asn_context " +
			"(ASN de l'adresse) ; avec scope=asn le parcours couvre tout l'ASN, " +
			"sans avoir à connaître le CIDR.",
		"inputSchema": schema(
			req("target", "string", "IP ou CIDR (203.0.113.7, 198.51.100.0/24, 2001:db8::/32) ; facultatif avec scope=asn et asn"),
			opt("scope", "string", "ip (défaut : la cible seule) ou asn (tout l'ASN de l'adresse)"),
			opt("asn", "string", "Numéro d'ASN (AS16276) à tracer en entier, à la place d'une adresse ; avec scope=asn"),
			opt("from", "string", "Début (RFC3339 ou AAAA-MM-JJ). Défaut : 30 jours avant `to`"),
			opt("to", "string", "Fin (RFC3339 ou AAAA-MM-JJ). Défaut : maintenant"),
			opt("order", "string", "desc (plus récent d'abord, défaut) ou asc (chronologique)"),
			opt("limit", "number", "Étapes par page (défaut 500, max 2000)"),
			opt("offset", "number", "Décalage de pagination des étapes"),
		),
	}}
}

func init() { tools = append(tools, ipTraceTools()...) }

func (h *Handler) toolTraceIP(r *http.Request, args map[string]any) (any, error) {
	get := func(k string) string {
		switch v := args[k].(type) {
		case string:
			return v
		case float64:
			return strconv.Itoa(int(v))
		}
		return ""
	}
	qy, err := api.ParseTraceQuery(get)
	if err != nil {
		return nil, err
	}
	if err := api.ResolveTraceScope(r.Context(), h.DB, h.ASN, &qy); err != nil {
		return nil, err
	}
	return api.TraceIP(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, qy)
}
