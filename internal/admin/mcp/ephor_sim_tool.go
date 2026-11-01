// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

func ephorSimTools() []map[string]any {
	return []map[string]any{{
		"name": "simulate_ephor_config",
		"description": "Dry-run Ephor : rejoue les access logs récents contre une config candidate (surchargée sur la config actuelle) " +
			"et la compare à la config actuelle. Ne modifie rien. Retourne requêtes bloquées, bans, IP les plus touchées et " +
			"legit_blocked (requêtes bloquées qui avaient abouti, indicateur de faux positifs). " +
			"Avec seasonal.mode detect ou block dans la config, le rapport porte aussi la part « seasonal » : par route, si elle est jugeable (warm), les alertes qu'elle aurait ouvertes (warnings, probables, durée) et, en block, les requêtes qu'un profil durci aurait touchées (hardened_requests, dont hardened_served ont abouti). Une route froide n'a pas assez d'historique dans la fenêtre pour être jugée. " +
			"Non simulé : listes par défaut, global_rps, agrégat par ASN (asn_aggregate) ; la note commune de comportement l'est (c'est elle qui dit si un signal peut passer en block) ; les IP pseudonymisées ou tronquées (anonymisation RGPD) sont ignorées.",
		"inputSchema": schema(
			req("config", "object", "Champs Ephor à surcharger (ex: {\"rate_limit\":20,\"custom_lists\":{\"paths\":[\"/wp-admin\"]}}), mêmes noms que threat-config"),
			opt("hours", "number", "Fenêtre de logs rejouée en heures (défaut 1, max 24 ; max 168 quand la config rejoue la référence saisonnière : un créneau a besoin de jours de trafic pour être jugé)"),
			opt("domain", "string", "Limiter le rejeu à un domaine"),
			opt("edge", "string", "ID de la passerelle dont la config actuelle sert de base (défaut: config globale)"),
		),
	}, {
		"name": "get_ephor_references",
		"description": "Ce que chaque passerelle a appris pour la note commune d'Ephor (ADR 0011) : références de débit par IP, route par route " +
			"et heure par heure (médiane, seuil, minutes observées, fiable ou encore en apprentissage), base ASN et table d'empreintes TLS " +
			"dont elle dispose, nombre de profils en cours.",
		"inputSchema": schema(
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "suggest_ephor_thresholds",
		"description": "Propose des seuils Ephor à partir des cumuls par minute (sans IP) : par passerelle, le débit normal observé (médiane, p99, " +
			"p99,9, max, part d'erreurs) et une limite globale proposée (quatre fois le p99,9 par minute, arrondie). Ne modifie rien : " +
			"l'administrateur accepte en enregistrant la configuration. Les seuils par IP s'apprennent sur la passerelle (get_ephor_references).",
		"inputSchema": schema(
			opt("days", "number", "Fenêtre lue en jours (défaut 7, max 90)"),
			opt("edge", "string", "Passerelle dont la configuration (ou celle de son groupe HA) sert de base à la comparaison"),
		),
	}}
}

func init() { tools = append(tools, ephorSimTools()...) }

func (h *Handler) toolSimulateEphor(r *http.Request, args map[string]any) (any, error) {
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
	return api.SimulateEphor(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, h.threatConfigKey(edgeID), override, hours, domain)
}

func (h *Handler) toolGetEphorReferences(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	return api.EphorReferences(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID)
}

func (h *Handler) toolSuggestEphorThresholds(r *http.Request, args map[string]any) (any, error) {
	days := 0
	if v, ok := args["days"].(float64); ok && v > 0 {
		days = int(v)
	}
	edgeID, _ := args["edge"].(string)
	sug, err := api.SuggestEphorThresholds(r.Context(), h.DB, h.threatConfigKey(edgeID), days)
	if err != nil {
		return nil, err
	}
	return map[string]any{"suggestions": sug}, nil
}

// threatConfigKey retourne la clé de la config Ephor qui s'applique à la passerelle : celle de son groupe HA, sinon la sienne.
func (h *Handler) threatConfigKey(edgeID string) string {
	if h.ArchStore == nil {
		return api.ThreatConfigKey(edgeID)
	}
	return api.ThreatConfigKeyFor(h.ArchStore, edgeID)
}
