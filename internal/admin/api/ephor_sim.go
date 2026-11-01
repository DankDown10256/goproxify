// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vincamok/goproxify/internal/edge/engines"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// errNoGatewayToReplay : la simulation rejoue le trafic des passerelles ; sans passerelle il n'y a rien à rejouer.
var errNoGatewayToReplay = errors.New("aucune passerelle enregistrée : rien à rejouer")

const (
	SimDefaultHours = 1
	SimMaxHours     = 24
	// SimMaxHoursSeasonal : la référence saisonnière a besoin de jours de trafic pour juger un créneau.
	SimMaxHoursSeasonal = 168
	simMaxEvents    = 200_000
)

// SimulateEphor rejoue les access logs récents contre la config Ephor de cfgKey surchargée par override,
// et la compare à la config actuelle. Ne modifie rien.
func SimulateEphor(ctx context.Context, db *sql.DB, edge *prismedge.Source, cfgKey string, override map[string]any, hours int, domain string) (map[string]any, error) {
	if hours <= 0 {
		hours = SimDefaultHours
	}
	var current threat.Config
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, cfgKey).Scan(&raw); err == nil {
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return nil, fmt.Errorf("config Ephor actuelle illisible: %w", err)
		}
	}
	candidate := current
	b, _ := json.Marshal(override)
	if err := engines.Validate(engines.Ephor, b); err != nil {
		return nil, fmt.Errorf("config candidate invalide: %w", err)
	}
	if err := json.Unmarshal(b, &candidate); err != nil {
		return nil, fmt.Errorf("config candidate invalide: %w", err)
	}

	maxHours := SimMaxHours
	if current.Seasonal.Active() || candidate.Seasonal.Active() {
		maxHours = SimMaxHoursSeasonal
	}
	if hours > maxHours {
		hours = maxHours
	}

	// La passerelle a le moteur et les lignes : elle rejoue son propre trafic (agents utilisateur compris) et l'Admin
	// compare les rapports.
	if edge != nil && edge.Available(ctx, analytics.Params{}) {
		sim, err := edge.SimulateEphor(ctx, current, candidate, hours, domain)
		if err == nil {
			out := map[string]any{
				"window_hours": hours, "domain": domain, "events_replayed": sim.Events, "truncated": sim.Truncated,
				"skipped_unattributable_ip": sim.Skipped, "current": sim.Current, "candidate": sim.Candidate,
				"delta": map[string]int{
					"blocked":       sim.Candidate.Blocked - sim.Current.Blocked,
					"legit_blocked": sim.Candidate.LegitBlocked - sim.Current.LegitBlocked,
					"blocked_ips":   sim.Candidate.BlockedIPs - sim.Current.BlockedIPs,
					"bans":          len(sim.Candidate.Bans) - len(sim.Current.Bans),
				},
				"gateways":      sim.Gateways,
				"not_simulated": []string{"default_lists", "global_rps", "waf", "asn_aggregate"},
				"note":          "Chaque passerelle rejoue son propre trafic : les compteurs s'additionnent (une IP vue par deux passerelles compte deux fois) et top_ips fusionne les dix premières de chacune. legit_blocked = requêtes bloquées par la config qui avaient reçu un statut < 400 à l'époque : indicateur de faux positifs, pas une certitude.",
			}
			if sim.Meta.Degraded() {
				out["partial"], out["unreachable"] = sim.Meta.Partial, sim.Meta.Unreachable
			}
			return out, nil
		}
		return nil, err
	}

	return nil, errNoGatewayToReplay
}

func (h *SecurityHandler) simulateThreat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config map[string]any `json:"config"`
		Hours  int            `json:"hours"`
		Domain string         `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Config == nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	scope, _ := h.scope(r)
	out, err := SimulateEphor(r.Context(), h.DB, h.Edge, threatConfigKey(scope), body.Config, body.Hours, body.Domain)
	if err != nil {
		secJSONErr(w, err, http.StatusBadRequest)
		return
	}
	jsonOK(w, out)
}
