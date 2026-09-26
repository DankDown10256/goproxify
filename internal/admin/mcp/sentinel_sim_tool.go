// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

const (
	simDefaultHours = 1
	simMaxHours     = 24
	simMaxEvents    = 200_000
)

func sentinelSimTools() []map[string]any {
	return []map[string]any{{
		"name": "simulate_sentinel_config",
		"description": "Dry-run Sentinel : rejoue les access logs récents contre une config candidate (surchargée sur la config actuelle) " +
			"et la compare à la config actuelle. Ne modifie rien. Retourne requêtes bloquées, bans, IP les plus touchées et " +
			"legit_blocked (requêtes bloquées qui avaient abouti, indicateur de faux positifs). " +
			"Non simulé : listes par défaut, global_rps, règles User-Agent (l'UA n'est pas conservé dans les logs) ; les IP pseudonymisées sont ignorées.",
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
	hours := simDefaultHours
	if v, ok := args["hours"].(float64); ok && v > 0 {
		hours = int(v)
		if hours > simMaxHours {
			hours = simMaxHours
		}
	}
	domain, _ := args["domain"].(string)
	edgeID, _ := args["edge"].(string)

	var current threat.Config
	var raw string
	if err := h.DB.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key=?`, api.ThreatConfigKey(edgeID)).Scan(&raw); err == nil {
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return nil, fmt.Errorf("config Sentinel actuelle illisible: %w", err)
		}
	}
	candidate := current
	b, _ := json.Marshal(override)
	if err := json.Unmarshal(b, &candidate); err != nil {
		return nil, fmt.Errorf("config candidate invalide: %w", err)
	}

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	q := `SELECT ts, ip, path, status FROM logs
	      WHERE status > 0 AND component <> 'admin' AND ts >= ?`
	qargs := []any{since.Format(time.RFC3339Nano)}
	if domain != "" {
		q += ` AND domain = ?`
		qargs = append(qargs, domain)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	qargs = append(qargs, simMaxEvents+1)
	rows, err := h.DB.QueryContext(r.Context(), q, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []threat.SimEvent
	skipped := 0
	for rows.Next() {
		var ts time.Time
		var ip, path string
		var status int
		if err := rows.Scan(&ts, &ip, &path, &status); err != nil {
			continue
		}
		if !parseableIP(ip) {
			skipped++
			continue
		}
		events = append(events, threat.SimEvent{Time: ts, IP: ip, Path: path, Status: status})
	}
	truncated := len(events)+skipped > simMaxEvents
	if truncated && len(events) > simMaxEvents {
		events = events[:simMaxEvents]
	}

	base := threat.Simulate(current, events)
	cand := threat.Simulate(candidate, events)
	return map[string]any{
		"window_hours":              hours,
		"domain":                    domain,
		"events_replayed":           len(events),
		"truncated":                 truncated,
		"skipped_unattributable_ip": skipped,
		"current":                   base,
		"candidate":                 cand,
		"delta": map[string]int{
			"blocked":       cand.Blocked - base.Blocked,
			"legit_blocked": cand.LegitBlocked - base.LegitBlocked,
			"blocked_ips":   cand.BlockedIPs - base.BlockedIPs,
			"bans":          len(cand.Bans) - len(base.Bans),
		},
		"not_simulated": []string{"default_lists", "global_rps", "user_agent_rules", "waf"},
		"note":          "legit_blocked = requêtes bloquées par la config qui avaient reçu un statut < 400 à l'époque : indicateur de faux positifs, pas une certitude.",
	}, nil
}

// parseableIP écarte les IP pseudonymisées ou vides, inutilisables pour les compteurs par IP.
func parseableIP(ip string) bool {
	_, err := netip.ParseAddr(ip)
	return err == nil
}
