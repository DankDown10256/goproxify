// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/vincamok/goproxify/internal/edge/engines"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/vincamok/goproxify/internal/edge/threat"
)

// SimulateSentinel rejoue les access logs récents contre la config Sentinel de cfgKey surchargée par override,
// et la compare à la config actuelle. Ne modifie rien.
func SimulateSentinel(ctx context.Context, db *sql.DB, cfgKey string, override map[string]any, hours int, domain string) (map[string]any, error) {
	if hours <= 0 {
		hours = SimDefaultHours
	}
	if hours > SimMaxHours {
		hours = SimMaxHours
	}
	var current threat.Config
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, cfgKey).Scan(&raw); err == nil {
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return nil, fmt.Errorf("config Sentinel actuelle illisible: %w", err)
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

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	q := `SELECT ts, ip, path, status, ip_truncated FROM logs
	      WHERE status > 0 AND component <> 'admin' AND ts >= ?`
	qargs := []any{since.Format(time.RFC3339Nano)}
	if domain != "" {
		q += ` AND domain = ?`
		qargs = append(qargs, domain)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	qargs = append(qargs, simMaxEvents+1)
	rows, err := db.QueryContext(ctx, q, qargs...)
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
		var ipTruncated bool
		if err := rows.Scan(&ts, &ip, &path, &status, &ipTruncated); err != nil {
			continue
		}
		if _, err := netip.ParseAddr(ip); err != nil || ipTruncated {
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

