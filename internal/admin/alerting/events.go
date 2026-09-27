// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
)

// RecentEvents retourne les alertes déclenchées (30 jours conservés), la plus récente d'abord.
// days (1-30, 30 par défaut), limit (1-500, 100 par défaut), trigger et node (nom de passerelle
// lu dans le détail de l'événement) sont optionnels.
func RecentEvents(ctx context.Context, db *sql.DB, days, limit int, trigger, node string) ([]map[string]any, error) {
	if days <= 0 || days > 30 {
		days = 30
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	conds := []string{"e.fired_at >= datetime('now', ?)"}
	args := []any{"-" + strconv.Itoa(days) + " days"}
	if trigger != "" {
		conds = append(conds, "e.trigger = ?")
		args = append(args, trigger)
	}
	if node != "" {
		conds = append(conds, "(json_extract(e.detail,'$.node_name') = ? OR json_extract(e.detail,'$.node') = ?)")
		args = append(args, node, node)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT e.id, e.rule_id, COALESCE(r.name,''), e.trigger, e.detail, e.channels,
		        COALESCE(e.message_title,''), COALESCE(e.message_body,''), COALESCE(e.priority,0), e.fired_at
		 FROM alert_events e LEFT JOIN alert_rules r ON r.id = e.rule_id
		 WHERE `+strings.Join(conds, " AND ")+` ORDER BY e.fired_at DESC, e.id DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, priority int
		var ruleID, ruleName, trig, detailJSON, chansJSON, title, body, firedAt string
		if rows.Scan(&id, &ruleID, &ruleName, &trig, &detailJSON, &chansJSON, &title, &body, &priority, &firedAt) != nil {
			continue
		}
		var detail, chans any
		_ = json.Unmarshal([]byte(detailJSON), &detail)
		_ = json.Unmarshal([]byte(chansJSON), &chans)
		out = append(out, map[string]any{
			"id": id, "rule_id": ruleID, "rule_name": ruleName, "trigger": trig, "detail": detail,
			"channels": chans, "title": title, "body": body, "priority": priority, "fired_at": firedAt,
		})
	}
	return out, nil
}
