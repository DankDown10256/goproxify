// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/rulesengine"
)

// RulesEngineHandler expose le CRUD des règles du moteur de règles.
type RulesEngineHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Engine *rulesengine.Engine
}

func (h *RulesEngineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rules-engine")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	sub := parts[0]
	id := ""
	if len(parts) == 2 {
		id = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && sub == "rules" && id == "":
		h.listRules(w, r)
	case r.Method == http.MethodPost && sub == "rules" && id == "":
		h.createRule(w, r)
	case r.Method == http.MethodPut && sub == "rules" && id != "":
		h.updateRule(w, r, id)
	case r.Method == http.MethodDelete && sub == "rules" && id != "":
		h.deleteRule(w, r, id)
	case r.Method == http.MethodPost && sub == "rules" && strings.HasSuffix(id, "/run"):
		ruleID := strings.TrimSuffix(id, "/run")
		h.runRule(w, r, ruleID)
	case r.Method == http.MethodGet && sub == "history":
		h.listHistory(w, r)
	case r.Method == http.MethodGet && sub == "condition-types":
		h.conditionTypes(w, r)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

func (h *RulesEngineHandler) listRules(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id, name, description, enabled, condition_json, action_json,
		       cooldown_sec, created_at, updated_at, last_fired_at, fire_count
		FROM rules_engine_rules ORDER BY created_at`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	var rules []rulesengine.Rule
	for rows.Next() {
		var rule rulesengine.Rule
		var condJSON, actionJSON string
		var enabled int
		var lastFired sql.NullString
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Description, &enabled,
			&condJSON, &actionJSON, &rule.CooldownSec,
			&rule.CreatedAt, &rule.UpdatedAt, &lastFired, &rule.FireCount,
		); err != nil {
			continue
		}
		rule.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(condJSON), &rule.Condition)
		_ = json.Unmarshal([]byte(actionJSON), &rule.Action)
		if lastFired.Valid && lastFired.String != "" {
			t, _ := time.Parse("2006-01-02T15:04:05Z", lastFired.String)
			if t.IsZero() {
				t, _ = time.Parse("2006-01-02 15:04:05", lastFired.String)
			}
			if !t.IsZero() {
				rule.LastFiredAt = &t
			}
		}
		rules = append(rules, rule)
	}
	jsonOK(w, rules)
}

type ruleBody struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Enabled     *bool                   `json:"enabled"`
	Condition   rulesengine.Condition   `json:"condition"`
	Action      rulesengine.Action      `json:"action"`
	CooldownSec int                     `json:"cooldown_sec"`
}

func (h *RulesEngineHandler) createRule(w http.ResponseWriter, r *http.Request) {
	var body ruleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	condJSON, _ := json.Marshal(body.Condition)
	actionJSON, _ := json.Marshal(body.Action)
	id := uuid.New().String()
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	_, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO rules_engine_rules
		  (id, name, description, enabled, condition_json, action_json, cooldown_sec)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, body.Name, body.Description, enabled,
		string(condJSON), string(actionJSON), body.CooldownSec,
	)
	if err != nil {
		h.Log.Error("rulesengine: create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"id": id})
}

func (h *RulesEngineHandler) updateRule(w http.ResponseWriter, r *http.Request, id string) {
	var body ruleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	condJSON, _ := json.Marshal(body.Condition)
	actionJSON, _ := json.Marshal(body.Action)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	res, err := h.DB.ExecContext(r.Context(), `
		UPDATE rules_engine_rules SET
		  name=?, description=?, enabled=?, condition_json=?, action_json=?,
		  cooldown_sec=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		body.Name, body.Description, enabled,
		string(condJSON), string(actionJSON), body.CooldownSec, id,
	)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RulesEngineHandler) deleteRule(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM rules_engine_rules WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RulesEngineHandler) runRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	if h.Engine == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	dryRun := r.URL.Query().Get("dry_run") != "false"
	matched, detail, err := h.Engine.EvalNow(r.Context(), ruleID, dryRun)
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]any{
		"matched":  matched,
		"dry_run":  dryRun,
		"detail":   detail,
	})
}

func (h *RulesEngineHandler) listHistory(w http.ResponseWriter, r *http.Request) {
	limit := 100
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT h.id, h.rule_id, r.name, h.cond_result, h.action_taken, h.detail, h.error, h.fired_at
		FROM rules_engine_history h
		LEFT JOIN rules_engine_rules r ON r.id=h.rule_id
		ORDER BY h.fired_at DESC LIMIT ?`, limit)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	var logs []rulesengine.ExecLog
	for rows.Next() {
		var l rulesengine.ExecLog
		var cond, action int
		if err := rows.Scan(
			&l.ID, &l.RuleID, &l.RuleName, &cond, &action,
			&l.Detail, &l.Error, &l.FiredAt,
		); err != nil {
			continue
		}
		l.CondResult = cond == 1
		l.ActionTaken = action == 1
		logs = append(logs, l)
	}
	jsonOK(w, logs)
}

func (h *RulesEngineHandler) conditionTypes(w http.ResponseWriter, r *http.Request) {
	types := []map[string]any{
		{
			"type":  "cve_critical",
			"label": "CVE critique sur proxy actif",
			"params": []string{"cvss_threshold", "proxy_id"},
		},
		{
			"type":  "ban_spike",
			"label": "Pic de bans",
			"params": []string{"ban_count", "ban_window", "ban_source"},
		},
		{
			"type":  "engine_silent",
			"label": "Moteur IPS silencieux",
			"params": []string{"engine_type", "silent_minutes"},
		},
		{
			"type":  "proxy_error_rate",
			"label": "Taux d'erreurs proxy",
			"params": []string{"error_rate_threshold", "error_rate_window", "proxy_id"},
		},
		{
			"type":  "ban_repeat",
			"label": "IP récidiviste",
			"params": []string{"repeat_count", "repeat_window"},
		},
	}
	jsonOK(w, types)
}
