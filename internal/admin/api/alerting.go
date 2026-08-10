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
	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/alerting/channels"
)

// ChannelsHandler gère le CRUD des canaux de notification.
type ChannelsHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Engine *alerting.Engine
}

func (h *ChannelsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alert-channels")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.delete(w, r, id)
	case r.Method == http.MethodPost && sub == "test":
		h.test(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *ChannelsHandler) list(w http.ResponseWriter, _ *http.Request) {
	rows, err := h.DB.Query(
		`SELECT id, name, type, config, enabled, created_at, updated_at FROM alert_channels ORDER BY name`)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, typ, cfgJSON string
		var enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &typ, &cfgJSON, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}
		var cfg map[string]any
		_ = json.Unmarshal([]byte(cfgJSON), &cfg)
		// Masquer les secrets dans la réponse
		cfg = maskSecrets(cfg)
		out = append(out, map[string]any{
			"id": id, "name": name, "type": typ, "config": cfg,
			"enabled": enabled == 1, "created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	jsonOK(w, out)
}

func (h *ChannelsHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string         `json:"name"`
		Type    string         `json:"type"`
		Config  map[string]any `json:"config"`
		Enabled *bool          `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.Name == "" || body.Type == "" {
		http.Error(w, "name et type requis", http.StatusBadRequest)
		return
	}
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	cfgJSON, _ := json.Marshal(body.Config)
	id := uuid.New().String()
	_, err := h.DB.Exec(
		`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES (?, ?, ?, ?, ?)`,
		id, body.Name, body.Type, string(cfgJSON), enabled,
	)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"id": id})
}

func (h *ChannelsHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name    string         `json:"name"`
		Config  map[string]any `json:"config"`
		Enabled *bool          `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	cfgJSON, _ := json.Marshal(body.Config)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	_, err := h.DB.Exec(
		`UPDATE alert_channels SET name=?, config=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		body.Name, string(cfgJSON), enabled, id,
	)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ChannelsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.DB.Exec(`DELETE FROM alert_channels WHERE id=?`, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

func (h *ChannelsHandler) test(w http.ResponseWriter, r *http.Request, id string) {
	var row struct {
		Name    string
		Type    string
		CfgJSON string
	}
	err := h.DB.QueryRow(`SELECT name, type, config FROM alert_channels WHERE id=?`, id).
		Scan(&row.Name, &row.Type, &row.CfgJSON)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	var cfg map[string]any
	_ = json.Unmarshal([]byte(row.CfgJSON), &cfg)
	cch := channels.Channel{ID: id, Name: row.Name, Type: row.Type, Config: cfg, Enabled: true}
	sender, err := channels.Build(cch)
	if err != nil {
		alertJSONErr(w, err, http.StatusBadRequest)
		return
	}
	msg := channels.Message{
		RuleName: "test",
		Trigger:  string(alerting.TriggerNodeOffline),
		Severity: string(alerting.SevInfo),
		Title:    "[Goproxify] Test de canal",
		Body:     "Ceci est un message de test envoyé depuis l'Administration Goproxify.",
		FiredAt:  time.Now(),
	}
	if err := sender.Send(r.Context(), msg); err != nil {
		alertJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// RulesHandler gère le CRUD des règles d'alertes + simulation.
type RulesHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Engine *alerting.Engine
}

func (h *RulesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alert-rules")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodGet && id == "triggers":
		h.listTriggers(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPost && id == "simulate":
		h.simulate(w, r)
	case r.Method == http.MethodPut && id != "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "":
		h.delete(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *RulesHandler) list(w http.ResponseWriter, _ *http.Request) {
	rows, err := h.DB.Query(
		`SELECT id, name, scope, triggers, channels, cooldown_sec, priority, enabled, created_at, updated_at
		 FROM alert_rules ORDER BY priority DESC, name`)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, scopeJSON, triggersJSON, chansJSON string
		var cooldown, priority, enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &scopeJSON, &triggersJSON, &chansJSON, &cooldown, &priority, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}
		var scope, triggers, chans any
		_ = json.Unmarshal([]byte(scopeJSON), &scope)
		_ = json.Unmarshal([]byte(triggersJSON), &triggers)
		_ = json.Unmarshal([]byte(chansJSON), &chans)
		out = append(out, map[string]any{
			"id": id, "name": name, "scope": scope, "triggers": triggers, "channels": chans,
			"cooldown_sec": cooldown, "priority": priority, "enabled": enabled == 1,
			"created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	jsonOK(w, out)
}

func (h *RulesHandler) listTriggers(w http.ResponseWriter, r *http.Request) {
	var out []map[string]string
	for _, t := range alerting.AllTriggers {
		out = append(out, map[string]string{
			"id":    string(t),
			"label": alerting.TriggerLabels[t],
		})
	}
	jsonOK(w, out)
}

func (h *RulesHandler) create(w http.ResponseWriter, r *http.Request) {
	var body alerting.Rule
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	id := uuid.New().String()
	scopeJSON, _ := json.Marshal(body.Scope)
	triggersJSON, _ := json.Marshal(body.Triggers)
	chansJSON, _ := json.Marshal(body.Channels)
	enabled := 1
	if !body.Enabled {
		enabled = 0
	}
	_, err := h.DB.Exec(
		`INSERT INTO alert_rules (id, name, scope, triggers, channels, cooldown_sec, priority, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, body.Name, string(scopeJSON), string(triggersJSON), string(chansJSON),
		body.CooldownSec, body.Priority, enabled,
	)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if h.Engine != nil {
		h.Engine.InvalidateRuleCache()
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"id": id})
}

func (h *RulesHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body alerting.Rule
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	scopeJSON, _ := json.Marshal(body.Scope)
	triggersJSON, _ := json.Marshal(body.Triggers)
	chansJSON, _ := json.Marshal(body.Channels)
	enabled := 1
	if !body.Enabled {
		enabled = 0
	}
	_, err := h.DB.Exec(
		`UPDATE alert_rules SET name=?, scope=?, triggers=?, channels=?, cooldown_sec=?, priority=?, enabled=?, updated_at=CURRENT_TIMESTAMP
		 WHERE id=?`,
		body.Name, string(scopeJSON), string(triggersJSON), string(chansJSON),
		body.CooldownSec, body.Priority, enabled, id,
	)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if h.Engine != nil {
		h.Engine.InvalidateRuleCache()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RulesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.DB.Exec(`DELETE FROM alert_rules WHERE id=?`, id) //nolint:errcheck
	if h.Engine != nil {
		h.Engine.InvalidateRuleCache()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RulesHandler) simulate(w http.ResponseWriter, r *http.Request) {
	var ev alerting.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	rows, err := h.DB.Query(
		`SELECT id, name, scope, triggers, channels, cooldown_sec, priority, enabled FROM alert_rules WHERE enabled=1 ORDER BY priority DESC`)
	if err != nil {
		alertJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type match struct {
		Rule     string   `json:"rule"`
		Channels []string `json:"channels"`
	}
	var matches []match
	for rows.Next() {
		var rule alerting.Rule
		var scopeJSON, triggersJSON, chansJSON string
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &scopeJSON, &triggersJSON, &chansJSON, &rule.CooldownSec, &rule.Priority, &enabled); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(scopeJSON), &rule.Scope)
		_ = json.Unmarshal([]byte(triggersJSON), &rule.Triggers)
		_ = json.Unmarshal([]byte(chansJSON), &rule.Channels)
		if matchesTrigger(rule, ev) && matchesScope(rule.Scope, ev) {
			matches = append(matches, match{Rule: rule.Name, Channels: rule.Channels})
		}
	}
	if matches == nil {
		matches = []match{}
	}
	jsonOK(w, map[string]any{"matches": matches})
}

// helpers

func matchesTrigger(r alerting.Rule, ev alerting.Event) bool {
	for _, t := range r.Triggers {
		if t == ev.Trigger {
			return true
		}
	}
	return false
}

func matchesScope(s alerting.Scope, ev alerting.Event) bool {
	if len(s.Nodes) > 0 && ev.NodeName != "" {
		found := false
		for _, n := range s.Nodes {
			if n == ev.NodeName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(s.Components) > 0 && ev.Component != "" {
		found := false
		for _, c := range s.Components {
			if c == ev.Component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func maskSecrets(cfg map[string]any) map[string]any {
	out := make(map[string]any, len(cfg))
	secret := map[string]bool{"password": true, "token": true, "api_key": true, "secret": true, "user_token": true, "app_token": true}
	for k, v := range cfg {
		if secret[k] {
			out[k] = "••••••••"
		} else {
			out[k] = v
		}
	}
	return out
}

func alertJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
