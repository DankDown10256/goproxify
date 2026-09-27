// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// exportedRule / exportedChannel / exportedSilence forment le format GitOps
// d'export-import de la configuration d'automatisation (règles, canaux,
// silences). Les IDs ne sont jamais exportés : l'import upserte par nom.
type exportedRule struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     bool           `yaml:"enabled" json:"enabled"`
	Condition   map[string]any `yaml:"condition" json:"condition"`
	Action      map[string]any `yaml:"action" json:"action"`
	CooldownSec int            `yaml:"cooldown_sec" json:"cooldown_sec"`
}

type exportedChannel struct {
	Name    string         `yaml:"name" json:"name"`
	Type    string         `yaml:"type" json:"type"`
	Config  map[string]any `yaml:"config" json:"config"`
	Enabled bool           `yaml:"enabled" json:"enabled"`
}

type exportedSilence struct {
	Name     string   `yaml:"name" json:"name"`
	RuleIDs  []string `yaml:"rule_ids,omitempty" json:"rule_ids,omitempty"`
	StartsAt string   `yaml:"starts_at" json:"starts_at"`
	EndsAt   string   `yaml:"ends_at" json:"ends_at"`
}

type automationExport struct {
	Version  int               `yaml:"version" json:"version"`
	Rules    []exportedRule    `yaml:"rules,omitempty" json:"rules,omitempty"`
	Channels []exportedChannel `yaml:"channels,omitempty" json:"channels,omitempty"`
	Silences []exportedSilence `yaml:"silences,omitempty" json:"silences,omitempty"`
}

// exportAutomation sert GET /api/v1/rules-engine/export : la configuration
// complète (règles, canaux, silences) en YAML, réimportable telle quelle.
// Les canaux exportent leur config en clair (identifiants inclus) : ce
// document doit être traité comme un secret, au même titre qu'une sauvegarde.
func (h *RulesEngineHandler) exportAutomation(w http.ResponseWriter, r *http.Request) {
	out := automationExport{Version: 1}

	ruleRows, err := h.DB.QueryContext(r.Context(),
		`SELECT name, description, enabled, condition_json, action_json, cooldown_sec
		 FROM rules_engine_rules ORDER BY name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	for ruleRows.Next() {
		var er exportedRule
		var enabled int
		var condJSON, actionJSON string
		if err := ruleRows.Scan(&er.Name, &er.Description, &enabled, &condJSON, &actionJSON, &er.CooldownSec); err != nil {
			continue
		}
		er.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(condJSON), &er.Condition)
		_ = json.Unmarshal([]byte(actionJSON), &er.Action)
		out.Rules = append(out.Rules, er)
	}
	ruleRows.Close()

	chanRows, err := h.DB.QueryContext(r.Context(),
		`SELECT name, type, config, enabled FROM alert_channels ORDER BY name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	for chanRows.Next() {
		var ec exportedChannel
		var enabled int
		var cfgJSON string
		if err := chanRows.Scan(&ec.Name, &ec.Type, &cfgJSON, &enabled); err != nil {
			continue
		}
		ec.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(cfgJSON), &ec.Config)
		out.Channels = append(out.Channels, ec)
	}
	chanRows.Close()

	silRows, err := h.DB.QueryContext(r.Context(),
		`SELECT name, rule_ids, starts_at, ends_at FROM automation_silences ORDER BY starts_at DESC`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	for silRows.Next() {
		var es exportedSilence
		var ruleIDsJSON string
		if err := silRows.Scan(&es.Name, &ruleIDsJSON, &es.StartsAt, &es.EndsAt); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(ruleIDsJSON), &es.RuleIDs)
		out.Silences = append(out.Silences, es)
	}
	silRows.Close()

	data, err := yaml.Marshal(out)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="automation.yaml"`)
	_, _ = w.Write(data)
}

// importAutomation sert POST /api/v1/rules-engine/import : applique un document
// au même format que l'export. Les règles et canaux sont upsertés par nom
// (créés s'ils n'existent pas, mis à jour sinon) ; les silences sont toujours
// créés (une fenêtre de temps ne se "met pas à jour", elle s'ajoute).
func (h *RulesEngineHandler) importAutomation(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	defer body.Close()
	var doc automationExport
	if err := yaml.NewDecoder(body).Decode(&doc); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}

	summary := map[string]int{"rules_created": 0, "rules_updated": 0, "channels_created": 0, "channels_updated": 0, "silences_created": 0}
	ctx := r.Context()

	for _, er := range doc.Rules {
		if er.Name == "" {
			continue
		}
		condJSON, _ := json.Marshal(er.Condition)
		actionJSON, _ := json.Marshal(er.Action)
		enabled := 0
		if er.Enabled {
			enabled = 1
		}
		var existingID string
		err := h.DB.QueryRowContext(ctx, `SELECT id FROM rules_engine_rules WHERE name=?`, er.Name).Scan(&existingID)
		if err == nil {
			_, execErr := h.DB.ExecContext(ctx,
				`UPDATE rules_engine_rules SET description=?, enabled=?, condition_json=?, action_json=?, cooldown_sec=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				er.Description, enabled, string(condJSON), string(actionJSON), er.CooldownSec, existingID,
			)
			if execErr == nil {
				summary["rules_updated"]++
				h.snapshotRuleVersion(ctx, existingID, er.Name, er.Description, er.Enabled, string(condJSON), string(actionJSON), er.CooldownSec)
			}
			continue
		}
		id := uuid.New().String()
		if _, execErr := h.DB.ExecContext(ctx,
			`INSERT INTO rules_engine_rules (id, name, description, enabled, condition_json, action_json, cooldown_sec) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, er.Name, er.Description, enabled, string(condJSON), string(actionJSON), er.CooldownSec,
		); execErr == nil {
			summary["rules_created"]++
			h.snapshotRuleVersion(ctx, id, er.Name, er.Description, er.Enabled, string(condJSON), string(actionJSON), er.CooldownSec)
		}
	}

	for _, ec := range doc.Channels {
		if ec.Name == "" || ec.Type == "" {
			continue
		}
		cfgJSON, _ := json.Marshal(ec.Config)
		enabled := 0
		if ec.Enabled {
			enabled = 1
		}
		var existingID string
		err := h.DB.QueryRowContext(ctx, `SELECT id FROM alert_channels WHERE name=?`, ec.Name).Scan(&existingID)
		if err == nil {
			_, execErr := h.DB.ExecContext(ctx,
				`UPDATE alert_channels SET type=?, config=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				ec.Type, string(cfgJSON), enabled, existingID,
			)
			if execErr == nil {
				summary["channels_updated"]++
			}
			continue
		}
		id := uuid.New().String()
		if _, execErr := h.DB.ExecContext(ctx,
			`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES (?, ?, ?, ?, ?)`,
			id, ec.Name, ec.Type, string(cfgJSON), enabled,
		); execErr == nil {
			summary["channels_created"]++
		}
	}

	for _, es := range doc.Silences {
		if es.Name == "" || es.StartsAt == "" || es.EndsAt == "" {
			continue
		}
		ruleIDs := es.RuleIDs
		if ruleIDs == nil {
			ruleIDs = []string{}
		}
		ruleIDsJSON, _ := json.Marshal(ruleIDs)
		id := uuid.New().String()
		if _, execErr := h.DB.ExecContext(ctx,
			`INSERT INTO automation_silences (id, name, rule_ids, starts_at, ends_at) VALUES (?, ?, ?, ?, ?)`,
			id, es.Name, string(ruleIDsJSON), es.StartsAt, es.EndsAt,
		); execErr == nil {
			summary["silences_created"]++
		}
	}

	jsonOK(w, summary)
}
