// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package rulesengine évalue périodiquement des règles condition→action
// en utilisant uniquement l'état en mémoire du Core (sans DB).
// Les règles sont poussées depuis l'Admin via WS.
package rulesengine

import "time"

// ConditionType identifie le type de condition.
type ConditionType string

const (
	CondCVECritical    ConditionType = "cve_critical"    // non évaluable en Core (toujours false)
	CondBanSpike       ConditionType = "ban_spike"        // > N bans dans une fenêtre de temps
	CondEngineSilent   ConditionType = "engine_silent"    // moteur IPS sans activité depuis > X min
	CondProxyErrorRate ConditionType = "proxy_error_rate" // taux d'erreurs HTTP > seuil
	CondBanRepeat      ConditionType = "ban_repeat"       // même IP bannie ≥ N fois
)

// ActionType identifie l'action à exécuter.
type ActionType string

const (
	ActionDisableProxy ActionType = "disable_proxy"
	ActionBanIP        ActionType = "ban_ip"
	ActionNotify       ActionType = "notify"
	ActionEnableStrict ActionType = "enable_strict"
)

// Condition décrit le prédicat évalué périodiquement.
type Condition struct {
	Type ConditionType `json:"type"`

	CVSSThreshold float64 `json:"cvss_threshold,omitempty"`
	ProxyID       string  `json:"proxy_id,omitempty"`

	BanCount  int    `json:"ban_count,omitempty"`
	BanWindow string `json:"ban_window,omitempty"`
	BanSource string `json:"ban_source,omitempty"`

	EngineType    string `json:"engine_type,omitempty"`
	SilentMinutes int    `json:"silent_minutes,omitempty"`

	ErrorRateThreshold float64 `json:"error_rate_threshold,omitempty"`
	ErrorRateWindow    string  `json:"error_rate_window,omitempty"`

	RepeatCount  int    `json:"repeat_count,omitempty"`
	RepeatWindow string `json:"repeat_window,omitempty"`
}

// Action décrit la remédiation à appliquer si la condition est vraie.
type Action struct {
	Type ActionType `json:"type"`

	ProxyID string `json:"proxy_id,omitempty"`

	BanReason   string `json:"ban_reason,omitempty"`
	BanDuration string `json:"ban_duration,omitempty"`

	NotifySeverity string `json:"notify_severity,omitempty"`
	NotifyMessage  string `json:"notify_message,omitempty"`

	StrictDuration string `json:"strict_duration,omitempty"`
}

// Rule est une règle : une condition + une action + métadonnées.
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	Condition   Condition `json:"condition"`
	Action      Action    `json:"action"`
	CooldownSec int       `json:"cooldown_sec"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ExecLog est un enregistrement d'exécution d'une règle, transmis à l'Admin via WS.
type ExecLog struct {
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	CondResult  bool           `json:"cond_result"`
	ActionTaken bool           `json:"action_taken"`
	Detail      map[string]any `json:"detail,omitempty"`
	Error       string         `json:"error,omitempty"`
	FiredAt     time.Time      `json:"fired_at"`
}
