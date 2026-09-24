// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package rulesengine évalue périodiquement des règles condition→action sur l'état
// du système et exécute des remediations automatiques (désactiver un proxy, bannir
// une IP, notifier…).
package rulesengine

import "time"

// ConditionType identifie le type de condition.
type ConditionType string

const (
	CondCVECritical    ConditionType = "cve_critical"     // CVE avec CVSS ≥ seuil sur proxy actif
	CondBanSpike       ConditionType = "ban_spike"         // > N bans dans une fenêtre de temps
	CondEngineSilent   ConditionType = "engine_silent"     // moteur IPS sans activité depuis > X min
	CondProxyErrorRate ConditionType = "proxy_error_rate"  // taux d'erreurs HTTP > seuil
	CondBanRepeat      ConditionType = "ban_repeat"        // même IP bannie ≥ N fois
	CondNodeOffline    ConditionType = "node_offline"      // Core/Agent sans heartbeat depuis > X min
	CondCertExpiring   ConditionType = "cert_expiring"      // certificat TLS expirant sous N jours
)

// ActionType identifie l'action à exécuter.
type ActionType string

const (
	ActionDisableProxy ActionType = "disable_proxy" // désactiver le proxy lié au backend CVE
	ActionBanIP        ActionType = "ban_ip"         // bannir l'IP déclenchante
	ActionNotify       ActionType = "notify"          // émettre vers le moteur d'alertes
	ActionEnableStrict ActionType = "enable_strict"   // réduire max_errors F2B (mode strict temporaire)
	ActionWebhookCall  ActionType = "webhook_call"    // POST JSON vers une URL externe
	ActionRunBackup    ActionType = "run_backup"      // déclencher un snapshot de sauvegarde immédiat
)

// Condition décrit le prédicat évalué périodiquement.
type Condition struct {
	Type ConditionType `json:"type"`

	// CondCVECritical / CondCVEOnProxy
	CVSSThreshold float64 `json:"cvss_threshold,omitempty"` // défaut : 9.0
	ProxyID       string  `json:"proxy_id,omitempty"`        // "" = tous les proxies

	// CondBanSpike
	BanCount  int    `json:"ban_count,omitempty"`  // nombre de bans déclenchant l'alerte
	BanWindow string `json:"ban_window,omitempty"` // durée ex: "1h", "15m"
	BanSource string `json:"ban_source,omitempty"` // "" = toutes sources

	// CondEngineSilent
	EngineType    string `json:"engine_type,omitempty"`    // "fail2ban" | "crowdsec"
	SilentMinutes int    `json:"silent_minutes,omitempty"` // défaut : 10

	// CondProxyErrorRate
	ErrorRateThreshold float64 `json:"error_rate_threshold,omitempty"` // pourcentage 0-100
	ErrorRateWindow    string  `json:"error_rate_window,omitempty"`    // ex: "5m"

	// CondBanRepeat
	RepeatCount  int    `json:"repeat_count,omitempty"`  // nombre de bans de la même IP
	RepeatWindow string `json:"repeat_window,omitempty"` // fenêtre d'observation

	// CondNodeOffline
	NodeName       string `json:"node_name,omitempty"`       // "" = tous les nœuds
	OfflineMinutes int    `json:"offline_minutes,omitempty"` // défaut : 5

	// CondCertExpiring
	Domain   string `json:"domain,omitempty"`    // "" = tous les domaines
	DaysLeft int    `json:"days_left,omitempty"` // défaut : 15
}

// Action décrit la remédiation à appliquer si la condition est vraie.
type Action struct {
	Type ActionType `json:"type"`

	// ActionDisableProxy
	ProxyID string `json:"proxy_id,omitempty"` // "" = proxy lié à la condition

	// ActionBanIP — enrichissement
	BanReason   string `json:"ban_reason,omitempty"`
	BanDuration string `json:"ban_duration,omitempty"` // ex: "24h", "" = permanent

	// ActionNotify
	NotifySeverity string `json:"notify_severity,omitempty"` // info | warning | critical
	NotifyMessage  string `json:"notify_message,omitempty"`

	// ActionEnableStrict
	StrictDuration string `json:"strict_duration,omitempty"` // ex: "30m"

	// ActionWebhookCall
	WebhookURL string `json:"webhook_url,omitempty"`

	// ActionRunBackup
	BackupRetention int `json:"backup_retention,omitempty"` // 0 = pas de purge automatique
}

// Rule est une règle du moteur : une condition + une action + métadonnées.
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	Condition   Condition `json:"condition"`
	Action      Action    `json:"action"`
	CooldownSec int       `json:"cooldown_sec"` // min secondes entre deux déclenchements
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	FireCount   int       `json:"fire_count"`
}

// ExecLog est un enregistrement d'exécution d'une règle.
type ExecLog struct {
	ID          int64      `json:"id"`
	RuleID      string     `json:"rule_id"`
	RuleName    string     `json:"rule_name,omitempty"`
	CondResult  bool       `json:"cond_result"`
	ActionTaken bool       `json:"action_taken"`
	Detail      string     `json:"detail"`
	Error       string     `json:"error,omitempty"`
	FiredAt     time.Time  `json:"fired_at"`
}

// ActionContext est passé aux exécuteurs d'actions.
type ActionContext struct {
	Rule    Rule
	Detail  map[string]any // données issues de l'évaluateur de condition
}
