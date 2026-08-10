// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package alerting implémente le moteur d'alertes de Goproxify.
package alerting

import "time"

// TriggerType identifie le type de déclencheur.
type TriggerType string

const (
	TriggerNodeOffline          TriggerType = "node_offline"
	TriggerCertExpiringSoon     TriggerType = "cert_expiring_soon"
	TriggerCVEDetected          TriggerType = "cve_detected"
	TriggerFail2BanBan          TriggerType = "fail2ban_ban"
	TriggerCrowdSecCritical     TriggerType = "crowdsec_critical"
	TriggerConfigChanged        TriggerType = "config_changed"
	TriggerBackupFailed         TriggerType = "backup_failed"
	TriggerHighErrorRate        TriggerType = "high_error_rate"
	TriggerHighLatency          TriggerType = "high_latency"
	TriggerAdminAuthFailures    TriggerType = "admin_auth_failures"
	TriggerScaleEvent           TriggerType = "scale_event"
	TriggerHealthEscalation     TriggerType = "health_escalation"
)

// AllTriggers liste tous les déclencheurs disponibles.
var AllTriggers = []TriggerType{
	TriggerNodeOffline, TriggerCertExpiringSoon, TriggerCVEDetected,
	TriggerFail2BanBan, TriggerCrowdSecCritical, TriggerConfigChanged,
	TriggerBackupFailed, TriggerHighErrorRate, TriggerHighLatency,
	TriggerAdminAuthFailures, TriggerScaleEvent, TriggerHealthEscalation,
}

// TriggerLabels associe chaque déclencheur à son libellé lisible.
var TriggerLabels = map[TriggerType]string{
	TriggerNodeOffline:       "Nœud Core/Agent hors ligne",
	TriggerCertExpiringSoon: "Certificat expirant prochainement",
	TriggerCVEDetected:      "CVE détectée sur un backend",
	TriggerFail2BanBan:      "Nouveau ban Fail2Ban",
	TriggerCrowdSecCritical: "Décision CrowdSec critique",
	TriggerConfigChanged:    "Modification de configuration sensible",
	TriggerBackupFailed:     "Échec de sauvegarde planifiée",
	TriggerHighErrorRate:    "Taux d'erreurs HTTP > seuil",
	TriggerHighLatency:      "Latence P95 > seuil",
	TriggerAdminAuthFailures: "Tentatives de connexion admin échouées",
	TriggerScaleEvent:        "Événement d'auto-scaling (montée/descente)",
	TriggerHealthEscalation:  "Escalade de santé conteneur (restart→recreate→rollback)",
}

// Severity classe la sévérité d'une alerte.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Event représente un événement qui peut déclencher des alertes.
type Event struct {
	Trigger   TriggerType
	Severity  Severity
	NodeName  string
	Domain    string
	Component string // core | agent | admin
	Team      string
	Detail    map[string]any
	FiredAt   time.Time
}

// Scope filtre les événements auxquels une règle est sensible.
type Scope struct {
	Nodes      []string `json:"nodes,omitempty"`       // noms de nœuds (vide = tous)
	DomainGlob string   `json:"domain_glob,omitempty"` // ex: "*.prod.fr"
	Teams      []string `json:"teams,omitempty"`
	Components []string `json:"components,omitempty"` // core, agent, admin
	MinSev     Severity `json:"min_severity,omitempty"`
}

// Rule est une règle de routage d'alertes.
type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Scope       Scope       `json:"scope"`
	Triggers    []TriggerType `json:"triggers"`
	Channels    []string    `json:"channels"` // IDs de alert_channels
	CooldownSec int         `json:"cooldown_sec"`
	Priority    int         `json:"priority"`
	Enabled     bool        `json:"enabled"`
}

// Channel est un canal de notification stocké en DB.
type Channel struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Config  map[string]any `json:"config"`
	Enabled bool           `json:"enabled"`
}

// Message est le payload envoyé à un canal.
type Message struct {
	RuleName string
	Trigger  TriggerType
	Severity Severity
	Title    string
	Body     string
	Detail   map[string]any
	FiredAt  time.Time
}
