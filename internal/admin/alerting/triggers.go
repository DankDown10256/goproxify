// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package alerting implémente le moteur d'alertes de Goproxify.
package alerting

import "time"

// TriggerType identifie le type de déclencheur.
type TriggerType string

const (
	TriggerNodeOffline            TriggerType = "node_offline"
	TriggerCertExpiringSoon       TriggerType = "cert_expiring_soon"
	TriggerCVEDetected            TriggerType = "cve_detected"
	TriggerFleetBan               TriggerType = "fleet_ban"
	TriggerCrowdSecCritical       TriggerType = "crowdsec_critical"
	TriggerConfigChanged          TriggerType = "config_changed"
	TriggerBackupFailed           TriggerType = "backup_failed"
	TriggerHighErrorRate          TriggerType = "high_error_rate"
	TriggerHighLatency            TriggerType = "high_latency"
	TriggerAdminAuthFailures      TriggerType = "admin_auth_failures"
	TriggerScaleEvent             TriggerType = "scale_event"
	TriggerHealthEscalation       TriggerType = "health_escalation"
	TriggerEphorBan               TriggerType = "ephor_ban"                 // IP bannie par Ephor/WAF
	TriggerBackendDown            TriggerType = "backend_down"              // backend déclaré indisponible par health-check
	TriggerCertDeployFailed       TriggerType = "cert_deploy_failed"        // échec de déploiement d'un certificat
	TriggerIPProfileRefreshFailed TriggerType = "ip_profile_refresh_failed" // feed d'un profil IP en échec de façon répétée
	TriggerSLOBurn                TriggerType = "slo_burn"                  // budget d'erreur SLO consommé trop vite ou épuisé
	TriggerAutomationNotify       TriggerType = "automation_notify"         // action « notifier » d'un flux d'automatisation
	TriggerSIEMExportLag          TriggerType = "siem_export_lag"           // l'export vers un SIEM prend du retard sur des logs qui vont être purgés
	TriggerSurfaceSuggestion      TriggerType = "surface_suggestion"        // un ajout est suggéré à la politique de surface d'un proxy (ADR 0016)
	TriggerLogBufferRisk          TriggerType = "log_buffer_risk"           // des logs que l'Admin n'a pas rangés approchent de la borne où la passerelle les supprime (ADR 0018)
	TriggerTrafficDeviation       TriggerType = "traffic_deviation"         // le trafic d'une route s'écarte de sa référence saisonnière (ADR 0020, étape 3)
)

// AllTriggers liste tous les déclencheurs disponibles.
var AllTriggers = []TriggerType{
	TriggerNodeOffline, TriggerCertExpiringSoon, TriggerCVEDetected,
	TriggerFleetBan, TriggerCrowdSecCritical, TriggerConfigChanged,
	TriggerBackupFailed, TriggerHighErrorRate, TriggerHighLatency,
	TriggerAdminAuthFailures, TriggerScaleEvent, TriggerHealthEscalation,
	TriggerEphorBan, TriggerBackendDown, TriggerCertDeployFailed, TriggerIPProfileRefreshFailed,
	TriggerSLOBurn, TriggerAutomationNotify, TriggerSIEMExportLag, TriggerSurfaceSuggestion, TriggerLogBufferRisk, TriggerTrafficDeviation,
}

// TriggerOutputs liste les clés de Detail que porte chaque déclencheur : un flux déclenché par
// l'événement peut s'en servir comme variables ({{detail.ip}}).
var TriggerOutputs = map[TriggerType][]string{
	TriggerCertExpiringSoon:       {"days_left"},
	TriggerFleetBan:               {"ip", "reason"},
	TriggerCrowdSecCritical:       {"ip", "scenario", "origin", "type"},
	TriggerBackupFailed:           {"title"},
	TriggerHighErrorRate:          {"domain", "error_rate", "errors", "total", "window_sec"},
	TriggerHighLatency:            {"domain", "avg_lat_ms", "threshold", "window_sec"},
	TriggerAdminAuthFailures:      {"email", "ip"},
	TriggerScaleEvent:             {"event_type", "detail", "container"},
	TriggerHealthEscalation:       {"event_type", "detail", "container"},
	TriggerEphorBan:               {"ip", "reason"},
	TriggerBackendDown:            {"url"},
	TriggerCertDeployFailed:       {"target_id", "type", "message"},
	TriggerIPProfileRefreshFailed: {"profile_id", "profile", "consecutive_failures", "error", "last_updated_at"},
	TriggerSLOBurn:                {"node_name", "state", "target", "availability", "budget_left", "burn_1h", "burn_6h"},
	TriggerAutomationNotify:       {"flow_id", "flow_name", "message"},
	TriggerSIEMExportLag:          {"destination", "node_name", "lag_min", "at_risk", "error"},
	TriggerLogBufferRisk:          {"node_name", "unacked_days", "max_days"},
	TriggerSurfaceSuggestion:      {"proxy", "domain", "count", "suggestions", "low_confidence"},
	TriggerTrafficDeviation:       {"route", "level", "rps", "expected", "natures", "hardened"},
}

// TriggerLabels associe chaque déclencheur à son libellé lisible.
var TriggerLabels = map[TriggerType]string{
	TriggerNodeOffline:            "Nœud passerelle/Agent hors ligne",
	TriggerCertExpiringSoon:       "Certificat expirant prochainement",
	TriggerCVEDetected:            "CVE détectée sur un backend",
	TriggerFleetBan:               "Nouveau ban des Seuils multi-passerelles",
	TriggerCrowdSecCritical:       "Décision CrowdSec critique",
	TriggerConfigChanged:          "Modification de configuration sensible",
	TriggerBackupFailed:           "Échec de sauvegarde planifiée",
	TriggerHighErrorRate:          "Taux d'erreurs HTTP > seuil",
	TriggerHighLatency:            "Latence P95 > seuil",
	TriggerAdminAuthFailures:      "Tentatives de connexion admin échouées",
	TriggerScaleEvent:             "Événement d'auto-scaling (montée/descente)",
	TriggerHealthEscalation:       "Escalade de santé conteneur (restart→recreate→rollback)",
	TriggerEphorBan:               "IP bannie par Ephor / WAF",
	TriggerBackendDown:            "Backend déclaré indisponible par health-check",
	TriggerCertDeployFailed:       "Échec de déploiement d'un certificat",
	TriggerIPProfileRefreshFailed: "Mise à jour d'un profil IP en échec répété",
	TriggerSLOBurn:                "Budget d'erreur SLO consommé trop vite",
	TriggerAutomationNotify:       "Notification d'un flux d'automatisation",
	TriggerSIEMExportLag:          "Export SIEM en retard",
	TriggerLogBufferRisk:          "Logs d'une passerelle non rangés par l'Admin, près d'être supprimés",
	TriggerSurfaceSuggestion:      "Ajout suggéré à la politique de surface d'un proxy",
	TriggerTrafficDeviation:       "Trafic d'une route hors de sa référence saisonnière",
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
	Component string // edge | agent | admin
	Team      string
	Detail    map[string]any
	FiredAt   time.Time
}

// Scope filtre les événements auxquels une règle est sensible.
type Scope struct {
	Nodes      []string `json:"nodes,omitempty"`       // noms de nœuds (vide = tous)
	DomainGlob string   `json:"domain_glob,omitempty"` // ex: "*.prod.fr"
	Teams      []string `json:"teams,omitempty"`
	Components []string `json:"components,omitempty"` // edge, agent, admin
	MinSev     Severity `json:"min_severity,omitempty"`
}

// Rule est une règle de routage d'alertes.
type Rule struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Scope          Scope            `json:"scope"`
	Triggers       []TriggerType    `json:"triggers"`
	Channels       []string         `json:"channels"` // IDs de alert_channels
	CooldownSec    int              `json:"cooldown_sec"`
	Priority       int              `json:"priority"`
	Enabled        bool             `json:"enabled"`
	GroupWindowSec int              `json:"group_window_sec,omitempty"` // 0 = pas de regroupement : chaque événement notifie immédiatement
	Escalation     []EscalationStep `json:"escalation,omitempty"`       // paliers relancés tant que l'événement n'est pas acquitté
}

// EscalationStep est un palier d'escalade : si l'événement n'est pas acquitté
// AfterSec secondes après son déclenchement, il est renotifié vers Channels
// (vide = mêmes canaux que la règle).
type EscalationStep struct {
	AfterSec int      `json:"after_sec"`
	Channels []string `json:"channels,omitempty"`
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
