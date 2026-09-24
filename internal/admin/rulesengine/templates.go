// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

// Template est une règle préconfigurée, proposée dans le store de règles.
// Installer un template crée une Rule concrète (via l'API), avec ses propres
// paramètres par défaut modifiables avant activation.
type Template struct {
	ID          string      `json:"id"`
	Category    string      `json:"category"` // "security" | "reliability" | "compliance"
	Name        string      `json:"name"`
	Description string      `json:"description"`
	CooldownSec int         `json:"cooldown_sec"`
	Condition   Condition   `json:"condition"`
	Action      Action      `json:"action"`
}

// Templates liste le catalogue v1 des règles préconfigurées.
func Templates() []Template {
	return []Template{
		{
			ID:          "cve-critical-autodisable",
			Category:    "security",
			Name:        "Désactiver un proxy sur CVE critique",
			Description: "Désactive automatiquement un proxy dont le backend expose une CVE avec un score CVSS ≥ 9.0.",
			CooldownSec: 3600,
			Condition:   Condition{Type: CondCVECritical, CVSSThreshold: 9.0},
			Action:      Action{Type: ActionDisableProxy},
		},
		{
			ID:          "ban-spike-strict-mode",
			Category:    "security",
			Name:        "Mode strict sur pic de bans",
			Description: "Passe le WAF en mode strict temporaire lorsque plus de 20 bans surviennent en 15 minutes.",
			CooldownSec: 900,
			Condition:   Condition{Type: CondBanSpike, BanCount: 20, BanWindow: "15m"},
			Action:      Action{Type: ActionEnableStrict, StrictDuration: "30m"},
		},
		{
			ID:          "ban-repeat-notify",
			Category:    "security",
			Name:        "Alerter sur IP récidiviste",
			Description: "Notifie l'équipe quand la même IP est bannie 3 fois ou plus sur 24h.",
			CooldownSec: 1800,
			Condition:   Condition{Type: CondBanRepeat, RepeatCount: 3, RepeatWindow: "24h"},
			Action:      Action{Type: ActionNotify, NotifySeverity: "warning", NotifyMessage: "IP récidiviste détectée"},
		},
		{
			ID:          "engine-silent-alert",
			Category:    "reliability",
			Name:        "Alerter si le moteur IPS est silencieux",
			Description: "Notifie si fail2ban ou CrowdSec n'a montré aucune activité depuis 30 minutes (panne probable).",
			CooldownSec: 1800,
			Condition:   Condition{Type: CondEngineSilent, EngineType: "fail2ban", SilentMinutes: 30},
			Action:      Action{Type: ActionNotify, NotifySeverity: "critical", NotifyMessage: "Moteur IPS silencieux"},
		},
		{
			ID:          "error-rate-ban",
			Category:    "reliability",
			Name:        "Bannir sur taux d'erreur anormal",
			Description: "Bannit temporairement les sources générant plus de 50% d'erreurs HTTP sur 5 minutes.",
			CooldownSec: 600,
			Condition:   Condition{Type: CondProxyErrorRate, ErrorRateThreshold: 50, ErrorRateWindow: "5m"},
			Action:      Action{Type: ActionBanIP, BanDuration: "1h", BanReason: "Taux d'erreur anormal"},
		},
		{
			ID:          "node-offline-notify",
			Category:    "reliability",
			Name:        "Alerter sur nœud hors ligne",
			Description: "Notifie dès qu'un Core ou un Agent n'a pas envoyé de heartbeat depuis plus de 5 minutes.",
			CooldownSec: 900,
			Condition:   Condition{Type: CondNodeOffline, OfflineMinutes: 5},
			Action:      Action{Type: ActionNotify, NotifySeverity: "critical", NotifyMessage: "Nœud hors ligne"},
		},
		{
			ID:          "cert-expiring-backup",
			Category:    "compliance",
			Name:        "Sauvegarde avant expiration de certificat",
			Description: "Déclenche un snapshot de sauvegarde dès qu'un certificat TLS expire dans moins de 7 jours (filet de sécurité avant intervention manuelle).",
			CooldownSec: 86400,
			Condition:   Condition{Type: CondCertExpiring, DaysLeft: 7},
			Action:      Action{Type: ActionRunBackup},
		},
		{
			ID:          "cve-high-notify",
			Category:    "security",
			Name:        "Alerter sur CVE élevée",
			Description: "Notifie l'équipe dès qu'un backend expose une CVE avec un score CVSS ≥ 7.0, sans désactiver le proxy.",
			CooldownSec: 3600,
			Condition:   Condition{Type: CondCVECritical, CVSSThreshold: 7.0},
			Action:      Action{Type: ActionNotify, NotifySeverity: "warning", NotifyMessage: "CVE élevée détectée sur un backend"},
		},
		{
			ID:          "ban-spike-notify",
			Category:    "security",
			Name:        "Alerter sur pic de bans massif",
			Description: "Notifie en critique lorsque plus de 50 bans surviennent en 1 heure (attaque distribuée probable).",
			CooldownSec: 1800,
			Condition:   Condition{Type: CondBanSpike, BanCount: 50, BanWindow: "1h"},
			Action:      Action{Type: ActionNotify, NotifySeverity: "critical", NotifyMessage: "Pic de bans massif"},
		},
		{
			ID:          "ban-repeat-permanent",
			Category:    "security",
			Name:        "Bannir définitivement un récidiviste",
			Description: "Bannit sans limite de durée une IP déjà bannie 5 fois ou plus sur 7 jours.",
			CooldownSec: 3600,
			Condition:   Condition{Type: CondBanRepeat, RepeatCount: 5, RepeatWindow: "168h"},
			Action:      Action{Type: ActionBanIP, BanDuration: "", BanReason: "Récidiviste (ban permanent)"},
		},
		{
			ID:          "crowdsec-silent-alert",
			Category:    "reliability",
			Name:        "Alerter si CrowdSec est silencieux",
			Description: "Notifie si CrowdSec n'a montré aucune activité depuis 30 minutes (panne probable de l'agent ou de la LAPI).",
			CooldownSec: 1800,
			Condition:   Condition{Type: CondEngineSilent, EngineType: "crowdsec", SilentMinutes: 30},
			Action:      Action{Type: ActionNotify, NotifySeverity: "critical", NotifyMessage: "CrowdSec silencieux"},
		},
		{
			ID:          "error-rate-notify",
			Category:    "reliability",
			Name:        "Alerter sur taux d'erreur élevé",
			Description: "Notifie quand plus de 30% des requêtes HTTP d'un proxy échouent sur 10 minutes.",
			CooldownSec: 900,
			Condition:   Condition{Type: CondProxyErrorRate, ErrorRateThreshold: 30, ErrorRateWindow: "10m"},
			Action:      Action{Type: ActionNotify, NotifySeverity: "warning", NotifyMessage: "Taux d'erreur HTTP élevé"},
		},
		{
			ID:          "node-offline-long-backup",
			Category:    "reliability",
			Name:        "Sauvegarde sur nœud hors ligne prolongé",
			Description: "Déclenche un snapshot de sauvegarde quand un Core ou un Agent est sans heartbeat depuis plus de 30 minutes.",
			CooldownSec: 3600,
			Condition:   Condition{Type: CondNodeOffline, OfflineMinutes: 30},
			Action:      Action{Type: ActionRunBackup},
		},
		{
			ID:          "cert-expiring-notify",
			Category:    "compliance",
			Name:        "Alerter 30 jours avant expiration de certificat",
			Description: "Notifie l'équipe lorsqu'un certificat TLS expire dans moins de 30 jours, pour laisser le temps de renouveler.",
			CooldownSec: 86400,
			Condition:   Condition{Type: CondCertExpiring, DaysLeft: 30},
			Action:      Action{Type: ActionNotify, NotifySeverity: "warning", NotifyMessage: "Certificat TLS bientôt expiré"},
		},
		{
			ID:          "cert-expiring-critical",
			Category:    "compliance",
			Name:        "Alerte critique certificat sous 3 jours",
			Description: "Notifie en critique quand un certificat TLS expire dans moins de 3 jours.",
			CooldownSec: 43200,
			Condition:   Condition{Type: CondCertExpiring, DaysLeft: 3},
			Action:      Action{Type: ActionNotify, NotifySeverity: "critical", NotifyMessage: "Certificat TLS expire sous 3 jours"},
		},
	}
}

// TemplateByID retourne le template correspondant, ou false s'il est inconnu.
func TemplateByID(id string) (Template, bool) {
	for _, tpl := range Templates() {
		if tpl.ID == id {
			return tpl, true
		}
	}
	return Template{}, false
}
