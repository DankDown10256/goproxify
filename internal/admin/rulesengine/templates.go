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
