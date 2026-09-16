// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import "time"

// Config pilote le moteur de détection. Poussée par Admin via /internal/v1/threat-config.
type Config struct {
	Enabled bool `json:"enabled"`

	// Mode : "block" (défaut) ou "detect" (log sans bannir).
	Mode string `json:"mode,omitempty"`

	// ScoreThreshold : score cumulatif avant action (0 = premier signal).
	ScoreThreshold int `json:"score_threshold,omitempty"`

	// GlobalRPS : limite de req/s sur l'ensemble du serveur (toutes IPs confondues).
	// Dépasser ce seuil retourne 503 immédiatement, avant toute résolution de route.
	// 0 = désactivé.
	GlobalRPS   float64 `json:"global_rps,omitempty"`
	GlobalBurst int     `json:"global_burst,omitempty"` // 0 = 2×GlobalRPS

	// Détection rate — requêtes par seconde au-delà desquelles l'IP déclenche un signal.
	RateLimit float64 `json:"rate_limit,omitempty"` // req/s, 0 = désactivé
	// Fenêtre glissante pour le rate limit.
	RateWindow Duration `json:"rate_window,omitempty"`
	// RateBanThreshold : nombre de déclenchements du signal "rate" dans RateBanWindow
	// avant ban automatique. 0 ou 1 = ban au premier dépassement.
	RateBanThreshold int      `json:"rate_ban_threshold,omitempty"`
	RateBanWindow    Duration `json:"rate_ban_window,omitempty"` // défaut = RateWindow

	// Erreurs 4xx : nombre d'erreurs dans la fenêtre avant ban.
	ErrorThreshold int      `json:"error_threshold,omitempty"`
	ErrorWindow    Duration `json:"error_window,omitempty"`

	// Durée du ban automatique (0 = permanent).
	BanDuration Duration `json:"ban_duration,omitempty"`

	// Listes actives.
	Lists ListsConfig `json:"lists,omitempty"`

	// CustomLists : entrées inline (sans fichier disque).
	CustomLists CustomListsConfig `json:"custom_lists,omitempty"`

	// Whitelist : IPs/CIDRs, User-Agents et path prefixes exemptés.
	Whitelist Whitelist `json:"whitelist,omitempty"`
}

// CustomListsConfig contient des entrées inline pour chaque liste.
type CustomListsConfig struct {
	IPs   []string `json:"ips,omitempty"`   // IP ou CIDR à bloquer
	UAs   []string `json:"uas,omitempty"`   // sous-chaînes UA à bloquer
	Paths []string `json:"paths,omitempty"` // préfixes de path à bloquer
}

type ListsConfig struct {
	// Fréquence de rafraîchissement des listes (0 = 6h par défaut).
	RefreshInterval Duration `json:"refresh_interval,omitempty"`

	UAEnabled   bool `json:"ua_enabled,omitempty"`
	PathEnabled bool `json:"path_enabled,omitempty"`
	IPEnabled   bool `json:"ip_enabled,omitempty"`

	// Sources optionnelles (vide = sources par défaut).
	UASources  []string `json:"ua_sources,omitempty"`
	PathSources []string `json:"path_sources,omitempty"`
	IPSources  []string `json:"ip_sources,omitempty"`
}

type Whitelist struct {
	IPs   []string `json:"ips,omitempty"`   // IP ou CIDR
	UAs   []string `json:"uas,omitempty"`   // sous-chaînes UA
	Paths []string `json:"paths,omitempty"` // préfixes de path
}

// Duration est un time.Duration sérialisable en JSON (secondes).
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) {
	if d.Duration == 0 {
		return []byte("0"), nil
	}
	return []byte(`"` + d.String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "0" || s == `""` || s == "null" {
		d.Duration = 0
		return nil
	}
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// defaults applique les valeurs par défaut si un champ est nul.
func (c *Config) defaults() {
	if c.RateWindow.Duration == 0 {
		c.RateWindow.Duration = time.Second
	}
	if c.RateBanWindow.Duration == 0 {
		c.RateBanWindow.Duration = c.RateWindow.Duration
	}
	if c.ErrorWindow.Duration == 0 {
		c.ErrorWindow.Duration = 10 * time.Second
	}
	if c.BanDuration.Duration == 0 {
		c.BanDuration.Duration = 24 * time.Hour
	}
	if c.Lists.RefreshInterval.Duration == 0 {
		c.Lists.RefreshInterval.Duration = 6 * time.Hour
	}
}
