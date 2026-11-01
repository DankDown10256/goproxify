// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import "time"

const (
	defaultScoreBanThreshold = 10.0
	defaultScoreHalfLife     = 10 * time.Minute

	defaultEscalationFactor = 2.0
	defaultEscalationWindow = 7 * 24 * time.Hour
	maxEscalationWindow     = 30 * 24 * time.Hour // rétention de l'historique des bans (bansdb)
	defaultEscalationMax    = 30 * 24 * time.Hour
)

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

	// IPScore : score cumulé par IP avec décroissance. Désactivé par défaut (ban au premier signal).
	IPScore IPScoreConfig `json:"ip_score,omitempty"`

	// Escalation : bans graduels, la durée croît avec le nombre de bans Ephor précédents de l'IP.
	Escalation EscalationConfig `json:"escalation,omitempty"`

	// Durée du ban automatique (0 = permanent).
	BanDuration Duration `json:"ban_duration,omitempty"`

	// Listes actives.
	Lists ListsConfig `json:"lists,omitempty"`

	// CustomLists : entrées inline (sans fichier disque).
	CustomLists CustomListsConfig `json:"custom_lists,omitempty"`

	// Whitelist : IPs/CIDRs, User-Agents et path prefixes exemptés.
	Whitelist Whitelist `json:"whitelist,omitempty"`

	// Tarpit : ralentit la réponse aux IP bloquées ou bannies par Ephor (désactivé par défaut).
	Tarpit TarpitConfig `json:"tarpit,omitempty"`

	// Behavior : la note commune par IP et les signaux de comportement (ADR 0011).
	Behavior BehaviorConfig `json:"behavior,omitempty"`

	// Challenge : le défi à preuve de travail imposé avant le ban (ADR 0020, étape 1.b). Désactivé par défaut.
	Challenge ChallengeConfig `json:"challenge,omitempty"`

	// Decoys : des chemins-leurres que l'application n'utilise jamais (ADR 0020, étape 2.a). Désactivé par défaut.
	Decoys DecoyConfig `json:"decoys,omitempty"`

	// Thresholds : les Seuils, règles « N événements en T, action » (ADR 0020, étape 2.c). Désactivés par défaut.
	Thresholds ThresholdsConfig `json:"thresholds,omitempty"`

	// Seasonal : la référence saisonnière du trafic de chaque route (ADR 0020, étape 3). Désactivée par défaut.
	Seasonal SeasonalConfig `json:"seasonal,omitempty"`

	// Enumeration : une IP qui parcourt de nombreuses valeurs d'un même gabarit de chemin (ADR 0020, étape 4.b). Désactivée par défaut.
	Enumeration EnumerationConfig `json:"enumeration,omitempty"`

	// TLSReputation : la réputation apprise des empreintes TLS, qui propose sans jamais bloquer (ADR 0020, étape 4.c). Désactivée par défaut.
	TLSReputation TLSReputationConfig `json:"tls_reputation,omitempty"`

	// UnknownHost : des points modérés pour un accès à un nom sans route ou sans certificat (ADR 0020, étape 2.b). Désactivé par défaut.
	UnknownHost UnknownHostConfig `json:"unknown_host,omitempty"`
}

// IPScoreConfig active un score par IP qui s'additionne d'une requête à l'autre et décroît avec le
// temps. Une IP n'est bannie que lorsque son score dépasse BanThreshold : quelques signaux isolés
// (un 404 sur un chemin sensible, un User-Agent suspect) s'estompent, une série rapprochée mène au ban.
// Les IP des listes de menaces (signal « ip ») restent bannies immédiatement. Quand le score est
// actif, le ban sur le signal « rate » passe lui aussi par le score (rate_ban_threshold est ignoré).
type IPScoreConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	// BanThreshold : score cumulé qui déclenche le ban (défaut 10 ; un chemin sensible pèse 2, un
	// User-Agent suspect 3, un dépassement de débit 4).
	BanThreshold float64 `json:"ban_threshold,omitempty"`
	// HalfLife : durée au bout de laquelle le score est divisé par deux (défaut 10 min).
	HalfLife Duration `json:"half_life,omitempty"`
	// Errors : pondère les erreurs 4xx et les verse au score (voir ErrorScoreConfig).
	Errors ErrorScoreConfig `json:"errors,omitempty"`
}

// ErrorScoreConfig verse les erreurs 4xx au score cumulé de l'IP, pondérées par code et par route,
// au lieu du simple compteur error_threshold / error_window (ignorés quand c'est actif). Nécessite
// ip_score.enabled. Un 404 isolé pèse peu, une rafale de 400 ou 405 sur un point d'entrée sensible
// mène au ban. 401, 403 et 429 ne comptent pas (échecs d'authentification, refus déjà prononcés par un
// ban, le WAF ou une limite : d'autres moteurs en décident).
type ErrorScoreConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	// Weights : points par code HTTP (clé « 404 »), qui complètent ou remplacent les valeurs par défaut.
	// 0 neutralise un code.
	Weights map[string]float64 `json:"weights,omitempty"`
	// DefaultWeight : points d'un 4xx absent de Weights et des valeurs par défaut (défaut 0,5).
	DefaultWeight float64 `json:"default_weight,omitempty"`
	// Routes : multiplicateur selon le préfixe du chemin (le préfixe le plus long l'emporte). 0 ignore
	// les erreurs de cette route, 3 les triple.
	Routes []RouteWeight `json:"routes,omitempty"`
}

// RouteWeight applique un multiplicateur aux erreurs d'un préfixe de chemin.
type RouteWeight struct {
	Prefix string  `json:"prefix"`
	Factor float64 `json:"factor"`
}

// EscalationConfig rend les bans graduels : une IP déjà bannie par Ephor récemment l'est plus
// longtemps. Durée = ban_duration × Factor^n, n étant le nombre de bans Ephor de cette IP dans
// la fenêtre, plafonnée à MaxDuration. Un déban manuel remet le compteur à zéro. L'historique des
// bans est conservé 30 jours sur la passerelle : la fenêtre est limitée à cette durée.
type EscalationConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	// Factor : multiplicateur par récidive (défaut 2 : 24 h, 48 h, 96 h…).
	Factor float64 `json:"factor,omitempty"`
	// Window : période pendant laquelle les bans précédents comptent (défaut 7 j, max 30 j).
	Window Duration `json:"window,omitempty"`
	// MaxDuration : plafond de la durée d'un ban (défaut 30 j).
	MaxDuration Duration `json:"max_duration,omitempty"`
}

// CustomListsConfig contient des entrées inline pour chaque liste.
type CustomListsConfig struct {
	IPs   []string `json:"ips,omitempty"`   // IP ou CIDR à bloquer
	UAs   []string `json:"uas,omitempty"`   // sous-chaînes UA à bloquer
	Paths []string `json:"paths,omitempty"` // préfixes de path à bloquer
	// TLSFingerprints : signatures JA3 (MD5, 32 caractères hexadécimaux) ou JA4 (ex. t13d1516h2_8daaf6152771_02713d6af862)
	// des clients à bannir. Ne s'applique qu'aux connexions TLS reçues par la passerelle (pas au HTTP clair ni à HTTP/3).
	TLSFingerprints []string `json:"tls_fingerprints,omitempty"`
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
	if c.Escalation.Factor <= 1 {
		c.Escalation.Factor = defaultEscalationFactor
	}
	if c.Escalation.Window.Duration <= 0 {
		c.Escalation.Window.Duration = defaultEscalationWindow
	}
	if c.Escalation.Window.Duration > maxEscalationWindow {
		c.Escalation.Window.Duration = maxEscalationWindow
	}
	if c.Escalation.MaxDuration.Duration <= 0 {
		c.Escalation.MaxDuration.Duration = defaultEscalationMax
	}
	if c.IPScore.BanThreshold <= 0 {
		c.IPScore.BanThreshold = defaultScoreBanThreshold
	}
	if c.IPScore.HalfLife.Duration <= 0 {
		c.IPScore.HalfLife.Duration = defaultScoreHalfLife
	}
	if c.Lists.RefreshInterval.Duration == 0 {
		c.Lists.RefreshInterval.Duration = 6 * time.Hour
	}
	if c.Challenge.Threshold <= 0 {
		c.Challenge.Threshold = c.IPScore.BanThreshold / 2
	}
}
