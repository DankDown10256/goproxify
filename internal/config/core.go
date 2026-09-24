// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

// CoreConfig est la configuration de démarrage du Core (Data Plane).
// Chargée depuis core.json, surchargeable par variables d'environnement GPX_*.
// Les règles de routage, certificats et snippets arrivent ensuite via l'Administration.
type CoreConfig struct {
	Identity struct {
		NodeName string `mapstructure:"node_name"` // Identifiant unique du node dans le cluster
		Role     string `mapstructure:"role"`      // data-plane
		TokenID  string `mapstructure:"token_id"`  // UUID stable généré au premier boot — identifiant persistant
	} `mapstructure:"identity"`

	ControlPlane struct {
		AuthToken string `mapstructure:"auth_token"` // Token de bootstrap pour l'API interne (optionnel)
	} `mapstructure:"control_plane"`

	Network struct {
		HTTPPort        int    `mapstructure:"http_port"`         // :80  — trafic proxy public
		HTTPSPort       int    `mapstructure:"https_port"`        // :443 — trafic proxy public (TLS)
		QUICPort        int    `mapstructure:"quic_port"`         // :443 UDP — HTTP/3
		InternalAPIPort int    `mapstructure:"internal_api_port"` // :8000 — reçoit les pushes de l'Admin
		BindAddress     string `mapstructure:"bind_address"`      // 0.0.0.0 par défaut
		APIHost         string `mapstructure:"api_host"`          // hostname résolvable par l'Admin (ex: goproxify-core)
	} `mapstructure:"network"`

	Cluster struct {
		Enabled   bool              `mapstructure:"enabled"`
		GroupName string            `mapstructure:"group_name"`
		NodeID    string            `mapstructure:"node_id"`
		RaftPort  int               `mapstructure:"raft_port"` // défaut: 8002
		Peers     map[string]string `mapstructure:"peers"`     // id → "http://host:raft_port"
	} `mapstructure:"cluster"`

	Engine struct {
		LogLevel        string `mapstructure:"log_level"`        // info | debug | warn | error
		LogFormat       string `mapstructure:"log_format"`       // json | text
		AccessLogPath   string `mapstructure:"access_log_path"`  // Chemin du log d'accès HTTP
		SystemLogPath   string `mapstructure:"system_log_path"`  // Chemin du log système
		TracingEndpoint string `mapstructure:"tracing_endpoint"` // Endpoint OTLP HTTP (vide = désactivé)
		// IPAnonymize : tronque le dernier octet IPv4 (x.x.x.0) et les 80 derniers bits IPv6.
		// Recommandé pour la conformité RGPD. Ne désactive pas la protection Fail2Ban/Sentinel.
		IPAnonymize bool `mapstructure:"ip_anonymize"`
		// WAFCustomRulesPath : chemin vers un fichier JSON de règles WAF custom.
		// Surveillé toutes les 10 s — hot-reload sans redémarrage.
		// Format : tableau de CustomRule. Exemple : /etc/goproxify/waf-custom-rules.json
		WAFCustomRulesPath string `mapstructure:"waf_custom_rules_path"`
	} `mapstructure:"engine"`

	// GeoIP : base MaxMind locale + téléchargement auto au démarrage si absente.
	GeoIP struct {
		AutoDownload bool   `mapstructure:"auto_download"` // défaut true (SetDefault loader)
		DBPath       string `mapstructure:"db_path"`       // chemin .mmdb sur le volume Core
		DBURL        string `mapstructure:"db_url"`        // URL de téléchargement si absente
	} `mapstructure:"geoip"`

	// Timeouts HTTP — protection contre Slowloris et clients lents.
	// Valeurs 0 = désactivé (déconseillé en production).
	Timeouts struct {
		ReadHeaderSeconds int `mapstructure:"read_header_seconds"` // délai max pour recevoir les headers (défaut 10s)
		ReadSeconds       int `mapstructure:"read_seconds"`        // délai max pour lire la requête entière (défaut 30s)
		WriteSeconds      int `mapstructure:"write_seconds"`       // délai max pour écrire la réponse (défaut 60s)
		IdleSeconds       int `mapstructure:"idle_seconds"`        // keep-alive idle max (défaut 120s)
		MaxHeaderKB       int `mapstructure:"max_header_kb"`       // taille max des en-têtes de requête en Ko (défaut 32)
	} `mapstructure:"timeouts"`
}

// DefaultMaxHeaderKB borne les en-têtes de requête (nginx : 4 × 8 Ko ; Go : 1 Mo si non borné).
const DefaultMaxHeaderKB = 32

// MaxHeaderBytes renvoie la taille max des en-têtes de requête en octets (défaut 32 Ko).
func (c *CoreConfig) MaxHeaderBytes() int {
	kb := c.Timeouts.MaxHeaderKB
	if kb <= 0 {
		kb = DefaultMaxHeaderKB
	}
	return kb << 10
}
