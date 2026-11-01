// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

// EdgeConfig est la configuration de démarrage de la passerelle (Data Plane).
// Chargée depuis edge.json, surchargeable par variables d'environnement GPX_*.
// Les règles de routage, certificats et snippets arrivent ensuite via l'Administration.
type EdgeConfig struct {
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
		APIHost         string `mapstructure:"api_host"`          // hostname résolvable par l'Admin (ex: goproxify-edge)
		// UnknownHostAction : réponse à une requête dont l'hôte n'a aucune route. « neutral » (défaut) : 404 sans corps ni
		// marque ; « close » : coupe la connexion HTTP/1 sans répondre (en HTTP/2, réponse neutre).
		UnknownHostAction string `mapstructure:"unknown_host_action"`
		// ProxyProtocol : lit l'en-tête PROXY (v1/v2) sur :80 et :443 pour conserver l'IP client
		// derrière un load balancer L4. Seules les sources de TrustedCIDRs sont crues.
		ProxyProtocol struct {
			Enabled      bool     `mapstructure:"enabled"`
			TrustedCIDRs []string `mapstructure:"trusted_cidrs"`
		} `mapstructure:"proxy_protocol"`
	} `mapstructure:"network"`

	Engine struct {
		LogLevel        string `mapstructure:"log_level"`        // info | debug | warn | error
		LogFormat       string `mapstructure:"log_format"`       // json | text
		// LogStoreDir : dossier de la base de logs de la passerelle (accès et système, ADR 0012). Vide : /etc/goproxify/logs.
		LogStoreDir string `mapstructure:"log_store_dir"`
		// LogRetentionDays : conservation des accès HTTP (0 : 365 jours). SystemLogRetentionDays : logs système (0 : 90 jours).
		LogRetentionDays       int `mapstructure:"log_retention_days"`
		SystemLogRetentionDays int `mapstructure:"system_log_retention_days"`
		// LogBufferDays et LogBufferMaxDays : quand l'Admin range et acquitte les lignes (ADR 0018), la base n'est qu'un tampon : une période
		// entièrement acquittée est supprimée LogBufferDays après sa fin (0 : 7 jours), une période que l'Admin n'a pas tout
		// acquittée l'est après LogBufferMaxDays (0 : 30 jours). Sans acquittement de l'Admin, LogRetentionDays reste la règle.
		LogBufferDays    int `mapstructure:"log_buffer_days"`
		LogBufferMaxDays int `mapstructure:"log_buffer_max_days"`
		SystemLogPath   string `mapstructure:"system_log_path"`  // Chemin du log système
		TracingEndpoint string `mapstructure:"tracing_endpoint"` // Endpoint OTLP HTTP (vide = désactivé)
		// TracingSampleRatio : part des nouvelles traces échantillonnées (0 ou >=1 = toutes ; une trace déjà décidée en amont est respectée).
		TracingSampleRatio float64 `mapstructure:"tracing_sample_ratio"`
		// IPAnonymize : tronque le dernier octet IPv4 (x.x.x.0) et les 80 derniers bits IPv6.
		// Recommandé pour la conformité RGPD. Ne désactive pas la protection d'Ephor.
		IPAnonymize bool `mapstructure:"ip_anonymize"`
		// MetricsDisabled coupe les métriques Prometheus par requête (benchmark ; /metrics reste servi, compteurs figés).
		MetricsDisabled bool `mapstructure:"metrics_disabled"`
		// AccessLogDisabled coupe le log d'accès global : plus de Prism/Logs, ni de signal Ephor/proxy issu du log (benchmark).
		AccessLogDisabled bool `mapstructure:"access_log_disabled"`
		// WAFCustomRulesPath : chemin vers un fichier JSON de règles WAF custom.
		// Surveillé toutes les 10 s — hot-reload sans redémarrage.
		// Format : tableau de CustomRule. Exemple : /etc/goproxify/waf-custom-rules.json
		WAFCustomRulesPath string `mapstructure:"waf_custom_rules_path"`
	} `mapstructure:"engine"`

	// GeoIP : base MaxMind locale + téléchargement auto au démarrage si absente.
	GeoIP struct {
		AutoDownload bool   `mapstructure:"auto_download"` // défaut true (SetDefault loader)
		DBPath       string `mapstructure:"db_path"`       // chemin .mmdb sur le volume passerelle
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
func (c *EdgeConfig) MaxHeaderBytes() int {
	kb := c.Timeouts.MaxHeaderKB
	if kb <= 0 {
		kb = DefaultMaxHeaderKB
	}
	return kb << 10
}
