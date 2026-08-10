// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

// AdminConfig est la configuration de démarrage de l'Administration (Control Plane).
// Chargée depuis admin.json, surchargeable par variables d'environnement GPX_*.
type AdminConfig struct {
	App struct {
		Environment        string `mapstructure:"environment"`          // development | production
		LogLevel           string `mapstructure:"log_level"`            // debug | info | warn | error
		AuditRetentionDays int    `mapstructure:"audit_retention_days"` // 0 = 90 jours par défaut
		TracingEndpoint    string `mapstructure:"tracing_endpoint"`     // Endpoint OTLP poussé aux Cores (Core local wins si renseigné)
	} `mapstructure:"app"`

	Server struct {
		ListenAddr string `mapstructure:"listen_addr"`
		APIPort    int    `mapstructure:"api_port"` // REST API + WebSocket
		UIPort     int    `mapstructure:"ui_port"`  // Interface Web
		TLSEnabled bool   `mapstructure:"tls_enabled"`
	} `mapstructure:"server"`

	Storage struct {
		BasePath  string `mapstructure:"base_path"`  // Racine /etc/goproxify en prod
		SQLiteDSN string `mapstructure:"sqlite_dsn"` // Chemin absolu vers goproxify.db
	} `mapstructure:"storage"`

	Security struct {
		JWTSecret string `mapstructure:"jwt_secret"` // Signature des tokens de session admin
		FirstBoot struct {
			DefaultAdminEmail    string `mapstructure:"default_admin_email"`
			DefaultAdminPassword string `mapstructure:"default_admin_password"`
		} `mapstructure:"first_boot"`
	} `mapstructure:"security"`

	HA struct {
		Enabled  bool              `mapstructure:"enabled"`
		NodeID   string            `mapstructure:"node_id"`
		RaftPort int               `mapstructure:"raft_port"` // défaut: 9444
		Peers    map[string]string `mapstructure:"peers"`     // id → "http://host:raft_port"
	} `mapstructure:"ha"`

	// CoreDefaults sont les paramètres runtime poussés aux Cores.
	// Chaque Core peut les surcharger via sa propre config locale.
	CoreDefaults struct {
		LogLevel      string `mapstructure:"log_level"`       // info | debug | warn | error
		LogFormat     string `mapstructure:"log_format"`      // json | text
		AccessLogPath string `mapstructure:"access_log_path"` // chemin du fichier d'access log
	} `mapstructure:"core_defaults"`

	ACME struct {
		Enabled      bool              `mapstructure:"enabled"`
		Email        string            `mapstructure:"email"`
		DirectoryURL string            `mapstructure:"directory_url"` // vide = Let's Encrypt prod
		DNS          struct {
			Type   string            `mapstructure:"type"`
			Params map[string]string `mapstructure:"params"`
		} `mapstructure:"dns"`
	} `mapstructure:"acme"`
}
