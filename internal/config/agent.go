// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

// AgentConfig est la configuration de démarrage de l'Agent (Discovery & Télémétrie).
// Chargée depuis agent.json, surchargeable par variables d'environnement GPX_*.
type AgentConfig struct {
	Identity struct {
		NodeName string `mapstructure:"node_name"`
	} `mapstructure:"identity"`

	ControlPlane struct {
		AdminEndpoint string `mapstructure:"admin_endpoint"` // URL de l'Admin (pour l'appairage initial, optionnel)
		CoreEndpoint  string `mapstructure:"core_endpoint"`  // URL du Core local (ex: http://goproxify-core:8000)
		AuthToken     string `mapstructure:"auth_token"`     // Token d'appairage gpx_agent_* (compatibilité HTTP)
		JoinToken     string `mapstructure:"join_token"`     // JOIN_TOKEN (gpx_join_*) pour le premier démarrage WS
	} `mapstructure:"control_plane"`

	Docker struct {
		SocketPath     string `mapstructure:"socket_path"`      // /var/run/docker.sock
		PollIntervalMs int    `mapstructure:"poll_interval_ms"` // Intervalle de scrute des événements
		LabelPrefix    string `mapstructure:"label_prefix"`     // "goproxify."
		Runtime        string `mapstructure:"runtime"`          // auto | docker | podman
		// Authentification pour les registries privés (pull d'images)
		RegistryUsername string `mapstructure:"registry_username"`
		RegistryPassword string `mapstructure:"registry_password"`
		RegistryServer   string `mapstructure:"registry_server"` // ex: ghcr.io
	} `mapstructure:"docker"`

	Kubernetes struct {
		Enabled     bool   `mapstructure:"enabled"`
		APIServer   string `mapstructure:"api_server"`   // "" = in-cluster autodetect
		Token       string `mapstructure:"token"`        // "" = service account
		CACert      string `mapstructure:"ca_cert"`      // PEM ou chemin fichier
		Namespace   string `mapstructure:"namespace"`    // "" = tous
		LabelPrefix string `mapstructure:"label_prefix"` // "goproxify." (hérité si vide)
	} `mapstructure:"kubernetes"`

	Telemetry struct {
		Enabled          bool `mapstructure:"enabled"`
		MetricsPort      int  `mapstructure:"metrics_port"`      // :9191 — export Prometheus
		ScrapeIntervalMs int  `mapstructure:"scrape_interval_ms"` // Intervalle de lecture /proc
	} `mapstructure:"telemetry"`

	NetworkManagement struct {
		ManageWireguard     bool   `mapstructure:"manage_wireguard"`
		DockerNetworkDriver string `mapstructure:"docker_network_driver"` // bridge | overlay
		// Nom du conteneur Core à connecter aux réseaux Docker des apps découvertes
		CoreContainerName string `mapstructure:"core_container_name"`
	} `mapstructure:"network_management"`

	LogForwarding struct {
		Enabled     bool `mapstructure:"enabled"`
		BufferLines int  `mapstructure:"buffer_lines"`
	} `mapstructure:"log_forwarding"`

	HealthEscalation struct {
		Enabled           bool `mapstructure:"enabled"`
		RestartMaxRetries int  `mapstructure:"restart_max_retries"` // avant recreate
		RecreateTimeoutS  int  `mapstructure:"recreate_timeout_s"`  // délai avant rollback
		CheckIntervalS    int  `mapstructure:"check_interval_s"`
	} `mapstructure:"health_escalation"`

	InternalAPI struct {
		// Port d'écoute de l'API interne de l'Agent (reçoit les commandes de l'Admin)
		Port int `mapstructure:"port"` // défaut: 8001
	} `mapstructure:"internal_api"`

	AutoScale struct {
		Enabled        bool    `mapstructure:"enabled"`
		CheckIntervalS int     `mapstructure:"check_interval_s"` // défaut: 30
		CooldownS      int     `mapstructure:"cooldown_s"`       // anti-flapping, défaut: 120
		CPUScaleUpPct  float64 `mapstructure:"cpu_scale_up_pct"` // seuil montée, défaut: 80
		CPUScaleDownPct float64 `mapstructure:"cpu_scale_down_pct"` // seuil descente, défaut: 20
	} `mapstructure:"autoscale"`

	DigestWatch struct {
		Enabled        bool `mapstructure:"enabled"`
		CheckIntervalS int  `mapstructure:"check_interval_s"` // défaut: 3600 (1h)
	} `mapstructure:"digest_watch"`

	// Portainer permet de découvrir des conteneurs sur plusieurs hôtes Docker
	// via l'API Portainer, sans installer l'Agent sur chaque hôte.
	Portainer struct {
		Enabled        bool   `mapstructure:"enabled"`
		URL            string `mapstructure:"url"`              // ex: https://portainer:9443
		APIKey         string `mapstructure:"api_key"`          // Settings → API Keys
		PollIntervalS  int    `mapstructure:"poll_interval_s"`  // défaut: 30
	} `mapstructure:"portainer"`
}
