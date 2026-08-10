// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Load charge la configuration d'un composant depuis un fichier JSON,
// puis surcharge les valeurs avec les variables d'environnement préfixées GPX_.
//
// Priorité (de la plus forte à la plus faible) :
//  1. Variables d'environnement  GPX_<SECTION>_<KEY>=valeur
//  2. Fichier JSON               (chemin passé en argument)
//  3. Valeurs par défaut         (définies dans cette fonction)
//
// Exemples de surcharge par variable d'environnement :
//
//	GPX_APP_ENVIRONMENT=production
//	GPX_SERVER_API_PORT=9443
//	GPX_SECURITY_JWT_SECRET=mon_secret_prod
//	GPX_CONTROL_PLANE_AUTH_TOKEN=gpx_core_abc123
func Load[T AdminConfig | CoreConfig | AgentConfig | LandingConfig](configPath string) (*T, error) {
	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("json")

	v.SetEnvPrefix("GPX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Viper ne remonte pas AutomaticEnv pour les clés imbriquées absentes du JSON.
	// BindEnv force la liaison explicite pour chaque clé susceptible d'être surchargée.
	_ = v.BindEnv("network.api_host", "GPX_NETWORK_API_HOST")
	_ = v.BindEnv("identity.node_name", "GPX_IDENTITY_NODE_NAME", "GPX_IDENTITY_CORE_NODE_NAME")
	_ = v.BindEnv("control_plane.auth_token", "GPX_CONTROL_PLANE_AUTH_TOKEN")
	_ = v.BindEnv("engine.log_level", "GPX_ENGINE_LOG_LEVEL")
	_ = v.BindEnv("engine.log_format", "GPX_ENGINE_LOG_FORMAT")
	_ = v.BindEnv("engine.tracing_endpoint", "GPX_ENGINE_TRACING_ENDPOINT")
	_ = v.BindEnv("geoip.auto_download", "GPX_GEOIP_AUTO_DOWNLOAD")
	_ = v.BindEnv("geoip.db_path", "GPX_GEOIP_DB_PATH")
	_ = v.BindEnv("geoip.db_url", "GPX_GEOIP_DB_URL")
	_ = v.BindEnv("network.http_port", "GPX_NETWORK_HTTP_PORT")
	_ = v.BindEnv("network.https_port", "GPX_NETWORK_HTTPS_PORT")
	_ = v.BindEnv("network.internal_api_port", "GPX_NETWORK_INTERNAL_API_PORT")
	_ = v.BindEnv("acme.enabled", "GPX_ACME_ENABLED")
	_ = v.BindEnv("acme.email", "GPX_ACME_EMAIL")
	_ = v.BindEnv("acme.dns.type", "GPX_ACME_DNS_TYPE")
	_ = v.BindEnv("acme.directory_url", "GPX_ACME_DIRECTORY_URL")
	_ = v.BindEnv("cluster.enabled", "GPX_CLUSTER_ENABLED")
	_ = v.BindEnv("cluster.group_name", "GPX_CLUSTER_GROUP_NAME", "GPX_CLUSTER_GROUP")
	_ = v.BindEnv("cluster.node_id", "GPX_CLUSTER_NODE_ID")
	_ = v.BindEnv("cluster.raft_port", "GPX_CLUSTER_RAFT_PORT")

	v.SetDefault("geoip.auto_download", true)
	v.SetDefault("geoip.db_path", "/etc/goproxify/geoip/GeoLite2-Country.mmdb")
	v.SetDefault("geoip.db_url", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("lecture config %q : %w", configPath, err)
	}

	var cfg T
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q : %w", configPath, err)
	}

	return &cfg, nil
}

// LoadAdmin charge admin.json → AdminConfig.
func LoadAdmin(path string) (*AdminConfig, error) {
	return Load[AdminConfig](path)
}

// LoadCore charge core.json → CoreConfig.
func LoadCore(path string) (*CoreConfig, error) {
	cfg, err := Load[CoreConfig](path)
	if err != nil {
		return nil, err
	}
	applyClusterPeersEnv(cfg)
	return cfg, nil
}

// applyClusterPeersEnv parse GPX_CLUSTER_PEERS si la map Peers est vide.
// Formats acceptés (séparés par virgule) :
//   - id=http://host:8002
//   - id:8002  → http://id:8002
//   - host:8002 → clé = host
func applyClusterPeersEnv(cfg *CoreConfig) {
	if cfg == nil || len(cfg.Cluster.Peers) > 0 {
		return
	}
	raw := strings.TrimSpace(os.Getenv("GPX_CLUSTER_PEERS"))
	if raw == "" {
		return
	}
	peers := parseClusterPeersCSV(raw)
	if len(peers) > 0 {
		cfg.Cluster.Peers = peers
	}
}

func parseClusterPeersCSV(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, url := "", ""
		if i := strings.IndexByte(part, '='); i > 0 {
			id = strings.TrimSpace(part[:i])
			url = strings.TrimSpace(part[i+1:])
		} else if i := strings.LastIndexByte(part, ':'); i > 0 {
			host := strings.TrimSpace(part[:i])
			port := strings.TrimSpace(part[i+1:])
			host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
			id = host
			url = "http://" + host + ":" + port
		} else {
			continue
		}
		if id == "" || url == "" {
			continue
		}
		if !strings.Contains(url, "://") {
			url = "http://" + url
		}
		out[id] = url
	}
	return out
}

// LoadAgent charge agent.json → AgentConfig.
func LoadAgent(path string) (*AgentConfig, error) {
	return Load[AgentConfig](path)
}

// LoadLanding charge landing/config.json → LandingConfig.
func LoadLanding(path string) (*LandingConfig, error) {
	return Load[LandingConfig](path)
}
