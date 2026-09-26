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
//	GPX_CONTROL_PLANE_AUTH_TOKEN=gpx_edge_abc123
// Load charge la configuration depuis un fichier JSON.
//
// Comportement selon l'état du fichier :
//   - Fichier absent     → erreur (appeler Bootstrap*() avant Load)
//   - Fichier existant   → JSON seul fait foi ; les variables d'environnement
//     GPX_* ne surchargent PAS les valeurs déjà présentes dans le JSON.
//     Seules les clés absentes du JSON peuvent être alimentées par env var.
//     Exception : GPX_PAIRING_SECRET est toujours lu via os.Getenv() directement
//     dans le code, jamais via Viper, car il est partagé entre services.
//
// Pour les utilisateurs avancés qui souhaitent surcharger une valeur du JSON
// sans éditer le fichier : supprimer la clé du JSON, la valeur sera alors
// lue depuis la variable d'environnement correspondante.
func Load[T AdminConfig | EdgeConfig | AgentConfig | LandingConfig](configPath string) (*T, error) {
	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("json")

	v.SetDefault("geoip.auto_download", true)
	v.SetDefault("geoip.db_path", "/etc/goproxify/geoip/GeoLite2-Country.mmdb")
	v.SetDefault("geoip.db_url", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb")
	v.SetDefault("timeouts.read_header_seconds", 10)
	v.SetDefault("timeouts.read_seconds", 30)
	v.SetDefault("timeouts.write_seconds", 60)
	v.SetDefault("timeouts.idle_seconds", 120)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("lecture config %q : %w", configPath, err)
	}
	migrateLegacyKeys(v)

	// Les env vars ne surchargent que les clés absentes du JSON (pas de AutomaticEnv global).
	// On bind uniquement les clés qui peuvent légitimement manquer dans le JSON
	// pour permettre à l'utilisateur avancé de les passer en env var.
	// cluster.peers est intentionnellement omis ici : GPX_CLUSTER_PEERS est une chaîne CSV
	// incompatible avec map[string]string pour viper. Géré par applyClusterPeersEnv après Unmarshal.
	// GPX_IDENTITY_EDGE_NODE_NAME pour compatibilité avec les variables de bootstrap passerelle.
	if !v.IsSet("identity.node_name") {
		_ = v.BindEnv("identity.node_name", "GPX_IDENTITY_EDGE_NODE_NAME", "GPX_IDENTITY_NODE_NAME")
	}
	bindIfMissing(v, "cluster.enabled")
	if !v.IsSet("cluster.group_name") {
		_ = v.BindEnv("cluster.group_name", "GPX_CLUSTER_GROUP_NAME", "GPX_CLUSTER_GROUP")
	}
	bindIfMissing(v, "cluster.node_id")
	bindIfMissing(v, "cluster.raft_port")

	var cfg T
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q : %w", configPath, err)
	}

	return &cfg, nil
}

// bindIfMissing lie une variable d'env uniquement si la clé est absente du JSON chargé.
func bindIfMissing(v *viper.Viper, key string) {
	if !v.IsSet(key) {
		envKey := "GPX_" + strings.ToUpper(strings.NewReplacer(".", "_").Replace(key))
		_ = v.BindEnv(key, envKey)
	}
}

// LoadAdmin charge admin.json → AdminConfig.
func LoadAdmin(path string) (*AdminConfig, error) {
	return Load[AdminConfig](path)
}

// LoadEdge charge edge.json → EdgeConfig.
func LoadEdge(path string) (*EdgeConfig, error) {
	cfg, err := Load[EdgeConfig](path)
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
func applyClusterPeersEnv(cfg *EdgeConfig) {
	if cfg == nil || len(cfg.Cluster.Peers) > 0 {
		return
	}
	raw := unquote(strings.TrimSpace(os.Getenv("GPX_CLUSTER_PEERS")))
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
		part = unquote(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		id, url := "", ""
		if i := strings.IndexByte(part, '='); i > 0 {
			id = unquote(strings.TrimSpace(part[:i]))
			url = unquote(strings.TrimSpace(part[i+1:]))
		} else if i := strings.LastIndexByte(part, ':'); i > 0 {
			host := unquote(strings.TrimSpace(part[:i]))
			port := unquote(strings.TrimSpace(part[i+1:]))
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

// unquote retire une paire de guillemets (simples ou doubles) englobant s.
// En syntaxe docker-compose "environment:", des guillemets écrits autour
// d'une valeur (ex: GPX_CLUSTER_PEERS="id=http://host:8002") sont transmis
// tels quels au process, sans être retirés par un shell — d'où ce nettoyage
// défensif avant parsing.
func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// LoadAgent charge agent.json → AgentConfig.
func LoadAgent(path string) (*AgentConfig, error) {
	cfg, err := Load[AgentConfig](path)
	if err != nil {
		return nil, err
	}
	applyAgentEnvOverrides(cfg)
	return cfg, nil
}

// applyAgentEnvOverrides applique uniquement les variables d'infra bootstrap-critiques
// qui doivent pouvoir être modifiées via docker-compose sans supprimer agent.json du volume.
// Les configs fonctionnelles (Docker, Portainer…) sont écrites dans agent.json au premier
// démarrage par BootstrapAgent() et gérées ensuite via l'UI — les env vars ne les écrasent plus.
func applyAgentEnvOverrides(cfg *AgentConfig) {
	if cfg == nil {
		return
	}
	if v := os.Getenv("GPX_CONTROL_PLANE_EDGE_ENDPOINT"); v != "" {
		cfg.ControlPlane.EdgeEndpoint = v
	}
	if v := os.Getenv("GPX_CONTROL_PLANE_JOIN_TOKEN"); v != "" {
		cfg.ControlPlane.JoinToken = v
	}
	if v := os.Getenv("GPX_IDENTITY_AGENT_NODE_NAME"); v != "" {
		cfg.Identity.NodeName = v
	}
	if v := os.Getenv("GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME"); v != "" {
		cfg.NetworkManagement.EdgeContainerName = v
	}
}

// LoadLanding charge landing/config.json → LandingConfig.
func LoadLanding(path string) (*LandingConfig, error) {
	return Load[LandingConfig](path)
}
