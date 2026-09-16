// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package config — bootstrap génère les fichiers config.json au premier démarrage
// si ils sont absents. Les variables d'environnement servent d'hints d'initialisation ;
// une fois le fichier créé, les env vars ne surchargent plus que les clés explicitement
// passées (comportement Viper standard). Seul GPX_PAIRING_SECRET reste obligatoire
// et n'est jamais écrit dans le JSON (partagé entre services).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// BootstrapAdmin génère admin.json s'il est absent.
// GPX_PAIRING_SECRET est obligatoire mais n'est pas écrit dans le JSON.
// GPX_SECURITY_JWT_SECRET est auto-généré s'il est absent.
func BootstrapAdmin(path string) error {
	if fileExists(path) {
		return nil
	}
	jwtSecret := os.Getenv("GPX_SECURITY_JWT_SECRET")
	if jwtSecret == "" {
		var err error
		jwtSecret, err = randomHex(32)
		if err != nil {
			return fmt.Errorf("bootstrap admin: génération JWT secret: %w", err)
		}
		slog.Info("bootstrap: GPX_SECURITY_JWT_SECRET auto-généré (persisté dans admin.json)")
	}

	basePath := envOr("GPX_STORAGE_BASE_PATH", "/etc/goproxify")
	apiPort := envIntOr("GPX_SERVER_API_PORT", 9443)
	nodeName := envOr("GPX_IDENTITY_CORE_NODE_NAME", "goproxify-core")
	logLevel := envOr("GPX_ENGINE_LOG_LEVEL", "info")
	adminEmail := envOr("GPX_FIRST_ADMIN_EMAIL", "")
	adminPassword := envOr("GPX_FIRST_ADMIN_PASSWORD", "")

	cfg := map[string]any{
		"app": map[string]any{
			"environment": envOr("GPX_APP_ENVIRONMENT", "production"),
			"log_level":   logLevel,
		},
		"server": map[string]any{
			"api_port":    apiPort,
			"listen_addr": "0.0.0.0",
		},
		"storage": map[string]any{
			"base_path":  basePath,
			"sqlite_dsn": filepath.Join(basePath, "admin.db"),
		},
		"security": map[string]any{
			"jwt_secret": jwtSecret,
			"first_boot": map[string]any{
				"default_admin_email":    adminEmail,
				"default_admin_password": adminPassword,
			},
		},
		"identity": map[string]any{
			"core_node_name": nodeName,
		},
	}

	if err := writeJSON(path, cfg); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	slog.Info("bootstrap: admin.json créé", "path", path)
	return nil
}

// BootstrapCore génère core.json s'il est absent.
func BootstrapCore(path string) error {
	if fileExists(path) {
		return nil
	}

	nodeName := envOr("GPX_IDENTITY_CORE_NODE_NAME", "goproxify-core")
	basePath := envOr("GPX_STORAGE_BASE_PATH", "/etc/goproxify")
	logLevel := envOr("GPX_ENGINE_LOG_LEVEL", "info")

	tokenID, err := randomHex(16) // 16 bytes = 32 hex chars, UUID-like
	if err != nil {
		return fmt.Errorf("bootstrap core: génération token_id: %w", err)
	}

	cfg := map[string]any{
		"identity": map[string]any{
			"node_name": nodeName,
			"role":      "data-plane",
			"token_id":  tokenID,
		},
		"network": map[string]any{
			"http_port":         envIntOr("GPX_NETWORK_HTTP_PORT", 80),
			"https_port":        envIntOr("GPX_NETWORK_HTTPS_PORT", 443),
			"internal_api_port": envIntOr("GPX_NETWORK_INTERNAL_API_PORT", 8000),
			"bind_address":      "0.0.0.0",
			"api_host":          envOr("GPX_NETWORK_API_HOST", nodeName),
		},
		"engine": map[string]any{
			"log_level":       logLevel,
			"log_format":      "json",
			"access_log_path": filepath.Join(basePath, "logs", "access.log"),
		},
		"geoip": map[string]any{
			"auto_download": true,
			"db_path":       filepath.Join(basePath, "geoip", "GeoLite2-Country.mmdb"),
		},
		"cluster": map[string]any{
			"enabled": envBoolOr("GPX_CLUSTER_ENABLED", false),
		},
	}

	if err := writeJSON(path, cfg); err != nil {
		return fmt.Errorf("bootstrap core: %w", err)
	}
	slog.Info("bootstrap: core.json créé", "path", path)
	return nil
}

// BootstrapAgent génère agent.json s'il est absent.
// Si le fichier existe mais manque les sections docker/portainer, elles sont
// ajoutées depuis les env vars (migration transparente lors de la mise à jour).
// GPX_CONTROL_PLANE_CORE_ENDPOINT est requis si l'agent est sur un hôte distant.
func BootstrapAgent(path string) error {
	dockerEnabled := true
	if v := os.Getenv("GPX_DOCKER_ENABLED"); v == "false" || v == "0" {
		dockerEnabled = false
	}
	dockerRuntime := envOr("GPX_DOCKER_RUNTIME", "auto")
	if !dockerEnabled {
		dockerRuntime = ""
	}
	portainerEnabled := os.Getenv("GPX_PORTAINER_ENABLED") == "true" || os.Getenv("GPX_PORTAINER_ENABLED") == "1"
	portainerURL := os.Getenv("GPX_PORTAINER_URL")
	portainerAPIKey := os.Getenv("GPX_PORTAINER_API_KEY")
	portainerPollS := envIntOr("GPX_PORTAINER_POLL_INTERVAL_S", 30)

	if fileExists(path) {
		// Migration : ajoute docker/portainer si absents (agents mis à jour depuis une ancienne version).
		return migrateAgentDockerConfig(path, dockerEnabled, dockerRuntime, portainerEnabled, portainerURL, portainerAPIKey, portainerPollS)
	}

	coreEndpoint := envOr("GPX_CONTROL_PLANE_CORE_ENDPOINT", "http://goproxify-core:8000")
	adminEndpoint := envOr("GPX_CONTROL_PLANE_ADMIN_ENDPOINT", "")
	joinToken := envOr("GPX_CONTROL_PLANE_JOIN_TOKEN", "")
	nodeName := envOr("GPX_IDENTITY_AGENT_NODE_NAME", "")
	logLevel := envOr("GPX_ENGINE_LOG_LEVEL", "info")

	cfg := map[string]any{
		"identity": map[string]any{
			"node_name": nodeName,
		},
		"control_plane": map[string]any{
			"core_endpoint":  coreEndpoint,
			"admin_endpoint": adminEndpoint,
			"join_token":     joinToken,
		},
		"docker": map[string]any{
			"enabled":      dockerEnabled,
			"socket_path":  envOr("GPX_DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
			"label_prefix": "goproxify.",
			"runtime":      dockerRuntime,
		},
		"portainer": map[string]any{
			"enabled":         portainerEnabled,
			"url":             portainerURL,
			"api_key":         portainerAPIKey,
			"poll_interval_s": portainerPollS,
			"skip_endpoints":  []string{},
		},
		"engine": map[string]any{
			"log_level": logLevel,
		},
	}

	if err := writeJSON(path, cfg); err != nil {
		return fmt.Errorf("bootstrap agent: %w", err)
	}
	slog.Info("bootstrap: agent.json créé", "path", path)
	return nil
}

// migrateAgentDockerConfig ajoute les sections docker/portainer dans agent.json
// si elles sont absentes. Opération idempotente et atomique.
func migrateAgentDockerConfig(path string, dockerEnabled bool, dockerRuntime string, portainerEnabled bool, portainerURL, portainerAPIKey string, portainerPollS int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // non bloquant
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	changed := false
	if _, ok := m["docker"]; !ok {
		m["docker"] = map[string]any{
			"enabled":      dockerEnabled,
			"socket_path":  envOr("GPX_DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
			"label_prefix": "goproxify.",
			"runtime":      dockerRuntime,
		}
		changed = true
	}
	if _, ok := m["portainer"]; !ok {
		m["portainer"] = map[string]any{
			"enabled":         portainerEnabled,
			"url":             portainerURL,
			"api_key":         portainerAPIKey,
			"poll_interval_s": portainerPollS,
		}
		changed = true
	}
	if !changed {
		return nil
	}
	if err := writeJSON(path, m); err != nil {
		return fmt.Errorf("bootstrap agent: migration docker/portainer: %w", err)
	}
	slog.Info("bootstrap: agent.json migré — sections docker/portainer ajoutées", "path", path)
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// Écriture atomique : temp + rename.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bootstrap-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, path)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func envBoolOr(key string, def bool) bool {
	v := os.Getenv(key)
	switch v {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return def
	}
}
