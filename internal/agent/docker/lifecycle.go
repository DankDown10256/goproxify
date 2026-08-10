// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// RegistryAuth contient les credentials pour un registry privé.
type RegistryAuth struct {
	Username string
	Password string
	Server   string
}

// LifecycleManager gère les mises à jour, rollbacks et l'escalade de health.
type LifecycleManager struct {
	client       *Client
	log          *slog.Logger
	registryAuth *RegistryAuth

	mu           sync.Mutex
	prevImages   map[string]string // containerID → image précédente
	restartCount map[string]int    // containerID → nb de restarts successifs
	onEscalation func(containerID, containerName, eventType, detail string)
}

// NewLifecycleManager crée un LifecycleManager.
func NewLifecycleManager(client *Client, log *slog.Logger) *LifecycleManager {
	return &LifecycleManager{
		client:       client,
		log:          log,
		prevImages:   make(map[string]string),
		restartCount: make(map[string]int),
	}
}

// SetOnEscalation enregistre le callback pour les événements d'escalade santé.
func (m *LifecycleManager) SetOnEscalation(fn func(containerID, containerName, eventType, detail string)) {
	m.mu.Lock()
	m.onEscalation = fn
	m.mu.Unlock()
}

func (m *LifecycleManager) emitEscalation(containerID, containerName, eventType, detail string) {
	m.mu.Lock()
	fn := m.onEscalation
	m.mu.Unlock()
	if fn != nil {
		fn(containerID, containerName, eventType, detail)
	}
}

// SetRegistryAuth configure les credentials pour les pulls d'images privées.
func (m *LifecycleManager) SetRegistryAuth(auth *RegistryAuth) {
	m.registryAuth = auth
}

// registryAuthHeader retourne le header X-Registry-Auth si des credentials sont configurés.
func (m *LifecycleManager) registryAuthHeader() string {
	if m.registryAuth == nil || m.registryAuth.Username == "" {
		return ""
	}
	cfg := map[string]string{
		"username":      m.registryAuth.Username,
		"password":      m.registryAuth.Password,
		"serveraddress": m.registryAuth.Server,
	}
	b, _ := json.Marshal(cfg)
	return base64.URLEncoding.EncodeToString(b)
}

// --- Mise à jour -----------------------------------------------------------

// PullImage déclenche un `docker pull` pour l'image spécifiée.
func (m *LifecycleManager) PullImage(ctx context.Context, image string) error {
	m.log.Info("lifecycle: pull image", "image", image)
	headers := map[string]string{}
	if auth := m.registryAuthHeader(); auth != "" {
		headers["X-Registry-Auth"] = auth
	}
	// Timeout plus long pour le pull (30s par défaut sur le client est trop court)
	pullCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return m.client.PostWithHeaders(pullCtx, "/images/create?fromImage="+image, nil, nil, headers)
}

// UpdateContainer tire la nouvelle image, recrée le conteneur.
// Sauvegarde l'image précédente pour un éventuel rollback.
func (m *LifecycleManager) UpdateContainer(ctx context.Context, containerID string, prune bool) error {
	var inspect ContainerInspect
	if err := m.client.Get(ctx, "/containers/"+containerID+"/json", &inspect); err != nil {
		return err
	}
	image := inspect.Config.Image
	m.log.Info("lifecycle: mise à jour conteneur", "name", inspect.Name, "image", image)

	// Sauvegarde de l'image actuelle pour rollback
	m.mu.Lock()
	m.prevImages[containerID] = image
	m.mu.Unlock()

	if err := m.PullImage(ctx, image); err != nil {
		return err
	}

	return m.RecreateContainer(ctx, containerID, image, prune)
}

// RecreateContainer arrête, supprime et recrée un conteneur avec la même config.
func (m *LifecycleManager) RecreateContainer(ctx context.Context, containerID, image string, prune bool) error {
	var inspect ContainerInspect
	if err := m.client.Get(ctx, "/containers/"+containerID+"/json", &inspect); err != nil {
		return err
	}
	name := inspect.Name

	m.log.Info("lifecycle: recreate", "name", name, "image", image)

	// Arrêt
	if err := m.client.Post(ctx, "/containers/"+containerID+"/stop", nil, nil); err != nil {
		m.log.Warn("lifecycle: stop container", "name", name, "err", err)
	}
	time.Sleep(3 * time.Second)

	// Suppression
	if err := m.client.Delete(ctx, "/containers/"+containerID+"?force=true"); err != nil {
		return err
	}

	// Recréation
	body := ContainerCreateBody{
		Image:  image,
		Labels: inspect.Config.Labels,
	}
	body.HostConfig.RestartPolicy.Name = inspect.HostConfig.RestartPolicy.Name

	var created struct{ ID string `json:"Id"` }
	if err := m.client.Post(ctx, "/containers/create?name="+trimSlash(name), body, &created); err != nil {
		return err
	}
	if err := m.client.Post(ctx, "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return err
	}
	m.log.Info("lifecycle: conteneur recréé", "name", name, "id", created.ID[:12])

	if prune {
		_ = m.client.Delete(ctx, "/images/prune")
	}
	return nil
}

// Rollback recrée le conteneur avec l'image précédente.
func (m *LifecycleManager) Rollback(ctx context.Context, containerID string) error {
	m.mu.Lock()
	prev, ok := m.prevImages[containerID]
	m.mu.Unlock()
	if !ok {
		m.log.Warn("lifecycle: pas d'image précédente pour rollback", "id", containerID)
		return nil
	}
	m.log.Info("lifecycle: rollback", "id", containerID[:12], "prev_image", prev)
	return m.RecreateContainer(ctx, containerID, prev, false)
}

// --- Health escalation ----------------------------------------------------

// HealthEscalationConfig configure la politique d'escalade.
type HealthEscalationConfig struct {
	RestartMaxRetries int
	RecreateTimeoutS  int
	CheckIntervalS    int
}

// WatchHealth surveille la santé d'un conteneur et escalade si nécessaire.
func (m *LifecycleManager) WatchHealth(ctx context.Context, containerID, containerName string, cfg HealthEscalationConfig) {
	if cfg.CheckIntervalS <= 0 {
		cfg.CheckIntervalS = 15
	}
	if cfg.RestartMaxRetries <= 0 {
		cfg.RestartMaxRetries = 3
	}

	ticker := time.NewTicker(time.Duration(cfg.CheckIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkHealth(ctx, containerID, containerName, cfg)
		}
	}
}

func (m *LifecycleManager) checkHealth(ctx context.Context, containerID, containerName string, cfg HealthEscalationConfig) {
	var inspect ContainerInspect
	if err := m.client.Get(ctx, "/containers/"+containerID+"/json", &inspect); err != nil {
		return
	}
	if inspect.State.Health == nil || inspect.State.Health.Status != "unhealthy" {
		// Conteneur sain : reset du compteur
		m.mu.Lock()
		m.restartCount[containerID] = 0
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	count := m.restartCount[containerID]
	m.restartCount[containerID] = count + 1
	m.mu.Unlock()

	m.log.Warn("lifecycle: conteneur unhealthy", "name", containerName, "restarts", count)
	m.emitEscalation(containerID, containerName, "health_critical",
		fmt.Sprintf("container=%s restarts=%d", containerName, count))

	switch {
	case count < cfg.RestartMaxRetries:
		// Étape 1 : restart simple
		m.log.Info("lifecycle: restart", "name", containerName)
		_ = m.client.Post(ctx, "/containers/"+containerID+"/restart", nil, nil)

	case count == cfg.RestartMaxRetries:
		// Étape 2 : recreate
		m.log.Warn("lifecycle: recreate après échecs restart", "name", containerName)
		m.emitEscalation(containerID, containerName, "health_escalation",
			fmt.Sprintf("container=%s action=recreate", containerName))
		if err := m.RecreateContainer(ctx, containerID, inspect.Config.Image, false); err != nil {
			m.log.Error("lifecycle: recreate échoué", "name", containerName, "err", err)
		}

	case count == cfg.RestartMaxRetries+1:
		// Étape 3 : rollback
		m.log.Warn("lifecycle: rollback", "name", containerName)
		m.emitEscalation(containerID, containerName, "health_escalation",
			fmt.Sprintf("container=%s action=rollback", containerName))
		if err := m.Rollback(ctx, containerID); err != nil {
			m.log.Error("lifecycle: rollback échoué", "name", containerName, "err", err)
		}

	default:
		// Étape 4 : quarantaine — le conteneur est retiré du pool par l'Admin via report
		m.log.Error("lifecycle: quarantaine", "name", containerName)
		m.emitEscalation(containerID, containerName, "health_escalation",
			fmt.Sprintf("container=%s action=quarantine", containerName))
	}
}

func trimSlash(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}
