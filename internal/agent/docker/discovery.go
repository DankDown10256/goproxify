// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LifecycleEventFn est appelé pour start/die/destroy sur les conteneurs gérés.
type LifecycleEventFn func(containerID, containerName, action string)

// Discovery écoute les événements Docker et rapporte les changements à l'Administration.
type Discovery struct {
	client       *Client
	coreEndpoint string
	agentName    string
	mu           sync.RWMutex
	authToken    string
	labelPrefix  string
	log          *slog.Logger
	netManager   *NetworkManager
	onLifecycle  LifecycleEventFn
	known        map[string]string // containerID → name (proxies goproxify)
}

// NewDiscovery crée un Discovery.
func NewDiscovery(client *Client, coreEndpoint, authToken, labelPrefix, agentName string,
	netMgr *NetworkManager, log *slog.Logger) *Discovery {
	return &Discovery{
		client:       client,
		coreEndpoint: coreEndpoint,
		agentName:    agentName,
		authToken:    authToken,
		labelPrefix:  labelPrefix,
		log:          log,
		netManager:   netMgr,
		known:        make(map[string]string),
	}
}

// SetToken met à jour le token d'authentification (après un appairage différé).
func (d *Discovery) SetToken(token string) {
	d.mu.Lock()
	d.authToken = token
	d.mu.Unlock()
}

// SetOnLifecycle enregistre le callback pour les événements de cycle de vie.
func (d *Discovery) SetOnLifecycle(fn LifecycleEventFn) {
	d.mu.Lock()
	d.onLifecycle = fn
	d.mu.Unlock()
}

// IsKnown indique si le conteneur (ID complet ou préfixe ≥12) est dans le
// catalogue découvert (labels goproxify).
func (d *Discovery) IsKnown(containerID string) bool {
	if d == nil || containerID == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if _, ok := d.known[containerID]; ok {
		return true
	}
	if len(containerID) >= 12 {
		prefix := containerID
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		for id := range d.known {
			if strings.HasPrefix(id, prefix) || strings.HasPrefix(containerID, id) {
				return true
			}
		}
	}
	return false
}

func (d *Discovery) emitLifecycle(containerID, containerName, action string) {
	d.mu.RLock()
	fn := d.onLifecycle
	d.mu.RUnlock()
	if fn != nil {
		fn(containerID, containerName, action)
	}
}

// Start lance la boucle de découverte : scan initial + écoute du stream d'événements.
func (d *Discovery) Start(ctx context.Context) {
	// Scan initial des conteneurs existants
	d.ScanAll(ctx)

	// Stream des événements Docker
	go func() {
		for {
			err := d.client.StreamLines(ctx, "/events?filters=%7B%22type%22%3A%7B%22container%22%3Atrue%7D%7D", func(line []byte) {
				var ev Event
				if json.Unmarshal(line, &ev) == nil {
					d.handleEvent(ctx, ev)
				}
			})
			if ctx.Err() != nil {
				return
			}
			d.log.Warn("docker: stream événements interrompu, reconnexion", "err", err)
			time.Sleep(5 * time.Second)
		}
	}()
}

// ScanAll liste les conteneurs actifs et rapporte ceux avec les labels Goproxify.
// Peut être appelé manuellement pour forcer un re-scan (commande rescan depuis Admin).
func (d *Discovery) ScanAll(ctx context.Context) {
	var containers []ContainerSummary
	if err := d.client.Get(ctx, "/containers/json?all=false", &containers); err != nil {
		d.log.Error("docker: liste containers", "err", err)
		return
	}
	for _, c := range containers {
		netName, ip := firstNetworkWithIP(c)
		specs := ParseLabelsMulti(c.ID, firstName(c.Names), c.Image, netName, c.Labels, firstExposedPortsFromSummary(c), ip)
		if len(specs) == 0 {
			continue
		}
		if d.netManager != nil && netName != "" {
			if err := d.netManager.ConnectCoreToNetwork(ctx, netName); err != nil {
				d.log.Warn("docker: connexion Core au réseau (scan initial)", "network", netName, "err", err)
			}
		}
		for _, spec := range specs {
			d.report(ctx, spec)
		}
		d.mu.Lock()
		d.known[c.ID] = trimSlash(firstName(c.Names))
		d.mu.Unlock()
	}
}

// handleEvent réagit aux événements start/die/destroy.
func (d *Discovery) handleEvent(ctx context.Context, ev Event) {
	switch ev.Action {
	case "start":
		var inspect ContainerInspect
		if err := d.client.Get(ctx, "/containers/"+ev.Actor.ID+"/json", &inspect); err != nil {
			d.log.Warn("docker: inspect container", "id", ev.Actor.ID, "err", err)
			return
		}
		name := inspect.Name
		firstNet, ip := "", ""
		for netName, net := range inspect.NetworkSettings.Networks {
			firstNet = netName
			ip = net.IPAddress
			break
		}
		specs := ParseLabelsMulti(ev.Actor.ID, name, inspect.Config.Image, firstNet, inspect.Config.Labels, inspect.Config.ExposedPorts, ip)
		if len(specs) == 0 {
			return
		}
		d.log.Info("docker: conteneur découvert", "name", name, "hosts", len(specs))

		if d.netManager != nil && firstNet != "" {
			if err := d.netManager.ConnectCoreToNetwork(ctx, firstNet); err != nil {
				d.log.Warn("docker: connexion Core au réseau", "network", firstNet, "err", err)
			}
		}
		for _, spec := range specs {
			d.report(ctx, spec)
		}
		d.mu.Lock()
		d.known[ev.Actor.ID] = trimSlash(name)
		d.mu.Unlock()
		d.emitLifecycle(ev.Actor.ID, trimSlash(name), "start")

	case "die", "destroy":
		name := ev.Actor.Attributes["name"]
		d.mu.Lock()
		knownName, tracked := d.known[ev.Actor.ID]
		if tracked {
			delete(d.known, ev.Actor.ID)
		}
		d.mu.Unlock()
		if !tracked {
			return
		}
		if name == "" {
			name = knownName
		}
		d.log.Info("docker: conteneur arrêté", "name", name)
		d.reportStop(ctx, ev.Actor.ID, name)
		action := ev.Action
		if action == "die" {
			action = "stop"
		}
		d.emitLifecycle(ev.Actor.ID, name, action)
	}
}

// report envoie la config proxy vers le Core.
func (d *Discovery) report(ctx context.Context, spec *ProxySpec) {
	shortID := spec.ContainerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	payload := map[string]any{
		"id":           "docker:" + shortID + ":" + spec.Host,
		"host":         spec.Host,
		"route_type":   spec.Type,
		"backends":     []string{spec.BackendURL},
		"tls_enabled":  spec.TLS,
		"passthrough":  spec.Passthrough,
		"source":       "docker",
		"container_id": spec.ContainerID,
		"agent_name":   d.agentName,
		"role":         spec.Role,
	}
	if spec.Role == RoleCanary {
		payload["canary_weight"] = spec.CanaryWeight
	}
	AttachSecurityPayload(payload, spec)

	d.mu.RLock()
	token := d.authToken
	d.mu.RUnlock()

	body, _ := json.Marshal(payload)
	url := d.coreEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.log.Warn("docker: report vers Core", "host", spec.Host, "err", err)
		return
	}
	defer resp.Body.Close()
	d.log.Info("docker: proxy rapporté au Core", "host", spec.Host, "status", resp.StatusCode)
}

// reportStop notifie le Core qu'un conteneur est arrêté.
func (d *Discovery) reportStop(ctx context.Context, id, name string) {
	payload := map[string]any{
		"container_id": id,
		"name":         name,
		"action":       "stop",
	}

	d.mu.RLock()
	token := d.authToken
	d.mu.RUnlock()

	body, _ := json.Marshal(payload)
	url := d.coreEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.log.Warn("docker: report stop vers Core", "err", err)
		return
	}
	defer resp.Body.Close()
}

// --- Helpers ---------------------------------------------------------------

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func firstNetworkWithIP(c ContainerSummary) (name, ip string) {
	for n, net := range c.NetworkSettings.Networks {
		return n, net.IPAddress
	}
	return "", ""
}

// firstExposedPortsFromSummary construit un map ExposedPorts depuis les Ports du summary.
func firstExposedPortsFromSummary(c ContainerSummary) map[string]struct{} {
	if len(c.Ports) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(c.Ports))
	for _, p := range c.Ports {
		if p.Type == "tcp" && p.PrivatePort > 0 {
			m[strconv.Itoa(p.PrivatePort)+"/tcp"] = struct{}{}
		}
	}
	return m
}

// Ping vérifie que le daemon Docker est joignable.
func (d *Discovery) Ping(ctx context.Context) error {
	var info struct {
		ID string `json:"ID"`
	}
	if err := d.client.Get(ctx, "/info", &info); err != nil {
		return fmt.Errorf("docker daemon injoignable : %w", err)
	}
	return nil
}
