// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portainer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
)

// Discovery découvre les conteneurs sur tous les endpoints Portainer
// et les rapporte à l'Administration Goproxify.
type Discovery struct {
	client        *Client
	adminEndpoint string
	authToken     string
	labelPrefix   string
	agentName     string
	pollInterval  time.Duration
	log           *slog.Logger
}

// NewDiscovery crée une Discovery Portainer.
func NewDiscovery(client *Client, adminEndpoint, authToken, labelPrefix, agentName string,
	pollIntervalS int, log *slog.Logger) *Discovery {
	if pollIntervalS <= 0 {
		pollIntervalS = 30
	}
	return &Discovery{
		client:        client,
		adminEndpoint: adminEndpoint,
		authToken:     authToken,
		labelPrefix:   labelPrefix,
		agentName:     agentName,
		pollInterval:  time.Duration(pollIntervalS) * time.Second,
		log:           log,
	}
}

// Start lance la boucle de découverte : scan initial puis polling périodique.
// Portainer ne fournit pas de stream d'événements multi-endpoint, on poll donc.
func (d *Discovery) Start(ctx context.Context) {
	d.scan(ctx)
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.scan(ctx)
		}
	}
}

// scan liste tous les endpoints puis tous les conteneurs de chacun.
func (d *Discovery) scan(ctx context.Context) {
	endpoints, err := d.client.ListEndpoints(ctx)
	if err != nil {
		d.log.Error("portainer: liste endpoints", "err", err)
		return
	}

	seen := map[string]bool{}

	for _, ep := range endpoints {
		containers, err := d.client.ListContainers(ctx, ep.ID)
		if err != nil {
			d.log.Warn("portainer: liste containers", "endpoint", ep.Name, "err", err)
			continue
		}
		for _, c := range containers {
			firstNet := ""
			for name := range c.NetworkSettings.Networks {
				firstNet = name
				break
			}
			firstName := ""
			if len(c.Names) > 0 {
				firstName = c.Names[0]
			}
			specs := docker.ParseLabelsMulti(c.ID, firstName, c.Image, firstNet, c.Labels, nil, "")
			if len(specs) == 0 {
				continue
			}
			key := fmt.Sprintf("%d:%s", ep.ID, c.ID)
			seen[key] = true
			for _, spec := range specs {
				d.report(ctx, ep, spec)
			}
		}
	}
}

// report envoie la config proxy vers l'Administration.
func (d *Discovery) report(ctx context.Context, ep Endpoint, spec *docker.ProxySpec) {
	containerName := strings.TrimPrefix(spec.ContainerName, "/")
	payload := map[string]any{
		"id":           fmt.Sprintf("portainer:%d:%s:%s", ep.ID, spec.ContainerID[:12], spec.Host),
		"host":         spec.Host,
		"route_type":   spec.Type,
		"backends":     []string{spec.BackendURL},
		"tls_enabled":  spec.TLS,
		"passthrough":  spec.Passthrough,
		"source":       "portainer",
		"container_id": spec.ContainerID,
		"endpoint_id":  ep.ID,
		"endpoint_name": ep.Name,
		"agent_name":   d.agentName,
		"role":         spec.Role,
	}
	if spec.Role == docker.RoleCanary {
		payload["canary_weight"] = spec.CanaryWeight
	}
	docker.AttachSecurityPayload(payload, spec)

	body, _ := json.Marshal(payload)
	url := d.adminEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+d.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.log.Warn("portainer: report vers Admin", "host", spec.Host, "container", containerName, "err", err)
		return
	}
	defer resp.Body.Close()
	d.log.Info("portainer: proxy rapporté", "host", spec.Host, "endpoint", ep.Name, "status", resp.StatusCode)
}
