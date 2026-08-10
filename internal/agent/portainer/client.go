// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package portainer fournit un client pour l'API Portainer v2,
// permettant à l'Agent de découvrir des conteneurs sur tous les endpoints
// sans installer quoi que ce soit sur les hôtes distants.
package portainer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client interroge l'API Portainer.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient crée un Client Portainer.
// token est un API-key Portainer (Settings → API Keys) ou un JWT de session.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.token)
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("portainer: GET %s → %d: %s", path, resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Endpoint représente un hôte Docker enregistré dans Portainer.
type Endpoint struct {
	ID     int    `json:"Id"`
	Name   string `json:"Name"`
	URL    string `json:"URL"`
	Status int    `json:"Status"` // 1 = up, 2 = down
}

// ListEndpoints retourne tous les endpoints actifs.
func (c *Client) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	var endpoints []Endpoint
	if err := c.get(ctx, "/api/endpoints?limit=100", &endpoints); err != nil {
		return nil, err
	}
	// Ne garder que les endpoints joignables
	active := endpoints[:0]
	for _, e := range endpoints {
		if e.Status == 1 {
			active = append(active, e)
		}
	}
	return active, nil
}

// Container est un résumé de conteneur retourné par l'API Docker proxifiée de Portainer.
type Container struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// ListContainers retourne les conteneurs en cours d'exécution sur un endpoint.
func (c *Client) ListContainers(ctx context.Context, endpointID int) ([]Container, error) {
	var containers []Container
	path := fmt.Sprintf("/api/endpoints/%d/docker/containers/json?all=false", endpointID)
	if err := c.get(ctx, path, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}
