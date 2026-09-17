// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package portainer fournit un client pour l'API Portainer v2,
// permettant à l'Agent de découvrir des conteneurs sur tous les endpoints
// sans installer quoi que ce soit sur les hôtes distants.
package portainer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// endpointsResponse couvre le format paginé de Portainer 2.19+
// ({ "value": [...], "totalCount": N }) et l'ancien format tableau brut.
type endpointsResponse struct {
	Value []Endpoint `json:"value"`
}

// Client interroge l'API Portainer.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient crée un Client Portainer.
// token est un API-key Portainer (Settings → API Keys) ou un JWT de session.
func NewClient(baseURL, token string) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Portainer self-signed certs
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}
}

// setAuth applique soit X-API-Key (préfixe "ptr_"), soit Authorization Bearer.
// Portainer 2.x refuse les deux headers simultanément.
func (c *Client) setAuth(req *http.Request) {
	if strings.HasPrefix(c.token, "ptr_") {
		req.Header.Set("X-API-Key", c.token)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	c.setAuth(req)

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

func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("portainer: GET %s → %d: %s", path, resp.StatusCode, b)
	}
	return b, nil
}

// Endpoint représente un hôte Docker enregistré dans Portainer.
type Endpoint struct {
	ID     int    `json:"Id"`
	Name   string `json:"Name"`
	URL    string `json:"URL"`
	Status int    `json:"Status"` // 1 = up, 2 = down
}

// ListEndpoints retourne tous les endpoints actifs.
// Portainer 2.19+ retourne un objet paginé { "value": [...], "totalCount": N } ;
// les versions antérieures retournent un tableau brut. On gère les deux.
func (c *Client) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	raw, err := c.getRaw(ctx, "/api/endpoints?limit=100")
	if err != nil {
		return nil, err
	}
	var endpoints []Endpoint
	var paged endpointsResponse
	if err := json.Unmarshal(raw, &paged); err == nil && paged.Value != nil {
		endpoints = paged.Value
	} else if err := json.Unmarshal(raw, &endpoints); err != nil {
		return nil, fmt.Errorf("portainer: décodage endpoints: %w", err)
	}
	active := endpoints[:0]
	for _, e := range endpoints {
		if e.Status == 1 {
			active = append(active, e)
		}
	}
	return active, nil
}

// ContainerPort est un port publié par un conteneur Docker.
type ContainerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"` // "tcp" | "udp"
}

// Container est un résumé de conteneur retourné par l'API Docker proxifiée de Portainer.
type Container struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	Ports   []ContainerPort   `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
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
