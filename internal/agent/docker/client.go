// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package docker fournit un client HTTP léger sur socket Unix pour l'API Docker/Podman.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// socketCandidates liste les emplacements de socket Docker/Podman par ordre de préférence.
var socketCandidates = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/podman/podman.sock",
	"/var/run/podman/podman.sock",
}

// AutoDetectSocket retourne le chemin du premier socket Docker/Podman disponible.
// runtime peut être "docker", "podman" ou "auto".
func AutoDetectSocket(runtime, configured string) string {
	if configured != "" {
		return configured
	}
	// Filtre selon le runtime demandé
	candidates := socketCandidates
	switch runtime {
	case "docker":
		candidates = []string{"/var/run/docker.sock", "/run/docker.sock"}
	case "podman":
		candidates = []string{"/run/podman/podman.sock", "/var/run/podman/podman.sock"}
		// Podman rootless : XDG_RUNTIME_DIR
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			candidates = append([]string{xdg + "/podman/podman.sock"}, candidates...)
		}
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/var/run/docker.sock" // fallback
}

// Client est un client HTTP minimal vers le daemon Docker via socket Unix.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient crée un Client Docker sur le socket indiqué.
func NewClient(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		socket: socketPath,
		http:   &http.Client{Transport: transport, Timeout: 2 * time.Minute},
	}
}

func (c *Client) url(path string) string {
	return "http://docker" + path
}

// Get effectue un GET sur l'API Docker et décode la réponse JSON.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: GET %s → %d: %s", path, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Post effectue un POST avec corps JSON.
func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: POST %s → %d: %s", path, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// PostWithHeaders effectue un POST avec corps JSON et headers supplémentaires.
func (c *Client) PostWithHeaders(ctx context.Context, path string, body any, out any, headers map[string]string) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: POST %s → %d: %s", path, resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Delete effectue un DELETE.
func (c *Client) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url(path), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: DELETE %s → %d: %s", path, resp.StatusCode, b)
	}
	return nil
}

// StreamLines ouvre un flux (events, logs) et appelle fn pour chaque ligne JSON brute.
// Bloque jusqu'à ctx.Done() ou erreur.
func (c *Client) StreamLines(ctx context.Context, path string, fn func([]byte)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return err
	}
	// Transport sans timeout global pour les flux longs
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", c.socket)
		},
	}
	cl := &http.Client{Transport: t}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fn(sc.Bytes())
		}
	}
	return sc.Err()
}

// --- Types Docker ----------------------------------------------------------

// ContainerSummary est la réponse de GET /containers/json.
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Ports   []PortBinding     `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// PortBinding décrit un port exposé par un conteneur.
type PortBinding struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
	IP          string `json:"IP"`
}

// ContainerInspect est la réponse de GET /containers/{id}/json.
type ContainerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Running  bool   `json:"Running"`
		Health   *struct {
			Status string `json:"Status"` // healthy | unhealthy | starting
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image        string              `json:"Image"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"` // "3000/tcp": {}
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Event est un événement Docker du stream /events.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

// NetworkConnectBody est le corps de POST /networks/{id}/connect.
type NetworkConnectBody struct {
	Container string `json:"Container"`
}

// ContainerCreateBody est le corps minimal de POST /containers/create.
type ContainerCreateBody struct {
	Image      string            `json:"Image"`
	Labels     map[string]string `json:"Labels"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		Binds []string `json:"Binds"`
	} `json:"HostConfig"`
}
