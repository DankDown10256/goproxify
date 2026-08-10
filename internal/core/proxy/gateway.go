// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// PeerInfo décrit un Core pair pour le gateway LB cross-Core.
type PeerInfo struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"` // http://host:8000
	Token    string `json:"token"`
}

// PeerRegistry stocke les credentials des Cores pairs (poussés par Admin).
type PeerRegistry struct {
	mu     sync.RWMutex
	byEP   map[string]PeerInfo
	byName map[string]PeerInfo
}

// NewPeerRegistry crée un registre vide.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		byEP:   make(map[string]PeerInfo),
		byName: make(map[string]PeerInfo),
	}
}

// Replace remplace entièrement la liste des pairs.
func (r *PeerRegistry) Replace(peers []PeerInfo) {
	if r == nil {
		return
	}
	nextEP := make(map[string]PeerInfo, len(peers))
	nextName := make(map[string]PeerInfo, len(peers))
	for _, p := range peers {
		ep := normalizeEndpoint(p.Endpoint)
		if ep == "" || p.Token == "" {
			continue
		}
		p.Endpoint = ep
		nextEP[ep] = p
		if p.Name != "" {
			nextName[p.Name] = p
		}
	}
	r.mu.Lock()
	r.byEP = nextEP
	r.byName = nextName
	r.mu.Unlock()
}

// LookupByEndpoint retourne le peer pour un endpoint gateway.
func (r *PeerRegistry) LookupByEndpoint(endpoint string) (PeerInfo, bool) {
	if r == nil {
		return PeerInfo{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byEP[normalizeEndpoint(endpoint)]
	return p, ok
}

// All retourne une copie des peers.
func (r *PeerRegistry) All() []PeerInfo {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PeerInfo, 0, len(r.byEP))
	for _, p := range r.byEP {
		out = append(out, p)
	}
	return out
}

func normalizeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	return strings.TrimRight(ep, "/")
}

// DialBackend ouvre une connexion TCP vers le backend.
// Si OwnerCoreEndpoint est défini, passe par le gateway du Core propriétaire.
func DialBackend(ctx context.Context, b *router.Backend, peers *PeerRegistry, timeout time.Duration) (net.Conn, error) {
	hostPort, err := backendHostPort(b.URL)
	if err != nil {
		return nil, err
	}
	if b.OwnerCoreEndpoint == "" {
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "tcp", hostPort)
	}
	peer, ok := peers.LookupByEndpoint(b.OwnerCoreEndpoint)
	if !ok || peer.Token == "" {
		return nil, fmt.Errorf("gateway: peer inconnu pour %s", b.OwnerCoreEndpoint)
	}
	return dialGateway(ctx, peer.Endpoint, peer.Token, hostPort, timeout)
}

func dialGateway(ctx context.Context, coreEndpoint, token, target string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(coreEndpoint)
	if err != nil {
		return nil, err
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		if u.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":8000"
		}
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	body, _ := json.Marshal(map[string]string{"target": target})
	req := fmt.Sprintf("POST /internal/v1/gateway/tunnel HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		u.Host, token, len(body), body)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("gateway: status %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	return &gatewayConn{Conn: conn, r: br}, nil
}

type gatewayConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *gatewayConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func backendHostPort(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		host = rawURL
	}
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host, nil
}
