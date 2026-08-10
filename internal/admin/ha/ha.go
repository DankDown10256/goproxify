// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ha implémente la Haute Disponibilité de l'Admin via Raft.
// Le leader Admin détient le lock d'écriture SQLite ;
// les followers redirigent les écritures vers le leader.
package ha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/vincamok/goproxify/internal/core/raft"
)

// Manager coordonne l'élection HA et le forwarding des écritures.
type Manager struct {
	node    *raft.Node
	raftSrv *raft.Server
	peers   map[string]string // id → base URL
	log     *slog.Logger
}

// Config configure le Manager HA.
type Config struct {
	NodeID   string
	Peers    map[string]string
	RaftPort int
}

// New crée un Manager HA.
func New(cfg Config, log *slog.Logger) *Manager {
	raftCfg := raft.Config{
		ID:                 cfg.NodeID,
		Peers:              cfg.Peers,
		ElectionTimeoutMin: 200 * time.Millisecond,
		ElectionTimeoutMax: 500 * time.Millisecond,
		HeartbeatInterval:  75 * time.Millisecond,
	}
	transport := raft.NewHTTPTransport()
	node := raft.NewNode(raftCfg, transport, log)
	srv := raft.NewServer(node, cfg.RaftPort, log)

	return &Manager{
		node:    node,
		raftSrv: srv,
		peers:   cfg.Peers,
		log:     log,
	}
}

// Start démarre le cluster HA.
func (m *Manager) Start(_ context.Context) error {
	if err := m.raftSrv.Start(); err != nil {
		return fmt.Errorf("ha: raft server: %w", err)
	}
	m.node.Start()
	m.log.Info("admin HA démarré")
	return nil
}

// Stop arrête le nœud HA.
func (m *Manager) Stop() { m.node.Stop() }

// IsLeader indique si ce nœud Admin est le leader.
func (m *Manager) IsLeader() bool { return m.node.IsLeader() }

// LeaderID retourne l'ID du leader Admin courant.
func (m *Manager) LeaderID() string { return m.node.LeaderID() }

// ForwardOrHandle renvoie un middleware HTTP qui:
//   - laisse passer les requêtes GET/HEAD sur tous les nœuds
//   - sur le leader, laisse passer les mutations (POST/PUT/PATCH/DELETE)
//   - sur un follower, proxy les mutations vers le leader
func (m *Manager) ForwardOrHandle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutation(r.Method) && !m.IsLeader() {
			m.proxyToLeader(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func (m *Manager) proxyToLeader(w http.ResponseWriter, r *http.Request) {
	leaderID := m.LeaderID()
	leaderURL, ok := m.peers[leaderID]
	if !ok || leaderURL == "" {
		http.Error(w, `{"error":"no leader available"}`, http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse(leaderURL)
	if err != nil {
		http.Error(w, `{"error":"bad leader url"}`, http.StatusInternalServerError)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(w, r)
}

// StatusResponse est retourné par l'endpoint /ha/status.
type StatusResponse struct {
	NodeID   string `json:"node_id"`
	IsLeader bool   `json:"is_leader"`
	LeaderID string `json:"leader_id"`
}

// HandleStatus expose l'état HA en HTTP.
func (m *Manager) HandleStatus(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		NodeID:   m.node.LeaderID(), // utilise leaderID stocké
		IsLeader: m.IsLeader(),
		LeaderID: m.LeaderID(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// ProposeWrite soumet une commande d'écriture au log Raft (leader uniquement).
func (m *Manager) ProposeWrite(data []byte) error {
	return m.node.Propose(data)
}

// ForwardWrite envoie une commande d'écriture au leader via HTTP POST.
func (m *Manager) ForwardWrite(ctx context.Context, path string, body []byte) error {
	leaderID := m.LeaderID()
	leaderURL, ok := m.peers[leaderID]
	if !ok {
		return fmt.Errorf("ha: leader inconnu")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, leaderURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ha: leader returned %d", resp.StatusCode)
	}
	return nil
}
