// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/core/proxy"
	"github.com/vincamok/goproxify/internal/core/router"
)

const peerSyncInterval = 15 * time.Second

// handlePushGatewayPeers reçoit la liste des Cores pairs (endpoint + token) depuis Admin.
func (s *Server) handlePushGatewayPeers(w http.ResponseWriter, r *http.Request) {
	var peers []proxy.PeerInfo
	if err := json.NewDecoder(r.Body).Decode(&peers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Ne pas s'enregistrer soi-même comme peer
	self := strings.TrimSpace(s.cfg.Identity.NodeName)
	filtered := peers[:0]
	for _, p := range peers {
		if p.Name != "" && p.Name == self {
			continue
		}
		filtered = append(filtered, p)
	}
	s.peers.Replace(filtered)
	s.log.Info("gateway: peers mis à jour", "count", len(filtered))
	w.WriteHeader(http.StatusNoContent)
}

// handleLBScores expose les scores adaptive pour sync inter-Cores.
func (s *Server) handleLBScores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.metrics.Snapshot())
}

// handleGatewayTunnel ouvre un tunnel TCP vers une cible locale (IP:port conteneur).
// Auth Bearer (token Core). Réponse 200 puis flux brut.
func (s *Server) handleGatewayTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" {
		http.Error(w, "target requis", http.StatusBadRequest)
		return
	}
	host, port, err := net.SplitHostPort(req.Target)
	if err != nil {
		http.Error(w, "target host:port invalide", http.StatusBadRequest)
		return
	}
	if net.ParseIP(host) == nil {
		http.Error(w, "target doit être une IP", http.StatusBadRequest)
		return
	}
	if !s.isLocalOwnedIP(host) {
		http.Error(w, "cible non possédée par ce Core", http.StatusForbidden)
		return
	}
	_ = port

	upstream, err := net.DialTimeout("tcp", req.Target, 10*time.Second)
	if err != nil {
		http.Error(w, "dial: "+err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, bufrw, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	_ = bufrw.Flush()

	errCh := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		errCh <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		errCh <- struct{}{}
	}()
	<-errCh
	upstream.Close()
	client.Close()
}

// isLocalOwnedIP indique si une IP appartient à un backend discovery local (sans owner distant).
func (s *Server) isLocalOwnedIP(ip string) bool {
	for _, rt := range s.table.All() {
		if !isDockerDiscoveryRoute(rt) {
			continue
		}
		for _, b := range rt.Backends {
			if b.OwnerCoreEndpoint != "" {
				continue
			}
			if backendIPMatch(b.URL, ip) {
				return true
			}
		}
	}
	return false
}

func backendIPMatch(rawURL, ip string) bool {
	u := rawURL
	for _, scheme := range []string{"http://", "https://"} {
		if strings.HasPrefix(u, scheme) {
			u = u[len(scheme):]
			break
		}
	}
	host := u
	if h, _, err := net.SplitHostPort(u); err == nil {
		host = h
	} else if i := strings.IndexByte(u, '/'); i >= 0 {
		host = u[:i]
	}
	return host == ip
}

// startPeerSyncLoop fusionne périodiquement les pools docker-host des Cores pairs.
func (s *Server) startPeerSyncLoop(ctx context.Context) {
	go func() {
		t := time.NewTicker(peerSyncInterval)
		defer t.Stop()
		s.syncPeersOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.syncPeersOnce(ctx)
			}
		}
	}()
}

func (s *Server) syncPeersOnce(ctx context.Context) {
	peers := s.peers.All()
	if len(peers) == 0 {
		return
	}
	for _, p := range peers {
		s.syncPeer(ctx, p)
	}
}

func (s *Server) syncPeer(ctx context.Context, p proxy.PeerInfo) {
	client := &http.Client{Timeout: 8 * time.Second}

	// Scores LB
	reqScores, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/lb/scores", nil)
	if err == nil {
		reqScores.Header.Set("Authorization", "Bearer "+p.Token)
		if resp, err := client.Do(reqScores); err == nil {
			var scores map[string]float64
			if resp.StatusCode == http.StatusOK {
				_ = json.NewDecoder(resp.Body).Decode(&scores)
				s.metrics.MergeScores(scores)
			}
			resp.Body.Close()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/agent/containers", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := client.Do(req)
	if err != nil {
		s.log.Debug("gateway: sync peer injoignable", "peer", p.Name, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var items []struct {
		ID        string   `json:"id"`
		Host      string   `json:"host"`
		Backends  []string `json:"backends"`
		TLS       bool     `json:"tls"`
		Source    string   `json:"source"`
		AgentName string   `json:"agent_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return
	}

	for _, it := range items {
		if it.Host == "" || len(it.Backends) == 0 {
			continue
		}
		if it.Source != "" && it.Source != "docker" {
			continue
		}
		local, ok := s.table.ByHost(it.Host)
		if !ok || !isDockerDiscoveryRoute(local) {
			// Pas de pool local pour ce host — ignorer (ce Core n'est pas concerné)
			continue
		}
		remoteBackends := make([]router.Backend, 0, len(it.Backends))
		for _, u := range it.Backends {
			remoteBackends = append(remoteBackends, router.Backend{
				URL:               u,
				AgentName:         it.AgentName,
				OwnerCoreEndpoint: p.Endpoint,
				OwnerCoreName:     p.Name,
			})
		}
		merged := mergeRemoteBackends(local.Backends, remoteBackends, p.Endpoint)
		if len(merged) == len(local.Backends) && backendsEqualURLs(merged, local.Backends) {
			continue
		}
		local.Backends = merged
		if local.LB == "" {
			local.LB = router.LBAdaptive
		}
		s.table.Upsert(local)
		s.log.Debug("gateway: pool enrichi", "host", it.Host, "peer", p.Name, "backends", len(merged))
	}
}

// mergeRemoteBackends garde les backends locaux, remplace les distants du même peer.
func mergeRemoteBackends(existing, remote []router.Backend, peerEndpoint string) []router.Backend {
	out := make([]router.Backend, 0, len(existing)+len(remote))
	for _, b := range existing {
		if b.OwnerCoreEndpoint == peerEndpoint {
			continue // refresh depuis peer
		}
		out = append(out, b)
	}
	out = append(out, remote...)
	return out
}

func backendsEqualURLs(a, b []router.Backend) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].URL != b[i].URL || a[i].OwnerCoreEndpoint != b[i].OwnerCoreEndpoint {
			return false
		}
	}
	return true
}

// applyGatewayPeersWS applique un push WS de peers gateway.
func (s *Server) applyGatewayPeersWS(payload json.RawMessage) error {
	var peers []proxy.PeerInfo
	if err := json.Unmarshal(payload, &peers); err != nil {
		return err
	}
	self := strings.TrimSpace(s.cfg.Identity.NodeName)
	filtered := peers[:0]
	for _, p := range peers {
		if p.Name != "" && p.Name == self {
			continue
		}
		filtered = append(filtered, p)
	}
	s.peers.Replace(filtered)
	s.log.Info("ws: gateway peers mis à jour", "count", len(filtered))
	return nil
}
