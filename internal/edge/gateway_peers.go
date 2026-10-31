// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

const peerSyncInterval = 15 * time.Second

// handlePushGatewayPeers reçoit la liste des passerelles pairs (endpoint + token) depuis Admin.
func (s *Server) handlePushGatewayPeers(w http.ResponseWriter, r *http.Request) {
	var peers []proxy.PeerInfo
	if err := json.NewDecoder(r.Body).Decode(&peers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyGatewayPeers(peers)
	w.WriteHeader(http.StatusNoContent)
}

// handleLBScores expose les scores adaptive pour sync inter-passerelles.
func (s *Server) handleLBScores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.metrics.Snapshot())
}

// handleGatewayTunnel ouvre un tunnel TCP vers une cible locale (IP:port conteneur).
// Auth Bearer (token passerelle). Réponse 200 puis flux brut.
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
		http.Error(w, "cible non possédée par cette passerelle", http.StatusForbidden)
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
			if b.OwnerEdgeEndpoint != "" {
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

// startPeerSyncLoop fusionne périodiquement les pools docker-host des passerelles pairs.
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
	s.peerHealth.retain(peers)
	for _, p := range peers {
		if !s.peerHealth.due(p.Name, time.Now()) {
			continue
		}
		s.syncPeer(ctx, p)
	}
}

// syncPeer sonde le pair avant de lui demander quoi que ce soit : un pair injoignable coûte un appel de 2 s et
// une attente croissante, pas la file de huit appels de 8 s. Seuls les tours menés à terme alimentent
// gpx_peer_sync_duration_seconds.
func (s *Server) syncPeer(ctx context.Context, p proxy.PeerInfo) {
	up := probePeer(ctx, p)
	if up {
		metrics.PeerSync.Up.WithLabelValues(p.Name).Set(1)
	} else {
		metrics.PeerSync.Up.WithLabelValues(p.Name).Set(0)
		s.log.Debug("gateway: pair injoignable, synchronisation reportée", "peer", p.Name)
		s.peerHealth.record(p.Name, false, time.Now())
		return
	}

	ctx, cancel := context.WithTimeout(ctx, peerSyncBudget)
	defer cancel()
	start := time.Now()
	defer func() {
		metrics.PeerSync.Duration.WithLabelValues(p.Name).Observe(time.Since(start).Seconds())
		s.peerHealth.record(p.Name, ctx.Err() == nil, time.Now())
	}()
	s.exchangeWithPeer(ctx, p)
}

func (s *Server) exchangeWithPeer(ctx context.Context, p proxy.PeerInfo) {
	client := &http.Client{Timeout: 8 * time.Second}

	// Scores LB
	reqScores, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/lb/scores", nil)
	if err == nil {
		reqScores.Header.Set("Authorization", "Bearer "+p.Token)
		if resp, err := client.Do(reqScores); err == nil {
			s.peerSeen.mark(p.Name, time.Now())
			var scores map[string]float64
			if resp.StatusCode == http.StatusOK {
				_ = json.NewDecoder(resp.Body).Decode(&scores)
				s.metrics.MergeScores(scores)
			}
			resp.Body.Close()
		}
	}

	// Profils comportementaux WAF
	s.syncWAFBehaviorFromPeer(ctx, client, p)
	s.syncSurfaceFromPeer(ctx, client, p)
	s.syncAppsFromPeer(ctx, client, p)
	s.syncThreatListsFromPeer(ctx, client, p)
	s.syncPortalReplicaFromPeer(ctx, client, p)
	s.syncAgentReplicaFromPeer(ctx, client, p)
	s.syncECHReplicaFromPeer(ctx, client, p)
	s.syncAgentStateFromPeer(ctx, client, p)
	s.syncAgentNodesFromPeer(ctx, client, p)
	s.syncProxiesFromPeer(ctx, client, p)
	s.syncPushedFromPeer(ctx, client, p)
	s.syncBansFromPeer(ctx, client, p)

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
		Disabled  bool     `json:"disabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return
	}

	for _, it := range items {
		if it.Host == "" || len(it.Backends) == 0 || it.Disabled {
			continue
		}
		if it.Source != "" && it.Source != "docker" {
			continue
		}
		local, ok := s.table.ByHost(it.Host)
		if !ok || !isDockerDiscoveryRoute(local) {
			// Pas de pool local pour ce host — ignorer (cette passerelle n'est pas concerné)
			continue
		}
		remoteBackends := make([]router.Backend, 0, len(it.Backends))
		for _, u := range it.Backends {
			remoteBackends = append(remoteBackends, router.Backend{
				URL:               u,
				AgentName:         it.AgentName,
				OwnerEdgeEndpoint: p.Endpoint,
				OwnerEdgeName:     p.Name,
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
		if b.OwnerEdgeEndpoint == peerEndpoint {
			continue // refresh depuis peer
		}
		out = append(out, b)
	}
	seen := make(map[string]struct{}, len(out))
	for _, b := range out {
		seen[b.URL] = struct{}{}
	}
	for _, b := range remote {
		if _, dup := seen[b.URL]; dup {
			continue
		}
		seen[b.URL] = struct{}{}
		out = append(out, b)
	}
	return out
}

func backendsEqualURLs(a, b []router.Backend) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].URL != b[i].URL || a[i].OwnerEdgeEndpoint != b[i].OwnerEdgeEndpoint {
			return false
		}
	}
	return true
}

func (s *Server) syncWAFBehaviorFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.wafEngine == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/waf/behavior/export", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var payload behavior.HAPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}
	s.wafEngine.BehaviorStore().ApplyHAPayload(payload)
}

// applyGatewayPeersWS applique un push WS de peers gateway.
func (s *Server) applyGatewayPeersWS(payload json.RawMessage) error {
	var peers []proxy.PeerInfo
	if err := json.Unmarshal(payload, &peers); err != nil {
		return err
	}
	s.applyGatewayPeers(peers)
	return nil
}

// applyGatewayPeers persiste la liste des passerelles pairs reçue de l'Admin puis l'applique, sans
// s'y inscrire soi-même. Les membres d'un groupe HA se retrouvent ainsi après un redémarrage sans
// Admin.
func (s *Server) applyGatewayPeers(peers []proxy.PeerInfo) {
	self := strings.TrimSpace(s.cfg.Identity.NodeName)
	filtered := make([]proxy.PeerInfo, 0, len(peers))
	for _, p := range peers {
		if p.Name != "" && p.Name == self {
			continue
		}
		filtered = append(filtered, p)
	}
	if err := s.cache.SaveFile(gatewayPeersPath(), filtered); err != nil {
		s.log.Warn("gateway: persistance des pairs échouée", "err", err)
	}
	s.peers.Replace(filtered)
	names := make([]string, 0, len(filtered))
	for _, p := range filtered {
		names = append(names, p.Name)
	}
	if s.surface != nil {
		s.surface.RetainPeers(names)
	}
	s.log.Info("gateway: peers mis à jour", "count", len(filtered))
	s.ensurePortalPublicRoute()
	go s.wsHub.BroadcastEdgeEndpoints()
}

// gatewayPeersPath est la copie locale chiffrée des passerelles pairs (endpoint et jeton compris).
func gatewayPeersPath() string {
	if p := os.Getenv("GPX_GATEWAY_PEERS_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/gateway-peers.gpx"
}

// loadGatewayPeersFromDisk rend à la passerelle ses pairs HA sans l'Admin : synchronisation des
// bans, du portail, des listes Ephor et des pools de conteneurs.
func (s *Server) loadGatewayPeersFromDisk() {
	var peers []proxy.PeerInfo
	ok, err := s.cache.LoadFile(gatewayPeersPath(), &peers)
	if err != nil {
		s.log.Warn("gateway: pairs locaux illisibles — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.peers.Replace(peers)
	s.log.Info("gateway: pairs chargés depuis le disque", "count", len(peers))
}
