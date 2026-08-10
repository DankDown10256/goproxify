// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/url"
	"sync"

	corews "github.com/vincamok/goproxify/internal/core/ws"
)

// AgentMetricsStore expose des scores de charge [0,100] par IP (conteneur ou hôte Agent).
// Alimenté par les messages WS metrics / heartbeat — plus de poll Admin HTTP.
type AgentMetricsStore struct {
	mu     sync.RWMutex
	scores map[string]float64 // IP → score
}

// NewAgentMetricsStore crée un store vide prêt à recevoir des updates WS.
func NewAgentMetricsStore() *AgentMetricsStore {
	return &AgentMetricsStore{scores: make(map[string]float64)}
}

// Score retourne le score de charge [0,100] pour une IP. -1 si inconnu.
func (s *AgentMetricsStore) Score(hostIP string) float64 {
	if s == nil {
		return -1
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.scores[hostIP]
	if !ok {
		return -1
	}
	return v
}

// UpdateFromMetrics ingère un payload Agent metrics (score par IP conteneur).
// Score = cpu×0.5 + mem×0.3 + disk_io×0.2.
func (s *AgentMetricsStore) UpdateFromMetrics(p corews.AgentMetricsPayload) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range p.Containers {
		ip := c.IP
		if ip == "" {
			continue
		}
		s.scores[ip] = compositeScore(c.CPUPct, c.MemPct, c.DiskIOPCT)
	}
}

// UpdateHost enregistre un score hôte (heartbeat Agent) pour l'IP de l'endpoint.
func (s *AgentMetricsStore) UpdateHost(endpoint string, cpuPct, memPct float64) {
	if s == nil {
		return
	}
	ip, err := endpointToIP(endpoint)
	if err != nil || ip == "" {
		return
	}
	s.mu.Lock()
	s.scores[ip] = compositeScore(cpuPct, memPct, 0)
	s.mu.Unlock()
}

func compositeScore(cpu, mem, disk float64) float64 {
	return cpu*0.5 + mem*0.3 + disk*0.2
}

// Snapshot retourne une copie des scores courants.
func (s *AgentMetricsStore) Snapshot() map[string]float64 {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]float64, len(s.scores))
	for k, v := range s.scores {
		out[k] = v
	}
	return out
}

// MergeScores fusionne des scores distants (ex. sync peer) sans effacer les locaux.
func (s *AgentMetricsStore) MergeScores(scores map[string]float64) {
	if s == nil || len(scores) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, sc := range scores {
		if ip == "" {
			continue
		}
		s.scores[ip] = sc
	}
}

// endpointToIP extrait l'IP/host d'un endpoint (URL ou host:port).
func endpointToIP(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errInvalidEndpoint
	}
	for _, scheme := range []string{"http://", "https://"} {
		if len(endpoint) > len(scheme) && endpoint[:len(scheme)] == scheme {
			endpoint = endpoint[len(scheme):]
			break
		}
	}
	if u, err := url.Parse("http://" + endpoint); err == nil && u.Host != "" {
		host := u.Hostname()
		if host != "" {
			return host, nil
		}
	}
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h, nil
	}
	return endpoint, nil
}

type endpointError string

func (e endpointError) Error() string { return string(e) }

const errInvalidEndpoint = endpointError("endpoint invalide")
