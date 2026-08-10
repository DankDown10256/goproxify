// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package agent gère les données opérationnelles remontées par les Agents.
package agent

import (
	"sync"
	"time"
)

// NodeInfo représente l'état courant d'un Agent.
type NodeInfo struct {
	NodeName          string    `json:"node_name"`
	Role              string    `json:"role"`
	Version           string    `json:"version"`
	Endpoint          string    `json:"endpoint"` // API interne :8001
	CPUPCT            float64   `json:"cpu_pct"`
	MemPCT            float64   `json:"mem_pct"`
	Status            string    `json:"status"`
	ContainerRuntimes []string  `json:"container_runtimes,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}

// NodeEvent représente un événement de cycle de vie ou de scaling.
type NodeEvent struct {
	ID          int64     `json:"id"`
	NodeName    string    `json:"node_name"`
	ContainerID string    `json:"container_id,omitempty"`
	EventType   string    `json:"event_type"`
	Detail      string    `json:"detail,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

const maxEvents = 500

// NodeStore conserve en mémoire l'état de tous les Agents enregistrés sur ce Core.
type NodeStore struct {
	mu     sync.RWMutex
	nodes  map[string]*NodeInfo // nodeName → info
	events []NodeEvent
	nextID int64
}

// NewNodeStore crée un NodeStore vide.
func NewNodeStore() *NodeStore {
	return &NodeStore{
		nodes: make(map[string]*NodeInfo),
	}
}

// Upsert met à jour ou crée l'entrée d'un Agent.
func (s *NodeStore) Upsert(n NodeInfo) {
	n.Status = "online"
	n.LastSeenAt = time.Now().UTC()
	s.mu.Lock()
	if existing, ok := s.nodes[n.NodeName]; ok && n.Endpoint == "" {
		n.Endpoint = existing.Endpoint
	}
	s.nodes[n.NodeName] = &n
	s.mu.Unlock()
}

// SetPending crée une entrée Agent en état "pending" (en attente d'approbation).
func (s *NodeStore) SetPending(agentID, agentName, version string) {
	n := NodeInfo{
		NodeName:   agentName,
		Role:       "agent",
		Version:    version,
		Status:     "pending",
		LastSeenAt: time.Now().UTC(),
	}
	s.mu.Lock()
	if existing, ok := s.nodes[agentName]; ok && existing.Status == "online" {
		// Ne pas écraser un agent déjà actif
		s.mu.Unlock()
		return
	}
	s.nodes[agentName] = &n
	s.mu.Unlock()
}

// MarkOffline passe tous les nœuds non vus depuis plus de threshold en "offline".
func (s *NodeStore) MarkOffline(threshold time.Duration) {
	now := time.Now().UTC()
	s.mu.Lock()
	for _, n := range s.nodes {
		if now.Sub(n.LastSeenAt) > threshold {
			n.Status = "offline"
		}
	}
	s.mu.Unlock()
}

// All retourne une copie de la liste des nœuds.
func (s *NodeStore) All() []NodeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NodeInfo, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, *n)
	}
	return out
}

// Get retourne le nœud par nom.
func (s *NodeStore) Get(name string) (NodeInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[name]
	if !ok {
		return NodeInfo{}, false
	}
	return *n, true
}

// RecordEvent enregistre un événement et expurge si > maxEvents.
// Retourne l'événement tel qu'enregistré (id + created_at renseignés).
func (s *NodeStore) RecordEvent(e NodeEvent) NodeEvent {
	s.mu.Lock()
	s.nextID++
	e.ID = s.nextID
	e.CreatedAt = time.Now().UTC()
	s.events = append(s.events, e)
	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
	}
	s.mu.Unlock()
	return e
}

// Events retourne les derniers événements (les plus récents en premier).
func (s *NodeStore) Events(limit int) []NodeEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.events)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]NodeEvent, limit)
	for i := 0; i < limit; i++ {
		out[i] = s.events[n-1-i]
	}
	return out
}
