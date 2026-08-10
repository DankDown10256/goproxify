// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AgentInfo décrit un Agent en attente d'approbation ou actif (vu via WS Core→Admin).
type AgentInfo struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Status   string    `json:"status"` // "pending" | "approved"
	SeenAt   time.Time `json:"seen_at"`
}

// AgentApprover est implémenté par corews.Manager pour approuver un Agent.
type AgentApprover interface {
	ApproveAgent(ctx interface{}, agentID string) error
}

// AgentStore maintient un registre en mémoire des Agents vus via WS.
type AgentStore struct {
	mu     sync.RWMutex
	agents map[string]*AgentInfo
}

// NewAgentStore crée un nouveau registre d'agents.
func NewAgentStore() *AgentStore {
	return &AgentStore{agents: make(map[string]*AgentInfo)}
}

// Upsert ajoute ou met à jour un Agent.
func (s *AgentStore) Upsert(id, name, version, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[id] = &AgentInfo{
		ID:      id,
		Name:    name,
		Version: version,
		Status:  status,
		SeenAt:  time.Now(),
	}
}

// List retourne tous les agents connus.
func (s *AgentStore) List() []AgentInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, *a)
	}
	return out
}

// AgentApproveFunc est la fonction qui, côté Admin, envoie approve_agent aux Cores via WS.
type AgentApproveFunc func(agentID string)

// AgentRevokeFunc envoie revoke_agent aux Cores via WS.
type AgentRevokeFunc func(agentID string)

// AgentsHandler gère la liste et l'approbation des Agents.
type AgentsHandler struct {
	Log      *slog.Logger
	Store    *AgentStore
	OnApprove AgentApproveFunc // appelé quand l'opérateur approuve un Agent
	OnRevoke  AgentRevokeFunc  // appelé quand l'opérateur révoque un Agent
}

func (h *AgentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id != "" && action == "approve":
		h.approve(w, r, id)
	case r.Method == http.MethodPost && id != "" && action == "revoke":
		h.revoke(w, r, id)
	case r.Method == http.MethodDelete && id != "" && action == "":
		h.revoke(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *AgentsHandler) list(w http.ResponseWriter, r *http.Request) {
	agents := h.Store.List()
	if agents == nil {
		agents = []AgentInfo{}
	}
	jsonOK(w, agents)
}

func (h *AgentsHandler) approve(w http.ResponseWriter, r *http.Request, agentID string) {
	if h.OnApprove != nil {
		h.OnApprove(agentID)
		h.Store.Upsert(agentID, agentID, "", "approved")
		h.Log.Info("agent: approbation envoyée aux Cores", "agent", agentID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"status":   "approved",
		"agent_id": agentID,
	})
}

func (h *AgentsHandler) revoke(w http.ResponseWriter, r *http.Request, agentID string) {
	if h.OnRevoke != nil {
		h.OnRevoke(agentID)
	}
	h.Store.Upsert(agentID, agentID, "", "revoked")
	h.Log.Info("agent: révocation envoyée aux Cores", "agent", agentID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"status":   "revoked",
		"agent_id": agentID,
	})
}
