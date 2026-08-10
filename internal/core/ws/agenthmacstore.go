// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// AgentHMACStore persiste les secrets HMAC des Agents approuvés sur disque.
// Permet aux Agents de se reconnecter sans nouveau JOIN_TOKEN après un redémarrage du Core.
type AgentHMACStore struct {
	mu   sync.RWMutex
	data map[string]string // agentID → hmac
	path string
}

// NewAgentHMACStore ouvre ou crée le store de HMACs agents.
func NewAgentHMACStore(path string) *AgentHMACStore {
	s := &AgentHMACStore{
		data: make(map[string]string),
		path: path,
	}
	s.load()
	return s
}

// Get retourne le HMAC stocké pour un agentID, ou ("", false) s'il n'existe pas.
func (s *AgentHMACStore) Get(agentID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[agentID]
	return v, ok
}

// Set stocke un HMAC et le persiste sur disque.
func (s *AgentHMACStore) Set(agentID, hmac string) error {
	s.mu.Lock()
	s.data[agentID] = hmac
	s.mu.Unlock()
	return s.save()
}

// Delete supprime le HMAC d'un Agent (ex: révocation).
func (s *AgentHMACStore) Delete(agentID string) error {
	s.mu.Lock()
	delete(s.data, agentID)
	s.mu.Unlock()
	return s.save()
}

func (s *AgentHMACStore) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var data map[string]string
	if err := json.Unmarshal(b, &data); err == nil {
		s.mu.Lock()
		s.data = data
		s.mu.Unlock()
	}
}

func (s *AgentHMACStore) save() error {
	s.mu.RLock()
	b, err := json.Marshal(s.data)
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("hmac store marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("hmac store mkdir: %w", err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("hmac store write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hmac store rename: %w", err)
	}
	return nil
}
