// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"sync"
)

// AuthProvider est un fournisseur d'authentification SSO/OIDC stocké dans le Core.
// Les routes le référencent par ID via AuthProviderID.
type AuthProvider struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Type   string          `json:"type"`   // authentik | authelia | pocket_id | oidc | basic | forward
	Config json.RawMessage `json:"config"` // structure dépend du type
}

// AuthProviderStore conserve les fournisseurs d'authentification en mémoire.
type AuthProviderStore struct {
	mu        sync.RWMutex
	providers map[string]*AuthProvider
}

func NewAuthProviderStore() *AuthProviderStore {
	return &AuthProviderStore{providers: make(map[string]*AuthProvider)}
}

// Replace remplace atomiquement tous les fournisseurs.
func (s *AuthProviderStore) Replace(list []*AuthProvider) {
	m := make(map[string]*AuthProvider, len(list))
	for _, p := range list {
		m[p.ID] = p
	}
	s.mu.Lock()
	s.providers = m
	s.mu.Unlock()
}

// Get retourne un fournisseur par ID ou par nom (labels Docker goproxify.auth_provider).
func (s *AuthProviderStore) Get(idOrName string) (*AuthProvider, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.providers[idOrName]; ok {
		return p, true
	}
	for _, p := range s.providers {
		if p.Name == idOrName {
			return p, true
		}
	}
	return nil, false
}

// All retourne tous les fournisseurs.
func (s *AuthProviderStore) All() []*AuthProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*AuthProvider, 0, len(s.providers))
	for _, p := range s.providers {
		list = append(list, p)
	}
	return list
}

// Len retourne le nombre de fournisseurs.
func (s *AuthProviderStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.providers)
}
