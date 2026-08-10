// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"sync"
)

// SnippetType correspond aux types supportés par l'interface Admin.
type SnippetType string

const (
	SnippetIPFilter  SnippetType = "ip_filter"
	SnippetRateLimit SnippetType = "rate_limit"
	SnippetCORS      SnippetType = "cors"
	SnippetHeaders   SnippetType = "headers"
	SnippetGeoIP     SnippetType = "geo_ip"
	SnippetTLS       SnippetType = "tls"
	SnippetBot       SnippetType = "bot"
	SnippetWAF       SnippetType = "waf"
)

// Snippet est un bloc de configuration réutilisable stocké dans le Core.
type Snippet struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Type   SnippetType     `json:"type"`
	Config json.RawMessage `json:"config"`
}

// SnippetStore conserve les snippets en mémoire.
type SnippetStore struct {
	mu       sync.RWMutex
	snippets map[string]*Snippet
}

func NewSnippetStore() *SnippetStore {
	return &SnippetStore{snippets: make(map[string]*Snippet)}
}

// Replace remplace atomiquement tous les snippets.
func (s *SnippetStore) Replace(list []*Snippet) {
	m := make(map[string]*Snippet, len(list))
	for _, sn := range list {
		m[sn.ID] = sn
	}
	s.mu.Lock()
	s.snippets = m
	s.mu.Unlock()
}

// Get retourne un snippet par ID ou par nom (labels Docker goproxify.snippets).
func (s *SnippetStore) Get(idOrName string) (*Snippet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sn, ok := s.snippets[idOrName]; ok {
		return sn, true
	}
	for _, sn := range s.snippets {
		if sn.Name == idOrName {
			return sn, true
		}
	}
	return nil, false
}

// All retourne tous les snippets.
func (s *SnippetStore) All() []*Snippet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*Snippet, 0, len(s.snippets))
	for _, sn := range s.snippets {
		list = append(list, sn)
	}
	return list
}

// Len retourne le nombre de snippets.
func (s *SnippetStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.snippets)
}
