// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// JoinTokenStore enregistre les JOIN_TOKEN déjà consommés (usage unique).
// Persistance disque pour survivre aux redémarrages du Core.
type JoinTokenStore struct {
	mu   sync.Mutex
	data map[string]time.Time // sha256(token) → consumed_at
	path string
}

// NewJoinTokenStore ouvre ou crée le store des JOIN_TOKEN consommés.
func NewJoinTokenStore(path string) *JoinTokenStore {
	s := &JoinTokenStore{
		data: make(map[string]time.Time),
		path: path,
	}
	s.load()
	return s
}

// Consume marque un JOIN_TOKEN comme utilisé. Retourne une erreur s'il l'était déjà.
func (s *JoinTokenStore) Consume(rawToken string) error {
	if rawToken == "" {
		return fmt.Errorf("join token vide")
	}
	h := hashToken(rawToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.data[h]; used {
		return fmt.Errorf("join token déjà utilisé")
	}
	s.data[h] = time.Now().UTC()
	s.saveLocked()
	return nil
}

// IsUsed indique si le JOIN_TOKEN a déjà été consommé.
func (s *JoinTokenStore) IsUsed(rawToken string) bool {
	h := hashToken(rawToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, used := s.data[h]
	return used
}

func (s *JoinTokenStore) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range raw {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t = time.Now().UTC()
		}
		s.data[k] = t
	}
}

func (s *JoinTokenStore) saveLocked() {
	out := make(map[string]string, len(s.data))
	for k, v := range s.data {
		out[k] = v.UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	_ = os.WriteFile(s.path, b, 0600)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
