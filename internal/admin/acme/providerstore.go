// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// ProviderEntry est un fournisseur DNS nommé persisté sur disque.
type ProviderEntry struct {
	ID     string            `yaml:"id"     json:"id"`
	Name   string            `yaml:"name"   json:"name"`
	Type   string            `yaml:"type"   json:"type"`
	Params map[string]string `yaml:"params" json:"params"`
}

// ProviderStore persiste les fournisseurs DNS nommés dans un fichier YAML.
type ProviderStore struct {
	path string
	mu   sync.RWMutex
}

// NewProviderStore crée un ProviderStore dont les données sont dans path.
func NewProviderStore(path string) *ProviderStore {
	return &ProviderStore{path: path}
}

func (s *ProviderStore) load() ([]ProviderEntry, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []ProviderEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("acme providers: parse yaml: %w", err)
	}
	return entries, nil
}

func (s *ProviderStore) save(entries []ProviderEntry) error {
	data, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

// List retourne tous les fournisseurs.
func (s *ProviderStore) List() ([]ProviderEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.load()
}

// Get retourne un fournisseur par ID.
func (s *ProviderStore) Get(id string) (*ProviderEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := s.load()
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].ID == id {
			return &entries[i], nil
		}
	}
	return nil, nil
}

// Create ajoute un fournisseur et retourne son ID.
func (s *ProviderStore) Create(name, dnsType string, params map[string]string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load()
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.Name == name {
			return "", fmt.Errorf("acme providers: nom %q déjà utilisé", name)
		}
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	if params == nil {
		params = map[string]string{}
	}
	entries = append(entries, ProviderEntry{ID: id, Name: name, Type: dnsType, Params: params})
	return id, s.save(entries)
}

// Update remplace name, type et params d'un fournisseur existant.
func (s *ProviderStore) Update(id, name, dnsType string, params map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load()
	if err != nil {
		return err
	}
	for i := range entries {
		if entries[i].ID == id {
			entries[i].Name = name
			entries[i].Type = dnsType
			if params != nil {
				entries[i].Params = params
			}
			return s.save(entries)
		}
	}
	return fmt.Errorf("acme providers: id %q introuvable", id)
}

// Delete supprime un fournisseur.
func (s *ProviderStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load()
	if err != nil {
		return err
	}
	n := len(entries)
	for i := range entries {
		if entries[i].ID == id {
			entries = append(entries[:i], entries[i+1:]...)
			break
		}
	}
	if len(entries) == n {
		return fmt.Errorf("acme providers: id %q introuvable", id)
	}
	return s.save(entries)
}
