// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package archstore persiste le référentiel architecture (nœuds déclarés, scopes RBAC)
// dans architecture.json — source de vérité de l'architecture, la base SQLite n'en est
// qu'un cache dérivé.
//
// Flux : mutation → écriture du fichier (version précédente conservée) → ApplyToDB.
// Au démarrage : ApplyToDB aligne la base sur le fichier ; SeedFromDB ne sert qu'à
// créer un premier fichier depuis une base existante.
package archstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	schemaVersion = 1
	filename      = "architecture.json"
)

// ScopeEntry est un périmètre RBAC attaché à un nœud passerelle.
type ScopeEntry struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// NodeEntry décrit un nœud de l'architecture (Passerelle ou Agent).
// Ne contient pas de secrets — les tokens sealed sont dans node_tokens.json.
type NodeEntry struct {
	ID          string          `json:"id"`
	Role        string          `json:"role"`
	Name        string          `json:"name"`
	Endpoint    string          `json:"endpoint,omitempty"`
	RBACRole    string          `json:"rbac_role,omitempty"`
	Region      string          `json:"region,omitempty"`
	Environment string          `json:"environment,omitempty"`
	Config      json.RawMessage `json:"config,omitempty"` // config du wizard déclaré
	Scopes      []ScopeEntry    `json:"scopes,omitempty"`
}

// wizardDeclared : le nœud vient de l'assistant Infrastructure (il porte sa config) ;
// il vit dans la table declared_nodes, qu'il soit connecté ou non.
func (n NodeEntry) wizardDeclared() bool { return len(n.Config) > 0 }

// ControlEndpoint retourne l'adresse que l'Admin doit joindre pour cette passerelle : `endpoint` s'il est
// posé, sinon `reachable_host` de la config du wizard (host:port du hub de la passerelle). Vide si inconnue.
func (n NodeEntry) ControlEndpoint() string {
	if n.Role != "edge" {
		return ""
	}
	if n.Endpoint != "" {
		return n.Endpoint
	}
	var cfg struct {
		ReachableHost string `json:"reachable_host"`
	}
	if len(n.Config) == 0 || json.Unmarshal(n.Config, &cfg) != nil || cfg.ReachableHost == "" {
		return ""
	}
	if strings.Contains(cfg.ReachableHost, "://") {
		return cfg.ReachableHost
	}
	return "http://" + cfg.ReachableHost
}

// DomainEntry décrit un domaine géré (TLS, ACME, délégation inter-passerelle).
type DomainEntry struct {
	ID                string `json:"id"`
	Domain            string `json:"domain"`
	EdgeID            string `json:"edge_id"`
	DNSProvider       string `json:"dns_provider"`
	DNSCredentials    string `json:"dns_credentials,omitempty"` // chiffré côté DB, répliqué tel quel
	CertMethod        string `json:"cert_method"`
	DelegatedToEdgeID string `json:"delegated_to_edge_id,omitempty"`
	DelegatedEndpoint string `json:"delegated_endpoint,omitempty"`
	DelegationMode    string `json:"delegation_mode,omitempty"`
}

// Architecture est la racine du fichier JSON.
type Architecture struct {
	SchemaVersion int           `json:"schema_version"`
	Nodes         []NodeEntry   `json:"nodes"`
	Domains       []DomainEntry `json:"domains,omitempty"`
}

// Store lit et écrit architecture.json de façon atomique.
type Store struct {
	mu   sync.RWMutex
	path string
}

// New crée un Store ciblant <dir>/architecture.json.
func New(dir string) *Store {
	return &Store{path: filepath.Join(dir, filename)}
}

// Path retourne le chemin absolu du fichier.
func (s *Store) Path() string { return s.path }

// List retourne tous les nœuds du fichier. Retourne une liste vide si le fichier n'existe pas.
func (s *Store) List() ([]NodeEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	arch, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	return arch.Nodes, nil
}

// EdgeEndpoints retourne les nœuds passerelle du fichier qui portent un endpoint joignable par l'Admin.
func (s *Store) EdgeEndpoints() ([]NodeEntry, error) {
	nodes, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []NodeEntry
	for _, n := range nodes {
		if ep := n.ControlEndpoint(); ep != "" && n.Name != "" {
			n.Endpoint = ep
			out = append(out, n)
		}
	}
	return out, nil
}

// Upsert insère ou met à jour un nœud (identifié par ID). Les périmètres et la config
// du wizard déjà présents sont conservés si le nouvel enregistrement n'en porte pas.
func (s *Store) Upsert(node NodeEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID == node.ID {
			if len(node.Scopes) == 0 {
				node.Scopes = n.Scopes
			}
			if len(node.Config) == 0 {
				node.Config = n.Config
			}
			if node.Region == "" {
				node.Region = n.Region
			}
			if node.Environment == "" {
				node.Environment = n.Environment
			}
			arch.Nodes[i] = node
			return s.writeLocked(arch)
		}
	}
	arch.Nodes = append(arch.Nodes, node)
	return s.writeLocked(arch)
}

// Delete supprime un nœud par ID. Ne retourne pas d'erreur si absent.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	out := arch.Nodes[:0]
	for _, n := range arch.Nodes {
		if n.ID != id {
			out = append(out, n)
		}
	}
	arch.Nodes = out
	return s.writeLocked(arch)
}

// AddScope ajoute un scope à un nœud existant (no-op si déjà présent).
func (s *Store) AddScope(nodeID string, sc ScopeEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID != nodeID {
			continue
		}
		for _, existing := range n.Scopes {
			if existing.Type == sc.Type && existing.Value == sc.Value {
				return nil
			}
		}
		arch.Nodes[i].Scopes = append(arch.Nodes[i].Scopes, sc)
		return s.writeLocked(arch)
	}
	return nil
}

// RemoveScope supprime un scope d'un nœud par ID de scope.
func (s *Store) RemoveScope(nodeID, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID != nodeID {
			continue
		}
		filtered := n.Scopes[:0]
		for _, sc := range n.Scopes {
			if sc.ID != scopeID {
				filtered = append(filtered, sc)
			}
		}
		arch.Nodes[i].Scopes = filtered
		return s.writeLocked(arch)
	}
	return nil
}

// UpsertEndpoint met à jour l'endpoint et le rbac_role d'un nœud (par ID).
// Utilisé quand une passerelle se reconnecte et met à jour son endpoint en DB.
func (s *Store) UpsertEndpoint(nodeID, endpoint, rbacRole string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID == nodeID {
			// Pas de doublon : l'adresse déjà portée par reachable_host (wizard) n'est pas recopiée.
			if endpoint != "" && (n.Endpoint != "" || n.ControlEndpoint() != endpoint) {
				arch.Nodes[i].Endpoint = endpoint
			}
			if rbacRole != "" {
				arch.Nodes[i].RBACRole = rbacRole
			}
			return s.writeLocked(arch)
		}
	}
	return nil
}

// --- helpers internes ---

func (s *Store) readLocked() (*Architecture, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Architecture{SchemaVersion: schemaVersion, Nodes: []NodeEntry{}}, nil
		}
		return nil, fmt.Errorf("archstore: read %s: %w", s.path, err)
	}
	var arch Architecture
	if err := json.Unmarshal(data, &arch); err != nil {
		return nil, fmt.Errorf("archstore: parse %s: %w", s.path, err)
	}
	if arch.Nodes == nil {
		arch.Nodes = []NodeEntry{}
	}
	for i := range arch.Nodes {
		if arch.Nodes[i].Role == "core" {
			arch.Nodes[i].Role = "edge"
		}
	}
	return &arch, nil
}

func (s *Store) writeLocked(arch *Architecture) error {
	if arch.SchemaVersion == 0 {
		arch.SchemaVersion = schemaVersion
	}
	data, err := json.MarshalIndent(arch, "", "  ")
	if err != nil {
		return fmt.Errorf("archstore: marshal: %w", err)
	}
	data = append(data, '\n')
	if err := s.snapshotLocked(data); err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("archstore: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-arch-*")
	if err != nil {
		return fmt.Errorf("archstore: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("archstore: write: %w", err)
	}
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("archstore: close: %w", err)
	}
	_ = os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("archstore: rename: %w", err)
	}
	return nil
}

// EnsureEdge garantit qu'une passerelle connectée figure dans le fichier, sans jamais dédoubler :
// un nœud déjà présent (même ID) voit son endpoint/rôle mis à jour, une passerelle déjà décrit
// sous un autre ID mais le même nom (nœud du wizard) est laissé tel quel.
func (s *Store) EnsureEdge(id, name, endpoint, rbacRole string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID != id {
			continue
		}
		changed := false
		if endpoint != "" && (n.Endpoint != "" || n.ControlEndpoint() != endpoint) && n.Endpoint != endpoint {
			arch.Nodes[i].Endpoint = endpoint
			changed = true
		}
		if rbacRole != "" && n.RBACRole != rbacRole {
			arch.Nodes[i].RBACRole = rbacRole
			changed = true
		}
		if !changed {
			return nil
		}
		return s.writeLocked(arch)
	}
	for _, n := range arch.Nodes {
		if n.Role == "edge" && n.Name == name {
			return nil
		}
	}
	arch.Nodes = append(arch.Nodes, NodeEntry{ID: id, Role: "edge", Name: name, Endpoint: endpoint, RBACRole: rbacRole})
	return s.writeLocked(arch)
}
