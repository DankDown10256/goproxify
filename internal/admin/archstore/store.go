// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package archstore persiste le référentiel architecture (nœuds déclarés, scopes RBAC)
// dans architecture.yaml — source de vérité indépendante de la base SQLite.
//
// Flux normal : mutations → écriture fichier + DB.
// Reprise DB vide : LoadIntoDB recharge le fichier en DB.
package archstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	schemaVersion = 1
	filename      = "architecture.yaml"
)

// ScopeEntry est un périmètre RBAC attaché à un nœud Core.
type ScopeEntry struct {
	ID    string `yaml:"id"`
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// NodeEntry décrit un nœud de l'architecture (Core ou Agent).
// Ne contient pas de secrets — les tokens sealed sont dans node_tokens.json.
type NodeEntry struct {
	ID          string       `yaml:"id"`
	Role        string       `yaml:"role"`
	Name        string       `yaml:"name"`
	Endpoint    string       `yaml:"endpoint,omitempty"`
	RBACRole    string       `yaml:"rbac_role,omitempty"`
	Region      string       `yaml:"region,omitempty"`
	Environment string       `yaml:"environment,omitempty"`
	Config      string       `yaml:"config,omitempty"` // JSON brut du wizard déclaré
	Scopes      []ScopeEntry `yaml:"scopes,omitempty"`
}

// Architecture est la racine du fichier YAML.
type Architecture struct {
	SchemaVersion int         `yaml:"schema_version"`
	Nodes         []NodeEntry `yaml:"nodes"`
}

// Store lit et écrit architecture.yaml de façon atomique.
type Store struct {
	mu   sync.RWMutex
	path string
}

// New crée un Store ciblant <dir>/architecture.yaml.
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

// Upsert insère ou met à jour un nœud (identifié par ID).
func (s *Store) Upsert(node NodeEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID == node.ID {
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
// Utilisé quand un Core se reconnecte et met à jour son endpoint en DB.
func (s *Store) UpsertEndpoint(nodeID, endpoint, rbacRole string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	for i, n := range arch.Nodes {
		if n.ID == nodeID {
			if endpoint != "" {
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

// LoadIntoDB ré-insère les nœuds du fichier dans la DB si les tables concernées
// sont vides (reprise après corruption).
func (s *Store) LoadIntoDB(ctx context.Context, db *sql.DB) error {
	nodes, err := s.List()
	if err != nil || len(nodes) == 0 {
		return err
	}

	// declared_nodes : restaurer uniquement si table vide.
	var dnCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM declared_nodes`).Scan(&dnCount)
	if dnCount == 0 {
		for _, n := range nodes {
			cfg := n.Config
			if cfg == "" {
				cfg = "{}"
			}
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO declared_nodes(id, role, name, region, environment, config)
				 VALUES(?,?,?,?,?,?)`,
				n.ID, n.Role, n.Name, n.Region, n.Environment, cfg)
		}
	}

	// token_scopes : restaurer uniquement si table vide.
	var scCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_scopes`).Scan(&scCount)
	if scCount == 0 {
		for _, n := range nodes {
			for _, sc := range n.Scopes {
				db.ExecContext(ctx, //nolint:errcheck
					`INSERT OR IGNORE INTO token_scopes(id, token_id, scope_type, scope_value)
					 VALUES(?,?,?,?)`,
					sc.ID, n.ID, sc.Type, sc.Value)
			}
		}
	}

	return nil
}

// SyncFromDB (re)construit le fichier depuis la DB — utile après import ou migration.
func (s *Store) SyncFromDB(ctx context.Context, db *sql.DB) error {
	var nodes []NodeEntry

	// Nœuds déclarés (wizard).
	rows, err := db.QueryContext(ctx,
		`SELECT id, role, name, COALESCE(region,''), COALESCE(environment,''), COALESCE(config,'{}')
		 FROM declared_nodes ORDER BY created_at`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n NodeEntry
			if rows.Scan(&n.ID, &n.Role, &n.Name, &n.Region, &n.Environment, &n.Config) == nil {
				nodes = append(nodes, n)
			}
		}
		rows.Close()
	}

	// Nœuds Core appairés (tokens) non encore dans declared_nodes.
	inNodes := map[string]bool{}
	for _, n := range nodes {
		inNodes[n.ID] = true
	}
	trows, err := db.QueryContext(ctx,
		`SELECT id, node_name, COALESCE(node_endpoint,''), COALESCE(rbac_role,'admin')
		 FROM tokens WHERE role='core' AND revoked=0`)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var id, name, ep, rbac string
			if trows.Scan(&id, &name, &ep, &rbac) == nil && !inNodes[id] {
				nodes = append(nodes, NodeEntry{
					ID: id, Role: "core", Name: name,
					Endpoint: ep, RBACRole: rbac,
				})
				inNodes[id] = true
			}
		}
		trows.Close()
	}

	// Scopes par nœud.
	idxNode := map[string]int{}
	for i, n := range nodes {
		idxNode[n.ID] = i
	}
	srows, err := db.QueryContext(ctx,
		`SELECT id, token_id, scope_type, scope_value FROM token_scopes ORDER BY token_id`)
	if err == nil {
		defer srows.Close()
		for srows.Next() {
			var sid, tid, stype, sval string
			if srows.Scan(&sid, &tid, &stype, &sval) == nil {
				if idx, ok := idxNode[tid]; ok {
					nodes[idx].Scopes = append(nodes[idx].Scopes, ScopeEntry{
						ID: sid, Type: stype, Value: sval,
					})
				}
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(&Architecture{SchemaVersion: schemaVersion, Nodes: nodes})
}

// --- helpers internes ---

func (s *Store) readLocked() (*Architecture, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Architecture{SchemaVersion: schemaVersion}, nil
		}
		return nil, fmt.Errorf("archstore: read %s: %w", s.path, err)
	}
	var arch Architecture
	if err := yaml.Unmarshal(data, &arch); err != nil {
		return nil, fmt.Errorf("archstore: parse %s: %w", s.path, err)
	}
	if arch.Nodes == nil {
		arch.Nodes = []NodeEntry{}
	}
	return &arch, nil
}

func (s *Store) writeLocked(arch *Architecture) error {
	if arch.SchemaVersion == 0 {
		arch.SchemaVersion = schemaVersion
	}
	data, err := yaml.Marshal(arch)
	if err != nil {
		return fmt.Errorf("archstore: marshal: %w", err)
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
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("archstore: rename: %w", err)
	}
	return nil
}
