// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// ApplyReport résume ce que ApplyToDB a changé.
type ApplyReport struct {
	Declared int `json:"declared"` // nœuds déclarés insérés ou mis à jour
	Removed  int `json:"removed"`  // nœuds déclarés supprimés (absents du fichier)
	Scopes   int `json:"scopes"`   // périmètres réalignés
	Domains  int `json:"domains"`  // domaines insérés ou mis à jour
}

// ApplyToDB aligne les tables dérivées (declared_nodes, token_scopes, domains) sur le fichier.
//
// Le fichier fait foi, mais un fichier qui ne liste aucun nœud (absent, vide) n'est pas
// considéré comme une déclaration : rien n'est supprimé (voir SeedFromDB pour l'amorçage).
// Les périmètres d'un nœud absents de son entrée ne sont réalignés que si elle en liste au moins un.
// Les domaines ne le sont que si le fichier en liste au moins un.
func (s *Store) ApplyToDB(ctx context.Context, db *sql.DB) (ApplyReport, error) {
	var rep ApplyReport
	s.mu.RLock()
	arch, err := s.readLocked()
	s.mu.RUnlock()
	if err != nil {
		return rep, err
	}
	if len(arch.Nodes) == 0 {
		return rep, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return rep, fmt.Errorf("archstore: apply begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	tokenIDs, err := idSet(ctx, tx, `SELECT id FROM tokens WHERE role='edge'`)
	if err != nil {
		return rep, err
	}

	// Nœuds déclarés : upsert de ceux du fichier, suppression des autres.
	wanted := map[string]bool{}
	for _, n := range arch.Nodes {
		if n.Role != "edge" && n.Role != "agent" {
			continue
		}
		// Un nœud sans config est un simple passerelle appairée (token) : il n'a pas de ligne declared_nodes.
		if !n.wizardDeclared() {
			continue
		}
		wanted[n.ID] = true
		cfg := compactJSON(n.Config)
		_, err := tx.ExecContext(ctx,
			`INSERT INTO declared_nodes(id, role, name, region, environment, config)
			 VALUES(?,?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET role=excluded.role, name=excluded.name,
			   region=excluded.region, environment=excluded.environment, config=excluded.config`,
			n.ID, n.Role, n.Name, n.Region, n.Environment, cfg)
		if err != nil {
			note(fmt.Errorf("declared_nodes %s: %w", n.ID, err))
			continue
		}
		rep.Declared++
	}
	existing, err := idSet(ctx, tx, `SELECT id FROM declared_nodes`)
	if err != nil {
		return rep, err
	}
	for id := range existing {
		if wanted[id] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM declared_nodes WHERE id=?`, id); err != nil {
			note(fmt.Errorf("declared_nodes delete %s: %w", id, err))
			continue
		}
		rep.Removed++
	}

	// Périmètres RBAC des passerelles appairées.
	for _, n := range arch.Nodes {
		if !tokenIDs[n.ID] || len(n.Scopes) == 0 {
			continue
		}
		keep := map[string]bool{}
		for _, sc := range n.Scopes {
			keep[sc.ID] = true
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO token_scopes(id, token_id, scope_type, scope_value) VALUES(?,?,?,?)`,
				sc.ID, n.ID, sc.Type, sc.Value); err != nil {
				note(fmt.Errorf("token_scopes %s: %w", sc.ID, err))
			}
		}
		cur, err := idSet(ctx, tx, `SELECT id FROM token_scopes WHERE token_id=?`, n.ID)
		if err != nil {
			return rep, err
		}
		for id := range cur {
			if keep[id] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM token_scopes WHERE id=?`, id); err != nil {
				note(fmt.Errorf("token_scopes delete %s: %w", id, err))
			}
		}
		rep.Scopes++
	}

	// Domaines.
	if len(arch.Domains) > 0 {
		keep := map[string]bool{}
		for _, d := range arch.Domains {
			keep[d.ID] = true
			creds := d.DNSCredentials
			if creds == "" {
				creds = "{}"
			}
			_, err := tx.ExecContext(ctx,
				`INSERT INTO domains(id, domain, edge_id, dns_provider, dns_credentials, cert_method,
				   delegated_to_edge_id, delegated_endpoint, delegation_mode)
				 VALUES(?,?,?,?,?,?,?,?,?)
				 ON CONFLICT(id) DO UPDATE SET domain=excluded.domain, edge_id=excluded.edge_id,
				   dns_provider=excluded.dns_provider, dns_credentials=excluded.dns_credentials,
				   cert_method=excluded.cert_method, delegated_to_edge_id=excluded.delegated_to_edge_id,
				   delegated_endpoint=excluded.delegated_endpoint, delegation_mode=excluded.delegation_mode`,
				d.ID, d.Domain, d.EdgeID, d.DNSProvider, creds, d.CertMethod,
				d.DelegatedToEdgeID, d.DelegatedEndpoint, d.DelegationMode)
			if err != nil {
				note(fmt.Errorf("domains %s: %w", d.ID, err))
				continue
			}
			rep.Domains++
		}
		cur, err := idSet(ctx, tx, `SELECT id FROM domains`)
		if err != nil {
			return rep, err
		}
		for id := range cur {
			if !keep[id] {
				if _, err := tx.ExecContext(ctx, `DELETE FROM domains WHERE id=?`, id); err != nil {
					note(fmt.Errorf("domains delete %s: %w", id, err))
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return rep, fmt.Errorf("archstore: apply commit: %w", err)
	}
	return rep, errors.Join(errs...)
}

// SeedFromDB crée le fichier depuis la base, une seule fois : il ne fait rien si le fichier
// liste déjà un nœud ou un domaine. Il ne réécrit jamais un fichier existant.
func (s *Store) SeedFromDB(ctx context.Context, db *sql.DB) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.readLocked()
	if err != nil {
		return err
	}
	if len(cur.Nodes) > 0 || len(cur.Domains) > 0 {
		return nil
	}
	arch, err := buildFromDB(ctx, db)
	if err != nil {
		return err
	}
	if len(arch.Nodes) == 0 && len(arch.Domains) == 0 {
		return nil
	}
	return s.writeLocked(arch)
}

// SyncDomainsFromDB recopie les domaines de la base dans le fichier, sans toucher aux nœuds.
// Les domaines restent pilotés par la base tant que leurs handlers n'écrivent pas le fichier d'abord.
func (s *Store) SyncDomainsFromDB(ctx context.Context, db *sql.DB) error {
	domains, err := loadDomains(ctx, db)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	arch.Domains = domains
	return s.writeLocked(arch)
}

func buildFromDB(ctx context.Context, db *sql.DB) (*Architecture, error) {
	nodes := []NodeEntry{}

	rows, err := db.QueryContext(ctx,
		`SELECT id, role, name, COALESCE(region,''), COALESCE(environment,''), COALESCE(config,'{}')
		 FROM declared_nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n NodeEntry
		var cfg string
		if rows.Scan(&n.ID, &n.Role, &n.Name, &n.Region, &n.Environment, &cfg) == nil {
			n.Config = json.RawMessage(cfg)
			nodes = append(nodes, n)
		}
	}
	rows.Close()

	seen := map[string]bool{}
	for _, n := range nodes {
		seen[n.ID] = true
	}
	trows, err := db.QueryContext(ctx,
		`SELECT id, node_name, COALESCE(node_endpoint,''), COALESCE(rbac_role,'admin')
		 FROM tokens WHERE role='edge' AND revoked=0`)
	if err == nil {
		for trows.Next() {
			var id, name, ep, rbac string
			if trows.Scan(&id, &name, &ep, &rbac) == nil && !seen[id] {
				nodes = append(nodes, NodeEntry{ID: id, Role: "edge", Name: name, Endpoint: ep, RBACRole: rbac})
				seen[id] = true
			}
		}
		trows.Close()
	}

	idx := map[string]int{}
	for i, n := range nodes {
		idx[n.ID] = i
	}
	srows, err := db.QueryContext(ctx, `SELECT id, token_id, scope_type, scope_value FROM token_scopes ORDER BY token_id`)
	if err == nil {
		for srows.Next() {
			var sid, tid, stype, sval string
			if srows.Scan(&sid, &tid, &stype, &sval) == nil {
				if i, ok := idx[tid]; ok {
					nodes[i].Scopes = append(nodes[i].Scopes, ScopeEntry{ID: sid, Type: stype, Value: sval})
				}
			}
		}
		srows.Close()
	}

	domains, err := loadDomains(ctx, db)
	if err != nil {
		return nil, err
	}
	return &Architecture{SchemaVersion: schemaVersion, Nodes: nodes, Domains: domains}, nil
}

func loadDomains(ctx context.Context, db *sql.DB) ([]DomainEntry, error) {
	drows, err := db.QueryContext(ctx,
		`SELECT id, domain, edge_id, dns_provider, COALESCE(dns_credentials,'{}'),
		        cert_method, delegated_to_edge_id, delegated_endpoint, delegation_mode
		 FROM domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer drows.Close()
	var domains []DomainEntry
	for drows.Next() {
		var d DomainEntry
		if drows.Scan(&d.ID, &d.Domain, &d.EdgeID, &d.DNSProvider, &d.DNSCredentials,
			&d.CertMethod, &d.DelegatedToEdgeID, &d.DelegatedEndpoint, &d.DelegationMode) == nil {
			domains = append(domains, d)
		}
	}
	return domains, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func idSet(ctx context.Context, q queryer, query string, args ...any) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func compactJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil || buf.Len() == 0 {
		return "{}"
	}
	return buf.String()
}
