// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+name+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, q := range []string{
		`CREATE TABLE tokens (id TEXT PRIMARY KEY, role TEXT, node_name TEXT, node_endpoint TEXT, rbac_role TEXT, revoked INTEGER DEFAULT 0)`,
		`CREATE TABLE declared_nodes (id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('core','agent')), name TEXT NOT NULL,
			region TEXT NOT NULL DEFAULT '', environment TEXT NOT NULL DEFAULT '', config TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE token_scopes (id TEXT PRIMARY KEY, token_id TEXT NOT NULL, scope_type TEXT NOT NULL, scope_value TEXT NOT NULL,
			UNIQUE(token_id, scope_type, scope_value))`,
		`CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT UNIQUE NOT NULL, core_id TEXT NOT NULL DEFAULT '',
			dns_provider TEXT NOT NULL DEFAULT 'none', dns_credentials TEXT NOT NULL DEFAULT '{}', cert_method TEXT NOT NULL DEFAULT 'http',
			delegated_to_core_id TEXT NOT NULL DEFAULT '', delegated_endpoint TEXT NOT NULL DEFAULT '', delegation_mode TEXT NOT NULL DEFAULT 'passthrough')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func count(t *testing.T, db *sql.DB, q string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApplyToDBFileIsTheReference(t *testing.T) {
	db := newTestDB(t, "apply_ref")
	s := New(t.TempDir())
	ctx := context.Background()

	// La base contient un nœud que le fichier ne connaît pas : il doit disparaître.
	_, _ = db.Exec(`INSERT INTO declared_nodes(id, role, name) VALUES('dn_old','agent','ancien')`)
	_, _ = db.Exec(`INSERT INTO tokens(id, role, node_name, node_endpoint) VALUES('c1','core','frontal','http://goproxify-core:8000')`)
	_, _ = db.Exec(`INSERT INTO token_scopes(id, token_id, scope_type, scope_value) VALUES('s_old','c1','domain','vieux.fr')`)

	for _, n := range []NodeEntry{
		{ID: "dn_b", Role: "core", Name: "backup", Config: json.RawMessage(`{"reachable_host": "192.0.2.20:8000", "cluster": true}`)},
		{ID: "c1", Role: "core", Name: "frontal", Endpoint: "http://goproxify-core:8000",
			Scopes: []ScopeEntry{{ID: "s_new", Type: "domain", Value: "nouveau.fr"}}},
	} {
		if err := s.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := s.ApplyToDB(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Declared != 1 || rep.Removed != 1 {
		t.Fatalf("rapport %+v", rep)
	}
	if count(t, db, `SELECT COUNT(*) FROM declared_nodes WHERE id='dn_old'`) != 0 {
		t.Fatal("nœud absent du fichier : doit être supprimé de la base")
	}
	if count(t, db, `SELECT COUNT(*) FROM declared_nodes WHERE id='dn_b'`) != 1 {
		t.Fatal("nœud du wizard : doit être dans la base")
	}
	if count(t, db, `SELECT COUNT(*) FROM declared_nodes WHERE id='c1'`) != 0 {
		t.Fatal("Core appairé sans config : pas de ligne declared_nodes")
	}
	if count(t, db, `SELECT COUNT(*) FROM token_scopes WHERE id='s_old'`) != 0 || count(t, db, `SELECT COUNT(*) FROM token_scopes WHERE id='s_new'`) != 1 {
		t.Fatal("les périmètres doivent suivre le fichier")
	}
	var cfg string
	_ = db.QueryRow(`SELECT config FROM declared_nodes WHERE id='dn_b'`).Scan(&cfg)
	if cfg != `{"reachable_host":"192.0.2.20:8000","cluster":true}` {
		t.Fatalf("config compactée attendue, reçu %s", cfg)
	}
}

func TestApplyToDBIgnoresEmptyFile(t *testing.T) {
	db := newTestDB(t, "apply_empty")
	_, _ = db.Exec(`INSERT INTO declared_nodes(id, role, name) VALUES('dn_keep','core','garde')`)
	rep, err := New(t.TempDir()).ApplyToDB(context.Background(), db)
	if err != nil || rep != (ApplyReport{}) {
		t.Fatalf("rapport %+v err %v", rep, err)
	}
	if count(t, db, `SELECT COUNT(*) FROM declared_nodes`) != 1 {
		t.Fatal("un fichier vide ne doit rien supprimer")
	}
}

func TestSeedFromDBNeverOverwrites(t *testing.T) {
	db := newTestDB(t, "seed")
	ctx := context.Background()
	_, _ = db.Exec(`INSERT INTO declared_nodes(id, role, name, config) VALUES('dn_a','core','a','{"x":1}')`)

	s := New(t.TempDir())
	if err := s.SeedFromDB(ctx, db); err != nil {
		t.Fatal(err)
	}
	nodes, _ := s.List()
	if len(nodes) != 1 || nodes[0].ID != "dn_a" {
		t.Fatalf("amorçage attendu depuis la base, reçu %+v", nodes)
	}

	_, _ = db.Exec(`INSERT INTO declared_nodes(id, role, name) VALUES('dn_b','core','b')`)
	if err := s.SeedFromDB(ctx, db); err != nil {
		t.Fatal(err)
	}
	if nodes, _ = s.List(); len(nodes) != 1 {
		t.Fatalf("un fichier existant ne doit jamais être réécrit depuis la base, reçu %+v", nodes)
	}
}

func TestSyncDomainsFromDBKeepsNodes(t *testing.T) {
	db := newTestDB(t, "sync_domains")
	_, _ = db.Exec(`INSERT INTO domains(id, domain) VALUES('d1','exemple.fr')`)
	s := New(t.TempDir())
	if err := s.Upsert(NodeEntry{ID: "n1", Role: "core", Name: "frontal", Endpoint: "http://c:8000"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncDomainsFromDB(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	nodes, _ := s.List()
	if len(nodes) != 1 || nodes[0].ID != "n1" {
		t.Fatalf("les nœuds doivent rester intacts, reçu %+v", nodes)
	}
	data, _ := os.ReadFile(s.Path())
	var arch Architecture
	_ = json.Unmarshal(data, &arch)
	if len(arch.Domains) != 1 || arch.Domains[0].Domain != "exemple.fr" {
		t.Fatalf("domaines: %+v", arch.Domains)
	}
}

func TestVersionsKeepPreviousFileAndRestoreIsReversible(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Upsert(NodeEntry{ID: "a", Role: "core", Name: "un", Endpoint: "http://un:8000"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Versions(); len(v) != 0 {
		t.Fatalf("première écriture : rien à conserver, reçu %v", v)
	}
	if err := s.Upsert(NodeEntry{ID: "b", Role: "core", Name: "deux", Endpoint: "http://deux:8000"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions()
	if err != nil || len(vs) != 2 {
		t.Fatalf("2 versions attendues, reçu %v err %v", vs, err)
	}

	// vs[1] = la plus ancienne = fichier avec seulement « a ».
	if err := s.Restore(vs[1].Name); err != nil {
		t.Fatal(err)
	}
	nodes, _ := s.List()
	if len(nodes) != 1 || nodes[0].ID != "a" {
		t.Fatalf("restauration : attendu le seul nœud a, reçu %+v", nodes)
	}
	after, _ := s.Versions()
	if len(after) != 3 {
		t.Fatalf("la restauration doit conserver l'état remplacé (3 versions), reçu %d", len(after))
	}
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	s := New(t.TempDir())
	for _, name := range []string{"../architecture.json", "architecture-1.json", "", `..\x`, "architecture-20260101T000000000000000Z.json/../../x"} {
		if err := s.Restore(name); err == nil {
			t.Errorf("Restore(%q) devrait échouer", name)
		}
	}
}

func TestVersionsArePruned(t *testing.T) {
	s := New(t.TempDir())
	for i := 0; i < maxVersions+8; i++ {
		if err := s.Upsert(NodeEntry{ID: "a", Role: "core", Name: "n", Endpoint: fmt.Sprintf("http://n:%d", 8000+i)}); err != nil {
			t.Fatal(err)
		}
	}
	vs, _ := s.Versions()
	if len(vs) > maxVersions {
		t.Fatalf("%d versions conservées, plafond %d", len(vs), maxVersions)
	}
	entries, _ := os.ReadDir(filepath.Join(filepath.Dir(s.Path()), versionsDirName))
	if len(entries) != len(vs) {
		t.Fatalf("dossier et liste divergent: %d vs %d", len(entries), len(vs))
	}
}

func TestControlEndpointPrefersEndpointThenReachableHost(t *testing.T) {
	cases := []struct {
		n    NodeEntry
		want string
	}{
		{NodeEntry{Role: "core", Endpoint: "http://goproxify-core:8000", Config: json.RawMessage(`{"reachable_host":"192.0.2.4:8000"}`)}, "http://goproxify-core:8000"},
		{NodeEntry{Role: "core", Config: json.RawMessage(`{"reachable_host":"192.0.2.91:8000"}`)}, "http://192.0.2.91:8000"},
		{NodeEntry{Role: "core", Config: json.RawMessage(`{"reachable_host":"https://c.example.com:8000"}`)}, "https://c.example.com:8000"},
		{NodeEntry{Role: "core", Config: json.RawMessage(`{"reachable_host":""}`)}, ""},
		{NodeEntry{Role: "core"}, ""},
		{NodeEntry{Role: "agent", Config: json.RawMessage(`{"reachable_host":"192.0.2.9:1"}`)}, ""},
	}
	for i, tc := range cases {
		if got := tc.n.ControlEndpoint(); got != tc.want {
			t.Errorf("cas %d: %q, attendu %q", i, got, tc.want)
		}
	}
}

func TestUpsertEndpointDoesNotDuplicateReachableHost(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Upsert(NodeEntry{ID: "dn_b", Role: "core", Name: "backup",
		Config: json.RawMessage(`{"reachable_host":"192.0.2.91:8000"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint("dn_b", "http://192.0.2.91:8000", "admin"); err != nil {
		t.Fatal(err)
	}
	nodes, _ := s.List()
	if nodes[0].Endpoint != "" {
		t.Fatalf("endpoint recopié depuis reachable_host: %q", nodes[0].Endpoint)
	}
	// une adresse différente (ex. réseau Docker interne) reste écrite : ce n'est pas un doublon
	if err := s.UpsertEndpoint("dn_b", "http://goproxify-core:8000", ""); err != nil {
		t.Fatal(err)
	}
	if nodes, _ = s.List(); nodes[0].Endpoint != "http://goproxify-core:8000" {
		t.Fatalf("endpoint différent attendu, reçu %q", nodes[0].Endpoint)
	}
}

func TestEnsureCoreNeverDuplicates(t *testing.T) {
	s := New(t.TempDir())
	// nœud du wizard sans endpoint : reste tel quel quand un token du même nom se crée sous un autre ID
	if err := s.Upsert(NodeEntry{ID: "dn_b", Role: "core", Name: "backup",
		Config: json.RawMessage(`{"reachable_host":"192.0.2.91:8000"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureCore("tok-1", "backup", "http://192.0.2.91:8000", "admin"); err != nil {
		t.Fatal(err)
	}
	// Core inconnu : ajouté une fois, puis idempotent
	for i := 0; i < 3; i++ {
		if err := s.EnsureCore("c-a", "core-a", "http://core-a:8000", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	nodes, _ := s.List()
	if len(nodes) != 2 || nodes[0].ID != "dn_b" || nodes[1].ID != "c-a" {
		t.Fatalf("attendu dn_b et c-a, reçu %+v", nodes)
	}
	// même ID que le nœud du wizard et même adresse que reachable_host : pas d'endpoint recopié
	if err := s.EnsureCore("dn_b", "backup", "http://192.0.2.91:8000", "admin"); err != nil {
		t.Fatal(err)
	}
	if nodes, _ = s.List(); nodes[0].Endpoint != "" || nodes[0].RBACRole != "admin" {
		t.Fatalf("pas de doublon d'adresse attendu, reçu %+v", nodes[0])
	}
	// une réécriture identique ne crée pas de nouvelle version
	before, _ := s.Versions()
	_ = s.EnsureCore("c-a", "core-a", "http://core-a:8000", "admin")
	if after, _ := s.Versions(); len(after) != len(before) {
		t.Fatalf("aucune version attendue pour un contenu inchangé (%d → %d)", len(before), len(after))
	}
}
