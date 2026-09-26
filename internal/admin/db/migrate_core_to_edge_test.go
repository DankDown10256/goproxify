// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrateCoreToEdge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE tokens (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, role TEXT NOT NULL, node_name TEXT NOT NULL, node_endpoint TEXT)`,
		`CREATE TABLE declared_nodes (id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('core','agent')), name TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}')`,
		`CREATE TABLE token_scopes (id TEXT PRIMARY KEY, token_id TEXT NOT NULL, scope_type TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','core')), scope_value TEXT NOT NULL)`,
		`CREATE TABLE security_threats (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, scenario TEXT NOT NULL DEFAULT '', core_name TEXT NOT NULL DEFAULT '', cvss_score REAL NOT NULL DEFAULT 0)`,
		`CREATE INDEX idx_threats_core ON security_threats (core_name)`,
		`INSERT INTO tokens VALUES ('t1','gpx_core_abc','core','core-a','http://c:8000')`,
		`INSERT INTO declared_nodes VALUES ('d1','core','core-b','{"target_core":"x","core_endpoint":"http://y"}')`,
		`INSERT INTO token_scopes VALUES ('s1','t1','core','core-a')`,
		`INSERT INTO security_threats (ip, core_name, cvss_score) VALUES ('1.2.3.4','core-a',7.5)`,
	} {
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	raw.Close()

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var role, node string
	if err := d.QueryRow(`SELECT role, node_name FROM tokens WHERE id='t1'`).Scan(&role, &node); err != nil || role != "edge" || node != "core-a" {
		t.Fatalf("tokens: role=%q node=%q err=%v", role, node, err)
	}
	var cfg string
	if err := d.QueryRow(`SELECT role, config FROM declared_nodes WHERE id='d1'`).Scan(&role, &cfg); err != nil || role != "edge" ||
		cfg != `{"target_edge":"x","edge_endpoint":"http://y"}` {
		t.Fatalf("declared_nodes: role=%q cfg=%q err=%v", role, cfg, err)
	}
	var scope string
	if err := d.QueryRow(`SELECT scope_type FROM token_scopes WHERE id='s1'`).Scan(&scope); err != nil || scope != "edge" {
		t.Fatalf("token_scopes: scope=%q err=%v", scope, err)
	}
	var name string
	var score float64
	if err := d.QueryRow(`SELECT edge_name, cvss_score FROM security_threats`).Scan(&name, &score); err != nil || name != "core-a" || score != 7.5 {
		t.Fatalf("security_threats: name=%q score=%v err=%v", name, score, err)
	}
	if _, err := d.Exec(`INSERT INTO token_scopes VALUES ('s2','t1','edge','core-z')`); err != nil {
		t.Fatalf("la contrainte CHECK doit accepter 'edge' : %v", err)
	}
	if _, err := d.Exec(`INSERT INTO token_scopes VALUES ('s3','t1','core','core-z')`); err == nil {
		t.Fatal("la contrainte CHECK ne doit plus accepter 'core'")
	}
}
