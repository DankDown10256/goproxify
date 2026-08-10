// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	_ "modernc.org/sqlite"
)

func TestMigrateRBACGrants_BPrimeMixedTeam(t *testing.T) {
	db := openLegacyRBAC(t)
	defer db.Close()

	teamID := uuid.New().String()
	mustExec(t, db, `INSERT INTO teams (id, name) VALUES (?, ?)`, teamID, "Backend")
	mustExec(t, db, `INSERT INTO team_scopes (id, team_id, scope_type, scope_value) VALUES (?,?,?,?)`,
		uuid.New().String(), teamID, "domain", "*.api.io")
	mustExec(t, db, `INSERT INTO users (id, email, password_hash, role) VALUES ('op','op@t.local','x','operator')`)
	mustExec(t, db, `INSERT INTO users (id, email, password_hash, role) VALUES ('vw','vw@t.local','x','viewer')`)
	mustExec(t, db, `INSERT INTO team_members (team_id, user_id, role) VALUES (?,?,?)`, teamID, "op", "operator")
	mustExec(t, db, `INSERT INTO team_members (team_id, user_id, role) VALUES (?,?,?)`, teamID, "vw", "viewer")

	if err := admindb.MigrateRBACGrantsForTest(db); err != nil {
		t.Fatal(err)
	}

	var teams []string
	trows, err := db.Query(`SELECT name FROM teams ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for trows.Next() {
		var n string
		_ = trows.Scan(&n)
		teams = append(teams, n)
	}
	trows.Close()
	if len(teams) != 2 {
		t.Fatalf("attendu 2 équipes après scission, got %v", teams)
	}

	var writeMode string
	_ = db.QueryRow(`SELECT access_mode FROM team_scopes WHERE team_id=?`, teamID).Scan(&writeMode)
	if writeMode != "write" {
		t.Fatalf("équipe operators: mode=%q teams=%v", writeMode, teams)
	}

	var readTeamID, readName string
	err = db.QueryRow(`SELECT id, name FROM teams WHERE id != ?`, teamID).Scan(&readTeamID, &readName)
	if err != nil {
		t.Fatalf("équipe lecture introuvable: %v teams=%v", err, teams)
	}
	var readMode string
	_ = db.QueryRow(`SELECT access_mode FROM team_scopes WHERE team_id=?`, readTeamID).Scan(&readMode)
	if readMode != "read" {
		t.Fatalf("équipe %q: mode=%q", readName, readMode)
	}

	var roleCol int
	_ = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('team_members') WHERE name='role'`).Scan(&roleCol)
	if roleCol != 0 {
		t.Fatal("team_members.role doit avoir disparu")
	}

	var opRole, vwRole string
	_ = db.QueryRow(`SELECT role FROM users WHERE id='op'`).Scan(&opRole)
	_ = db.QueryRow(`SELECT role FROM users WHERE id='vw'`).Scan(&vwRole)
	if opRole != "user" || vwRole != "user" {
		t.Fatalf("roles normalisés: op=%q vw=%q", opRole, vwRole)
	}

	// Idempotence
	if err := admindb.MigrateRBACGrantsForTest(db); err != nil {
		t.Fatal(err)
	}
	var teamCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM teams`).Scan(&teamCount)
	if teamCount != 2 {
		t.Fatalf("re-run a dupliqué des équipes: %d", teamCount)
	}
}

func TestMigrateRBACGrants_Homogeneous(t *testing.T) {
	db := openLegacyRBAC(t)
	defer db.Close()

	tid := uuid.New().String()
	mustExec(t, db, `INSERT INTO teams (id, name) VALUES (?, ?)`, tid, "Viewers")
	mustExec(t, db, `INSERT INTO team_scopes (id, team_id, scope_type, scope_value) VALUES (?,?,?,?)`,
		uuid.New().String(), tid, "domain", "*.io")
	mustExec(t, db, `INSERT INTO users (id, email, password_hash, role) VALUES ('v','v@t.local','x','viewer')`)
	mustExec(t, db, `INSERT INTO team_members (team_id, user_id, role) VALUES (?,?,?)`, tid, "v", "viewer")

	if err := admindb.MigrateRBACGrantsForTest(db); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM teams`).Scan(&n)
	if n != 1 {
		t.Fatalf("pas de scission attendue, got %d teams", n)
	}
	var mode string
	_ = db.QueryRow(`SELECT access_mode FROM team_scopes WHERE team_id=?`, tid).Scan(&mode)
	if mode != "read" {
		t.Fatalf("mode=%q", mode)
	}
}

func TestOpenCreatesUserScopes(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='user_scopes'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("user_scopes missing: %v n=%d", err, n)
	}
	if admindb.TableHasColumnForTest(db, "team_members", "role") {
		t.Fatal("nouvelle DB ne doit pas avoir team_members.role")
	}
	if !admindb.TableHasColumnForTest(db, "team_scopes", "access_mode") {
		t.Fatal("nouvelle DB doit avoir access_mode")
	}
}

func openLegacyRBAC(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE users (
			id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE teams (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE team_members (
			team_id TEXT NOT NULL, user_id TEXT NOT NULL,
			role TEXT NOT NULL CHECK(role IN ('operator','viewer')),
			PRIMARY KEY (team_id, user_id))`,
		`CREATE TABLE team_scopes (
			id TEXT PRIMARY KEY, team_id TEXT NOT NULL,
			scope_type TEXT NOT NULL, scope_value TEXT NOT NULL,
			UNIQUE(team_id, scope_type, scope_value))`,
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at DATETIME)`,
	} {
		mustExec(t, db, s)
	}
	return db
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
