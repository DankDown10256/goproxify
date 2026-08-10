// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// migrateRBACGrants applique le modèle grants (scope + access_mode) :
//   - table user_scopes
//   - team_scopes.access_mode
//   - team_members sans role (héritage intégral)
//   - users.role operator/viewer → user
//   - scission B' des équipes mixtes avant suppression de team_members.role
func migrateRBACGrants(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_scopes (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			scope_type   TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','core')),
			scope_value  TEXT NOT NULL,
			access_mode  TEXT NOT NULL DEFAULT 'read' CHECK(access_mode IN ('read','write')),
			UNIQUE(user_id, scope_type, scope_value)
		)`); err != nil {
		return fmt.Errorf("user_scopes: %w", err)
	}

	hasMemberRole := tableHasColumn(db, "team_members", "role")
	hasAccessMode := tableHasColumn(db, "team_scopes", "access_mode")

	if hasMemberRole {
		if err := splitMixedTeamsBPrime(db); err != nil {
			return fmt.Errorf("rbac B': %w", err)
		}
	}

	if !hasAccessMode {
		if err := rebuildTeamScopesWithMode(db, hasMemberRole); err != nil {
			return fmt.Errorf("team_scopes access_mode: %w", err)
		}
	} else if hasMemberRole {
		// Colonne déjà présente (ex. migration core) : caler le mode sur les rôles avant de les supprimer.
		if err := assignTeamScopeModesFromRoles(db); err != nil {
			return fmt.Errorf("team_scopes modes from roles: %w", err)
		}
	}

	if hasMemberRole {
		if err := rebuildTeamMembersWithoutRole(db); err != nil {
			return fmt.Errorf("team_members drop role: %w", err)
		}
	}

	// Idempotent à chaque boot.
	if _, err := db.Exec(`UPDATE users SET role='user' WHERE role IN ('viewer','operator')`); err != nil {
		return fmt.Errorf("users.role normalize: %w", err)
	}

	return nil
}

func assignTeamScopeModesFromRoles(db *sql.DB) error {
	if _, err := db.Exec(`UPDATE team_scopes SET access_mode='read'`); err != nil {
		return err
	}
	_, err := db.Exec(`
		UPDATE team_scopes SET access_mode='write'
		WHERE team_id IN (
			SELECT team_id FROM team_members WHERE role IN ('operator','admin')
		)`)
	return err
}

func tableHasColumn(db *sql.DB, table, col string) bool {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		if strings.EqualFold(name, col) {
			return true
		}
	}
	return false
}

// splitMixedTeamsBPrime : équipe avec operators ET viewers →
// équipe d'origine (operators, scopes → write plus tard) + "Nom (lecture)" (viewers, scopes read).
func splitMixedTeamsBPrime(db *sql.DB) error {
	trows, err := db.Query(`SELECT id, name FROM teams`)
	if err != nil {
		return err
	}
	defer trows.Close()

	type team struct{ id, name string }
	var teams []team
	for trows.Next() {
		var t team
		if err := trows.Scan(&t.id, &t.name); err != nil {
			continue
		}
		teams = append(teams, t)
	}

	for _, t := range teams {
		mrows, err := db.Query(`SELECT user_id, role FROM team_members WHERE team_id=?`, t.id)
		if err != nil {
			return err
		}
		var ops, views []string
		for mrows.Next() {
			var uid, role string
			if err := mrows.Scan(&uid, &role); err != nil {
				continue
			}
			switch role {
			case "operator", "admin":
				ops = append(ops, uid)
			case "viewer":
				views = append(views, uid)
			default:
				views = append(views, uid)
			}
		}
		mrows.Close()

		if len(ops) == 0 || len(views) == 0 {
			continue
		}

		readName, err := uniqueTeamName(db, t.name+" (lecture)")
		if err != nil {
			return err
		}
		readID := uuid.New().String()
		if _, err := db.Exec(`INSERT INTO teams (id, name) VALUES (?, ?)`, readID, readName); err != nil {
			return err
		}

		srows, err := db.Query(`SELECT scope_type, scope_value FROM team_scopes WHERE team_id=?`, t.id)
		if err != nil {
			return err
		}
		type scope struct{ typ, val string }
		var scopes []scope
		for srows.Next() {
			var s scope
			if err := srows.Scan(&s.typ, &s.val); err != nil {
				continue
			}
			scopes = append(scopes, s)
		}
		srows.Close()
		for _, s := range scopes {
			if _, err := db.Exec(
				`INSERT INTO team_scopes (id, team_id, scope_type, scope_value) VALUES (?, ?, ?, ?)`,
				uuid.New().String(), readID, s.typ, s.val,
			); err != nil {
				return fmt.Errorf("copie scope vers %s: %w", readName, err)
			}
		}

		for _, uid := range views {
			if _, err := db.Exec(`DELETE FROM team_members WHERE team_id=? AND user_id=?`, t.id, uid); err != nil {
				return err
			}
			if _, err := db.Exec(
				`INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, 'viewer')`,
				readID, uid,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func uniqueTeamName(db *sql.DB, base string) (string, error) {
	name := base
	for i := 2; ; i++ {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM teams WHERE name=?`, name).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return name, nil
		}
		name = fmt.Sprintf("%s %d", base, i)
	}
}

func rebuildTeamScopesWithMode(db *sql.DB, hasMemberRole bool) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS team_scopes_grants (
			id           TEXT PRIMARY KEY,
			team_id      TEXT NOT NULL,
			scope_type   TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','core')),
			scope_value  TEXT NOT NULL,
			access_mode  TEXT NOT NULL DEFAULT 'read' CHECK(access_mode IN ('read','write')),
			UNIQUE(team_id, scope_type, scope_value)
		)`); err != nil {
		return err
	}

	rows, err := db.Query(`SELECT id, team_id, scope_type, scope_value FROM team_scopes`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct{ id, teamID, typ, val string }
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.teamID, &r.typ, &r.val); err != nil {
			continue
		}
		all = append(all, r)
	}

	modeCache := map[string]string{}
	teamMode := func(teamID string) string {
		if m, ok := modeCache[teamID]; ok {
			return m
		}
		mode := "read"
		if hasMemberRole {
			var n int
			_ = db.QueryRow(`
				SELECT COUNT(*) FROM team_members
				WHERE team_id=? AND role IN ('operator','admin')`, teamID).Scan(&n)
			if n > 0 {
				mode = "write"
			}
		}
		modeCache[teamID] = mode
		return mode
	}

	for _, r := range all {
		_, err := db.Exec(
			`INSERT OR IGNORE INTO team_scopes_grants (id, team_id, scope_type, scope_value, access_mode) VALUES (?, ?, ?, ?, ?)`,
			r.id, r.teamID, r.typ, r.val, teamMode(r.teamID),
		)
		if err != nil {
			return err
		}
	}

	for _, s := range []string{
		`ALTER TABLE team_scopes RENAME TO team_scopes_pre_grants`,
		`ALTER TABLE team_scopes_grants RENAME TO team_scopes`,
		`DROP TABLE IF EXISTS team_scopes_pre_grants`,
	} {
		if _, err := db.Exec(s); err != nil {
			// Idempotence : table déjà migrée / rename conflict
			_ = err
		}
	}

	// Si le rename a échoué à mi-chemin, s'assurer que team_scopes a access_mode.
	if !tableHasColumn(db, "team_scopes", "access_mode") {
		return fmt.Errorf("team_scopes sans access_mode après migration")
	}
	return nil
}

func rebuildTeamMembersWithoutRole(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS team_members_v2 (
			team_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			PRIMARY KEY (team_id, user_id)
		)`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO team_members_v2 (team_id, user_id)
		SELECT team_id, user_id FROM team_members`); err != nil {
		return err
	}
	for _, s := range []string{
		`ALTER TABLE team_members RENAME TO team_members_pre_grants`,
		`ALTER TABLE team_members_v2 RENAME TO team_members`,
		`DROP TABLE IF EXISTS team_members_pre_grants`,
	} {
		_, _ = db.Exec(s)
	}
	if tableHasColumn(db, "team_members", "role") {
		return fmt.Errorf("team_members.role toujours présent après migration")
	}
	return nil
}

// MigrateRBACGrantsForTest expose migrateRBACGrants aux tests du package db_test.
func MigrateRBACGrantsForTest(db *sql.DB) error { return migrateRBACGrants(db) }

// TableHasColumnForTest expose tableHasColumn aux tests.
func TableHasColumnForTest(db *sql.DB, table, col string) bool {
	return tableHasColumn(db, table, col)
}
