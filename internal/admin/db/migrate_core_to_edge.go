// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

var legacyCoreName = regexp.MustCompile(`(^|_)core(s?)($|_)`)

// legacyEdgeName renvoie le nom actuel d'une colonne ou d'un index hérité de l'ère « core ».
func legacyEdgeName(s string) string {
	return legacyCoreName.ReplaceAllString(s, "${1}edge${2}${3}")
}

// legacyValueColumns liste les colonnes dont la valeur « core » est devenue « edge ».
var legacyValueColumns = map[string]bool{
	"role": true, "scope_type": true, "resource_type": true, "component": true,
}

// migrateCoreToEdge adapte une base créée avant le renommage Core → Edge : colonnes, index,
// contraintes CHECK et valeurs. Elle doit s'exécuter avant les CREATE TABLE IF NOT EXISTS
// de migrate(), sinon les colonnes « edge_* » seraient ajoutées à côté des « core_* ».
// Idempotente : sans reste de « core », elle ne modifie rien.
func migrateCoreToEdge(db *sql.DB) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	type table struct{ name, sql string }
	var tables []table
	rows, err := conn.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var t table
		var s sql.NullString
		if err := rows.Scan(&t.name, &s); err != nil {
			rows.Close()
			return err
		}
		t.sql = s.String
		tables = append(tables, t)
	}
	rows.Close()
	if len(tables) == 0 {
		return nil
	}

	rebuildSchema := false
	for _, t := range tables {
		if strings.Contains(t.sql, "'core'") {
			rebuildSchema = true
		}
	}

	// Index hérités (la définition suit la colonne renommée, seul le nom est obsolète).
	idx, err := conn.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='index' AND name LIKE '%core%'`)
	if err != nil {
		return err
	}
	var oldIdx []string
	for idx.Next() {
		var n string
		if err := idx.Scan(&n); err != nil {
			idx.Close()
			return err
		}
		if legacyEdgeName(n) != n {
			oldIdx = append(oldIdx, n)
		}
	}
	idx.Close()

	for _, t := range tables {
		cols, err := conn.QueryContext(ctx, fmt.Sprintf(`SELECT name FROM pragma_table_info('%s')`, t.name))
		if err != nil {
			return err
		}
		var names []string
		for cols.Next() {
			var n string
			if err := cols.Scan(&n); err != nil {
				cols.Close()
				return err
			}
			names = append(names, n)
		}
		cols.Close()
		have := map[string]bool{}
		for _, n := range names {
			have[n] = true
		}
		for _, n := range names {
			if nn := legacyEdgeName(n); nn != n && !have[nn] {
				if _, err := conn.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s RENAME COLUMN %s TO %s`, t.name, n, nn)); err != nil {
					return fmt.Errorf("renommage %s.%s : %w", t.name, n, err)
				}
			}
		}
	}

	for _, n := range oldIdx {
		if _, err := conn.ExecContext(ctx, `DROP INDEX IF EXISTS `+n); err != nil {
			return err
		}
	}

	if rebuildSchema {
		// Les CHECK(... IN ('core', ...)) ne se modifient pas par ALTER : on réécrit le texte du
		// schéma (procédure « writable_schema » de la doc SQLite, sans changement de structure).
		var ver int
		if err := conn.QueryRowContext(ctx, `PRAGMA schema_version`).Scan(&ver); err != nil {
			return err
		}
		for _, s := range []string{
			`PRAGMA writable_schema=ON`,
			`UPDATE sqlite_master SET sql = replace(sql, '''core''', '''edge''') WHERE type='table' AND sql LIKE '%''core''%'`,
			fmt.Sprintf(`PRAGMA schema_version=%d`, ver+1),
			`PRAGMA writable_schema=OFF`,
		} {
			if _, err := conn.ExecContext(ctx, s); err != nil {
				return fmt.Errorf("réécriture du schéma : %w", err)
			}
		}
	}
	conn.Close()

	for _, t := range tables {
		cols, err := db.Query(fmt.Sprintf(`SELECT name FROM pragma_table_info('%s')`, t.name))
		if err != nil {
			return err
		}
		var names []string
		for cols.Next() {
			var n string
			if err := cols.Scan(&n); err != nil {
				cols.Close()
				return err
			}
			names = append(names, n)
		}
		cols.Close()
		for _, n := range names {
			if legacyValueColumns[n] {
				if _, err := db.Exec(fmt.Sprintf(`UPDATE %s SET %s='edge' WHERE %s='core'`, t.name, n, n)); err != nil {
					return fmt.Errorf("valeurs %s.%s : %w", t.name, n, err)
				}
			}
		}
	}

	// Blobs JSON dont les clés ont changé.
	for _, s := range []string{
		`UPDATE declared_nodes SET config = replace(replace(config, '"target_core"', '"target_edge"'), '"core_endpoint"', '"edge_endpoint"') WHERE config LIKE '%core%'`,
	} {
		db.Exec(s) //nolint:errcheck — table absente sur une base neuve
	}
	return nil
}
