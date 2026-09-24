// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// backupTables liste, dans l'ordre de restauration, les tables de configuration
// sauvegardées telle quelles (SELECT *). Les tables d'état (logs, bans, audit,
// MFA, sessions, snapshots, historiques) et les clés de chiffrement (gdpr_keys)
// n'en font volontairement pas partie.
var backupTables = []string{
	"settings",
	"backup_schedule",
	"fail2ban_config",
	"crowdsec_config",
	"rules_engine_rules",
	"domains",
	"cert_deploy_targets",
	"auth_providers",
	"ip_profiles",
	"node_tunnel_configs",
	"teams",
	"team_members",
	"team_scopes",
	"team_scopes_v2",
	"token_scopes_v2",
	"workspaces",
	"workspace_members",
	"workspace_resources",
	"error_page_templates",
	"error_page_assets",
	"portal_destinations",
	"portal_users",
	"portal_page_templates",
}

// blobColumns : colonnes BLOB, encodées en base64 dans le JSON de sauvegarde.
var blobColumns = map[string]bool{"error_page_assets.content": true}

// clearedColumns : colonnes dont la valeur ne doit jamais sortir de la base.
var clearedColumns = map[string]bool{"portal_users.invite_token_hash": true}

var secretFragments = []string{"secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "credential", "webhook_url", "authorization"}

func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	for _, f := range secretFragments {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

func redactJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if _, isStr := val.(string); isStr && isSecretKey(k) {
				x[k] = ""
				continue
			}
			x[k] = redactJSONValue(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactJSONValue(x[i])
		}
		return x
	}
	return v
}

// redactTableValue rédige les secrets d'une valeur texte (JSON ou brute) d'une colonne.
func redactTableValue(table, col string, val any) any {
	if clearedColumns[table+"."+col] {
		return ""
	}
	s, ok := val.(string)
	if !ok || s == "" {
		return val
	}
	var parsed any
	if (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Unmarshal([]byte(s), &parsed) == nil {
		out, _ := json.Marshal(redactJSONValue(parsed))
		return string(out)
	}
	return val
}

func exportTables(db *sql.DB) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, table := range backupTables {
		rows, err := db.Query(`SELECT * FROM ` + table)
		if err != nil {
			continue // table absente sur une base ancienne
		}
		cols, _ := rows.Columns()
		var list []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if rows.Scan(ptrs...) != nil {
				continue
			}
			row := make(map[string]any, len(cols))
			for i, c := range cols {
				v := vals[i]
				if b, ok := v.([]byte); ok {
					if blobColumns[table+"."+c] {
						v = base64.StdEncoding.EncodeToString(b)
					} else {
						v = string(b)
					}
				}
				row[c] = v
			}
			list = append(list, row)
		}
		rows.Close()
		if len(list) > 0 {
			out[table] = list
		}
	}
	return out
}

// redactTables retire les secrets des lignes exportées (clés d'API DNS, secrets OIDC, etc.).
func redactTables(tables map[string][]map[string]any) {
	for table, rows := range tables {
		for _, row := range rows {
			if k, ok := row["key"].(string); ok && isSecretKey(k) {
				row["value"] = ""
				continue
			}
			for col, v := range row {
				row[col] = redactTableValue(table, col, v)
			}
		}
	}
}

// TableRowCount retourne le nombre total de lignes de configuration d'une sauvegarde.
func TableRowCount(tables map[string][]map[string]any) int {
	n := 0
	for _, rows := range tables {
		n += len(rows)
	}
	return n
}

// TableCounts retourne le nombre de lignes par table de configuration.
func TableCounts(tables map[string][]map[string]any) map[string]int {
	out := make(map[string]int, len(tables))
	for t, rows := range tables {
		out[t] = len(rows)
	}
	return out
}

// applyTables restaure les tables de configuration ; retourne le nombre de lignes écrites.
func applyTables(db *sql.DB, tables map[string][]map[string]any, overwrite bool) (written, skipped int) {
	verb := `INSERT OR IGNORE`
	if overwrite {
		verb = `INSERT OR REPLACE`
	}
	for _, table := range backupTables {
		rows := tables[table]
		if len(rows) == 0 {
			continue
		}
		valid := tableColumns(db, table)
		if len(valid) == 0 {
			skipped += len(rows)
			continue
		}
		for _, row := range rows {
			var cols []string
			var args []any
			var ph []string
			for c, v := range row {
				if !valid[c] {
					continue
				}
				if s, ok := v.(string); ok && blobColumns[table+"."+c] {
					if b, err := base64.StdEncoding.DecodeString(s); err == nil {
						v = b
					}
				}
				cols = append(cols, c)
				args = append(args, v)
				ph = append(ph, "?")
			}
			if k, ok := row["key"].(string); ok && isSecretKey(k) && row["value"] == "" {
				continue // secret rédigé : ne pas écraser la valeur en place
			}
			if len(cols) == 0 {
				continue
			}
			q := fmt.Sprintf(`%s INTO %s (%s) VALUES (%s)`, verb, table, strings.Join(cols, ","), strings.Join(ph, ","))
			if res, err := db.Exec(q, args...); err != nil {
				skipped++
			} else if n, _ := res.RowsAffected(); n > 0 {
				written++
			} else {
				skipped++
			}
		}
	}
	return written, skipped
}

func tableColumns(db *sql.DB, table string) map[string]bool {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) == nil {
			cols[name] = true
		}
	}
	return cols
}
