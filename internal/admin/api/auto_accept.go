// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// NodeAutoAccept indique si un nœud (declared ou ticket bootstrap) doit être
// accepté automatiquement à la connexion (wizard architecture).
func NodeAutoAccept(db *sql.DB, nodeName string) bool {
	name := strings.TrimSpace(nodeName)
	if db == nil || name == "" {
		return false
	}
	if DeclaredAutoAccept(db, name) {
		return true
	}
	return BootstrapTicketAutoAccept(db, name)
}

// DeclaredAutoAccept lit config.auto_accept des declared_nodes au nom donné.
func DeclaredAutoAccept(db *sql.DB, nodeName string) bool {
	rows, err := db.Query(`SELECT config FROM declared_nodes WHERE name=?`, nodeName)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		if configAutoAccept(cfg) {
			return true
		}
	}
	return false
}

// BootstrapTicketAutoAccept regarde les tickets non expirés dont payload.auto_accept
// est vrai et payload.node_names contient nodeName.
func BootstrapTicketAutoAccept(db *sql.DB, nodeName string) bool {
	rows, err := db.Query(
		`SELECT payload FROM bootstrap_tickets WHERE expires_at > ?`,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var p struct {
			AutoAccept bool     `json:"auto_accept"`
			NodeNames  []string `json:"node_names"`
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil || !p.AutoAccept {
			continue
		}
		for _, n := range p.NodeNames {
			if strings.TrimSpace(n) == nodeName {
				return true
			}
		}
	}
	return false
}

// LinkBootstrapToDeclared attache bootstrap_token + auto_accept aux declared_nodes
// dont le nom figure dans names.
func LinkBootstrapToDeclared(db *sql.DB, token string, names []string) {
	if db == nil || token == "" || len(names) == 0 {
		return
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		var cfg string
		err := db.QueryRow(`SELECT config FROM declared_nodes WHERE name=? ORDER BY created_at DESC LIMIT 1`, name).Scan(&cfg)
		if err != nil {
			continue
		}
		var m map[string]any
		if cfg == "" {
			m = map[string]any{}
		} else if err := json.Unmarshal([]byte(cfg), &m); err != nil {
			m = map[string]any{}
		}
		m["auto_accept"] = true
		m["bootstrap_token"] = token
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}
		_, _ = db.Exec(`UPDATE declared_nodes SET config=? WHERE name=?`, string(b), name)
	}
}

func configAutoAccept(cfg string) bool {
	if cfg == "" {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		return false
	}
	switch v := m["auto_accept"].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
	}
}
