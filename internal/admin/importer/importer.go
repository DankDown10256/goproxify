// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package importer gère l'export/import de sauvegardes et la migration de configurations.
package importer

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/core/router"
)

// Backup est le format natif de sauvegarde Goproxify (.gpx-admin-backup).
type Backup struct {
	Version       string           `json:"version"`
	CreatedAt     time.Time        `json:"created_at"`
	Proxies       []BackupProxy    `json:"proxies"`
	Users         []BackupUser     `json:"users"`
	Tokens        []BackupToken    `json:"tokens"`
	Snippets      []BackupSnippet  `json:"snippets"`
	AlertChannels []map[string]any `json:"alert_channels"`
	AlertRules    []map[string]any `json:"alert_rules"`
}

type BackupProxy struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Config  router.Route `json:"config"`
	Enabled bool         `json:"enabled"`
}

type BackupUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type BackupToken struct {
	ID           string  `json:"id"`
	Token        string  `json:"token"`
	Role         string  `json:"role"`
	NodeName     string  `json:"node_name"`
	NodeEndpoint string  `json:"node_endpoint"`
	ExpiresAt    *string `json:"expires_at"`
}

type BackupSnippet struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Config string `json:"config"`
}

// BackupSummary est le résumé renvoyé lors du preview d'une sauvegarde.
type BackupSummary struct {
	Version       string        `json:"version"`
	CreatedAt     time.Time     `json:"created_at"`
	Proxies       []ProxySummary `json:"proxies"`
	UserCount     int           `json:"user_count"`
	TokenCount    int           `json:"token_count"`
	SnippetCount  int           `json:"snippet_count"`
	ChannelCount  int           `json:"channel_count"`
	RuleCount     int           `json:"rule_count"`
}

type ProxySummary struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// ImportSelection précise ce qu'on importe depuis la sauvegarde.
type ImportSelection struct {
	ProxyIDs       []string `json:"proxy_ids"`      // vide = tous
	ImportUsers    bool     `json:"import_users"`
	ImportTokens   bool     `json:"import_tokens"`
	ImportSnippets bool     `json:"import_snippets"`
	ImportChannels bool     `json:"import_alert_channels"`
	ImportRules    bool     `json:"import_alert_rules"`
	OnConflict     string   `json:"on_conflict"` // skip | overwrite
}

// ImportResult décrit ce qui a été importé.
type ImportResult struct {
	Proxies  int `json:"proxies"`
	Users    int `json:"users"`
	Tokens   int `json:"tokens"`
	Snippets int `json:"snippets"`
	Channels int `json:"channels"`
	Rules    int `json:"rules"`
	Skipped  int `json:"skipped"`
	Errors   int `json:"errors"`
}

// SummarizeBackup parse le JSON et retourne un résumé sans tout charger.
func SummarizeBackup(data []byte) (*Backup, *BackupSummary, error) {
	var b Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, nil, err
	}
	sum := &BackupSummary{
		Version:      b.Version,
		CreatedAt:    b.CreatedAt,
		UserCount:    len(b.Users),
		TokenCount:   len(b.Tokens),
		SnippetCount: len(b.Snippets),
		ChannelCount: len(b.AlertChannels),
		RuleCount:    len(b.AlertRules),
	}
	for _, p := range b.Proxies {
		sum.Proxies = append(sum.Proxies, ProxySummary{
			ID: p.ID, Name: p.Name, Host: p.Config.Host,
			Type: string(p.Config.Type), Enabled: p.Enabled,
		})
	}
	return &b, sum, nil
}

// Apply importe les entités sélectionnées dans la DB.
func Apply(db *sql.DB, b *Backup, sel ImportSelection) ImportResult {
	var res ImportResult
	overwrite := sel.OnConflict == "overwrite"

	// Proxies
	wanted := map[string]bool{}
	for _, id := range sel.ProxyIDs {
		wanted[id] = true
	}
	for _, p := range b.Proxies {
		if len(wanted) > 0 && !wanted[p.ID] {
			continue
		}
		// Normaliser tls_mode dans les sauvegardes anciennes :
		// un proxy HTTPS sans tls_mode explicite passe en "manual" + cert auto (SNI).
		cfg := normalizeTLSMode(p.Config)
		id := p.ID
		if id == "" {
			id = uuid.New().String()
		}
		enabled := 0
		if p.Enabled {
			enabled = 1
		}
		if overwrite {
			_, err := db.Exec(
				`INSERT OR REPLACE INTO proxies (id, name, config, enabled) VALUES (?,?,?,?)`,
				id, p.Name, string(cfg), enabled)
			if err == nil {
				res.Proxies++
			} else {
				res.Errors++
			}
		} else {
			_, err := db.Exec(
				`INSERT OR IGNORE INTO proxies (id, name, config, enabled) VALUES (?,?,?,?)`,
				id, p.Name, string(cfg), enabled)
			if err == nil {
				res.Proxies++
			} else {
				res.Skipped++
			}
		}
	}

	// Users (sans mot de passe — on ne restaure pas les hashes)
	if sel.ImportUsers {
		for _, u := range b.Users {
			id := u.ID
			if id == "" {
				id = uuid.New().String()
			}
			hash, _ := auth.HashPassword(uuid.New().String()) // mot de passe aléatoire, à réinitialiser
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			_, err := db.Exec(verb+` INTO users (id, email, password_hash, role) VALUES (?,?,?,?)`,
				id, u.Email, hash, u.Role)
			if err == nil {
				res.Users++
			} else {
				res.Skipped++
			}
		}
	}

	// Tokens
	if sel.ImportTokens {
		for _, t := range b.Tokens {
			if strings.TrimSpace(t.Token) == "" {
				res.Skipped++
				continue
			}
			id := t.ID
			if id == "" {
				id = uuid.New().String()
			}
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			stored, hash := auth.PrepareNodeTokenForStore(t.Token)
			_, err := db.Exec(verb+` INTO tokens (id, token, token_hash, role, node_name, node_endpoint, expires_at) VALUES (?,?,?,?,?,?,?)`,
				id, stored, hash, t.Role, t.NodeName, t.NodeEndpoint, t.ExpiresAt)
			if err == nil {
				res.Tokens++
			} else {
				res.Skipped++
			}
		}
	}

	// Snippets
	if sel.ImportSnippets {
		for _, s := range b.Snippets {
			id := s.ID
			if id == "" {
				id = uuid.New().String()
			}
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			_, err := db.Exec(verb+` INTO snippets (id, name, type, config) VALUES (?,?,?,?)`,
				id, s.Name, s.Type, s.Config)
			if err == nil {
				res.Snippets++
			} else {
				res.Skipped++
			}
		}
	}

	// Alert Channels
	if sel.ImportChannels {
		for _, c := range b.AlertChannels {
			id, _ := c["id"].(string)
			if id == "" {
				id = uuid.New().String()
			}
			name, _ := c["name"].(string)
			typ, _ := c["type"].(string)
			cfgJ, _ := json.Marshal(c["config"])
			enabled := 1
			if v, ok := c["enabled"].(bool); ok && !v {
				enabled = 0
			}
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			_, err := db.Exec(verb+` INTO alert_channels (id, name, type, config, enabled) VALUES (?,?,?,?,?)`,
				id, name, typ, string(cfgJ), enabled)
			if err == nil {
				res.Channels++
			} else {
				res.Skipped++
			}
		}
	}

	// Alert Rules
	if sel.ImportRules {
		for _, r := range b.AlertRules {
			id, _ := r["id"].(string)
			if id == "" {
				id = uuid.New().String()
			}
			name, _ := r["name"].(string)
			scopeJ, _ := json.Marshal(r["scope"])
			triggersJ, _ := json.Marshal(r["triggers"])
			chansJ, _ := json.Marshal(r["channels"])
			cooldown := 300
			if v, ok := r["cooldown_sec"].(float64); ok {
				cooldown = int(v)
			}
			priority := 0
			if v, ok := r["priority"].(float64); ok {
				priority = int(v)
			}
			enabled := 1
			if v, ok := r["enabled"].(bool); ok && !v {
				enabled = 0
			}
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			_, err := db.Exec(verb+` INTO alert_rules (id, name, scope, triggers, channels, cooldown_sec, priority, enabled) VALUES (?,?,?,?,?,?,?,?)`,
				id, name, string(scopeJ), string(triggersJ), string(chansJ), cooldown, priority, enabled)
			if err == nil {
				res.Rules++
			} else {
				res.Skipped++
			}
		}
	}

	return res
}

// ExportBackup crée un Backup complet depuis la DB.
func ExportBackup(db *sql.DB) (*Backup, error) {
	b := &Backup{Version: "1", CreatedAt: time.Now()}

	// Proxies
	rows, err := db.Query(`SELECT id, name, config, enabled FROM proxies ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p BackupProxy
		var cfg string
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &cfg, &enabled); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(cfg), &p.Config)
		p.Enabled = enabled == 1
		b.Proxies = append(b.Proxies, p)
	}

	// Users
	urows, _ := db.Query(`SELECT id, email, role FROM users ORDER BY created_at`)
	if urows != nil {
		defer urows.Close()
		for urows.Next() {
			var u BackupUser
			urows.Scan(&u.ID, &u.Email, &u.Role) //nolint:errcheck
			b.Users = append(b.Users, u)
		}
	}

	// Tokens — n'exporter jamais le secret en clair (H7) ; métadonnées seulement.
	trows, _ := db.Query(`SELECT id, token, role, node_name, node_endpoint, expires_at FROM tokens WHERE revoked=0 ORDER BY created_at`)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var t BackupToken
			var exp sql.NullString
			var rawTok string
			trows.Scan(&t.ID, &rawTok, &t.Role, &t.NodeName, &t.NodeEndpoint, &exp) //nolint:errcheck
			_ = rawTok
			t.Token = "" // toujours rédigé à l'export
			if exp.Valid {
				s := exp.String
				t.ExpiresAt = &s
			}
			b.Tokens = append(b.Tokens, t)
		}
	}

	// Snippets
	srows, _ := db.Query(`SELECT id, name, type, config FROM snippets ORDER BY created_at`)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var s BackupSnippet
			srows.Scan(&s.ID, &s.Name, &s.Type, &s.Config) //nolint:errcheck
			b.Snippets = append(b.Snippets, s)
		}
	}

	// Alert Channels
	crows, _ := db.Query(`SELECT id, name, type, config, enabled FROM alert_channels ORDER BY name`)
	if crows != nil {
		defer crows.Close()
		for crows.Next() {
			var id, name, typ, cfg string
			var enabled int
			crows.Scan(&id, &name, &typ, &cfg, &enabled) //nolint:errcheck
			var cfgMap map[string]any
			json.Unmarshal([]byte(cfg), &cfgMap) //nolint:errcheck
			b.AlertChannels = append(b.AlertChannels, map[string]any{
				"id": id, "name": name, "type": typ, "config": cfgMap, "enabled": enabled == 1,
			})
		}
	}

	// Alert Rules
	rrows, _ := db.Query(`SELECT id, name, scope, triggers, channels, cooldown_sec, priority, enabled FROM alert_rules ORDER BY priority DESC`)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var id, name, scope, triggers, chans string
			var cooldown, priority, enabled int
			rrows.Scan(&id, &name, &scope, &triggers, &chans, &cooldown, &priority, &enabled) //nolint:errcheck
			var scopeMap, triggersArr, chansArr any
			json.Unmarshal([]byte(scope), &scopeMap)     //nolint:errcheck
			json.Unmarshal([]byte(triggers), &triggersArr) //nolint:errcheck
			json.Unmarshal([]byte(chans), &chansArr)     //nolint:errcheck
			b.AlertRules = append(b.AlertRules, map[string]any{
				"id": id, "name": name, "scope": scopeMap, "triggers": triggersArr,
				"channels": chansArr, "cooldown_sec": cooldown, "priority": priority, "enabled": enabled == 1,
			})
		}
	}

	return b, nil
}

// normalizeTLSMode s'assure que tls_mode est présent dans le JSON d'une route HTTPS.
// Les sauvegardes antérieures à l'introduction de tls_mode ne contiennent pas ce champ ;
// on l'initialise à "manual" avec cert_name vide (détection automatique par SNI).
func normalizeTLSMode(route router.Route) []byte {
	raw, _ := json.Marshal(route)
	if !route.TLSEnabled {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if _, ok := m["tls_mode"]; !ok {
		m["tls_mode"] = "manual"
	}
	if _, ok := m["cert_name"]; !ok {
		m["cert_name"] = ""
	}
	out, _ := json.Marshal(m)
	return out
}
