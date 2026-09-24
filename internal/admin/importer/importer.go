// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package importer gère l'export/import de sauvegardes et la migration de configurations.
package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/coreproxy"
	"github.com/vincamok/goproxify/internal/core/router"
)

// Backup est le format natif de sauvegarde Goproxify (.gpx-admin-backup / .gpx-full-backup).
type Backup struct {
	Version        string                     `json:"version"`
	CreatedAt      time.Time                  `json:"created_at"`
	Proxies        []BackupProxy              `json:"proxies"`
	Users          []BackupUser               `json:"users"`
	Tokens         []BackupToken              `json:"tokens"`
	TokenScopes    []BackupTokenScope         `json:"token_scopes,omitempty"`
	PATs           []BackupPAT                `json:"pats,omitempty"`
	Snippets       []BackupSnippet            `json:"snippets"`
	AlertChannels  []map[string]any           `json:"alert_channels"`
	AlertRules     []map[string]any           `json:"alert_rules"`
	DeclaredNodes  []map[string]any           `json:"declared_nodes,omitempty"`
	Configs        map[string]json.RawMessage `json:"configs,omitempty"` // "admin" | "core" | "agent:<name>"
	Tables         map[string][]map[string]any `json:"tables,omitempty"` // tables de configuration (settings, règles auto, équipes, domaines…)
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
	RBACRole     string  `json:"rbac_role,omitempty"`
	NodeName     string  `json:"node_name"`
	NodeEndpoint string  `json:"node_endpoint"`
	ExpiresAt    *string `json:"expires_at"`
}

type BackupTokenScope struct {
	ID         string `json:"id"`
	TokenID    string `json:"token_id"`
	ScopeType  string `json:"scope_type"`
	ScopeValue string `json:"scope_value"`
}

type BackupPAT struct {
	ID          string   `json:"id"`
	UserID      string   `json:"user_id"`
	Label       string   `json:"label"`
	TokenHash   string   `json:"token_hash"`
	TokenPrefix string   `json:"token_prefix"`
	Scopes      []string `json:"scopes"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
}

type BackupSnippet struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Config string `json:"config"`
}

// BackupSummary est le résumé renvoyé lors du preview d'une sauvegarde.
type BackupSummary struct {
	Version            string         `json:"version"`
	CreatedAt          time.Time      `json:"created_at"`
	Proxies            []ProxySummary `json:"proxies"`
	UserCount          int            `json:"user_count"`
	TokenCount         int            `json:"token_count"`
	TokenScopeCount    int            `json:"token_scope_count"`
	PATCount           int            `json:"pat_count"`
	SnippetCount       int            `json:"snippet_count"`
	ChannelCount       int            `json:"channel_count"`
	RuleCount          int            `json:"rule_count"`
	DeclaredNodeCount  int            `json:"declared_node_count"`
	ConfigRowCount     int            `json:"config_row_count"`
	ConfigTables       map[string]int `json:"config_tables,omitempty"`
	HasConfigs         bool           `json:"has_configs"`
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
	ImportPATs     bool     `json:"import_pats"`
	ImportSnippets bool     `json:"import_snippets"`
	ImportChannels bool     `json:"import_alert_channels"`
	ImportRules    bool     `json:"import_alert_rules"`
	OnConflict     string   `json:"on_conflict"`     // skip | overwrite
	RestoreConfigs bool     `json:"restore_configs"` // écrire les fichiers config sur disque
	ImportConfig   bool     `json:"import_config"`   // restaurer les tables de configuration (règles auto, équipes, domaines, settings…)
}

// ImportResult décrit ce qui a été importé.
type ImportResult struct {
	Proxies  int `json:"proxies"`
	Users    int `json:"users"`
	Tokens   int `json:"tokens"`
	PATs     int `json:"pats"`
	Snippets int `json:"snippets"`
	Channels int `json:"channels"`
	Rules    int `json:"rules"`
	Config        int `json:"config"`
	DeclaredNodes int `json:"declared_nodes"`
	Skipped  int `json:"skipped"`
	Errors   int `json:"errors"`
}

// SummarizeBackup parse le JSON et retourne un résumé sans tout charger.
func SummarizeBackup(data []byte) (*Backup, *BackupSummary, error) {
	var b Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, nil, err
	}
	if b.Version != "" && b.Version != "1" {
		return nil, nil, fmt.Errorf("version de sauvegarde %q non supportée (attendue : 1)", b.Version)
	}
	sum := &BackupSummary{
		Version:           b.Version,
		CreatedAt:         b.CreatedAt,
		UserCount:         len(b.Users),
		TokenCount:        len(b.Tokens),
		TokenScopeCount:   len(b.TokenScopes),
		PATCount:          len(b.PATs),
		SnippetCount:      len(b.Snippets),
		ChannelCount:      len(b.AlertChannels),
		RuleCount:         len(b.AlertRules),
		DeclaredNodeCount: len(b.DeclaredNodes),
		ConfigRowCount:    TableRowCount(b.Tables),
		ConfigTables:      TableCounts(b.Tables),
		HasConfigs:        len(b.Configs) > 0,
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
		var m map[string]any
		_ = json.Unmarshal(cfg, &m)
		m["id"] = id
		cfgBytes, _ := json.Marshal(m)
		targets, err := coreproxy.ListTargets(context.Background(), db)
		if err != nil || len(targets) == 0 {
			res.Errors++
			continue
		}
		client := coreproxy.NewClient()
		ok := false
		for _, t := range targets {
			if _, err := client.Publish(context.Background(), t, id, p.Name, p.Enabled, cfgBytes, "import"); err != nil {
				continue
			}
			ok = true
		}
		if ok {
			res.Proxies++
		} else {
			res.Errors++
		}
	}

	// Users (sans mot de passe — on ne restaure jamais les hashes, on ne les écrase pas non plus)
	if sel.ImportUsers {
		for _, u := range b.Users {
			id := u.ID
			if id == "" {
				id = uuid.New().String()
			}
			hash, _ := auth.HashPassword(uuid.New().String()) // mot de passe aléatoire pour les nouveaux comptes
			if overwrite {
				// Mettre à jour email et rôle sans toucher au mot de passe de l'utilisateur existant.
				_, err := db.Exec(
					`INSERT INTO users (id, email, password_hash, role) VALUES (?,?,?,?)
					 ON CONFLICT(email) DO UPDATE SET role=excluded.role WHERE id != excluded.id OR role != excluded.role`,
					id, u.Email, hash, u.Role)
				if err == nil {
					res.Users++
				} else {
					res.Skipped++
				}
				continue
			}
			_, err := db.Exec(`INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES (?,?,?,?)`,
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
			rbacRole := t.RBACRole
			_, err := db.Exec(verb+` INTO tokens (id, token, token_hash, role, rbac_role, node_name, node_endpoint, expires_at) VALUES (?,?,?,?,?,?,?,?)`,
				id, stored, hash, t.Role, rbacRole, t.NodeName, t.NodeEndpoint, t.ExpiresAt)
			if err == nil {
				res.Tokens++
			} else {
				res.Skipped++
			}
		}
		// token_scopes
		for _, s := range b.TokenScopes {
			id := s.ID
			if id == "" {
				id = uuid.New().String()
			}
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			db.Exec(verb+` INTO token_scopes (id, token_id, scope_type, scope_value) VALUES (?,?,?,?)`, //nolint:errcheck
				id, s.TokenID, s.ScopeType, s.ScopeValue)
		}
	}

	// PATs (user_api_tokens)
	if sel.ImportPATs {
		for _, p := range b.PATs {
			if p.TokenHash == "" {
				res.Skipped++
				continue
			}
			id := p.ID
			if id == "" {
				id = uuid.New().String()
			}
			verb := `INSERT OR IGNORE`
			if overwrite {
				verb = `INSERT OR REPLACE`
			}
			_, err := db.Exec(verb+` INTO user_api_tokens (id, user_id, label, token_hash, token_prefix, expires_at) VALUES (?,?,?,?,?,?)`,
				id, p.UserID, p.Label, p.TokenHash, p.TokenPrefix, p.ExpiresAt)
			if err == nil {
				res.PATs++
				for _, scope := range p.Scopes {
					db.Exec(`INSERT OR IGNORE INTO user_api_token_scopes (token_id, scope) VALUES (?,?)`, id, scope) //nolint:errcheck
				}
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

	// Declared nodes — toujours restaurés (base de la topologie déclarée)
	for _, n := range b.DeclaredNodes {
		id, _ := n["id"].(string)
		// Ne pas restaurer les nœuds synthétiques issus de config (préfixe "cfg:")
		if strings.HasPrefix(id, "cfg:") {
			continue
		}
		if id == "" {
			id = uuid.New().String()
		}
		role, _ := n["role"].(string)
		name, _ := n["name"].(string)
		region, _ := n["region"].(string)
		env, _ := n["environment"].(string)
		cfgJ, _ := json.Marshal(n["config"])
		verb := `INSERT OR IGNORE`
		if overwrite {
			verb = `INSERT OR REPLACE`
		}
		_, err := db.Exec(verb+` INTO declared_nodes (id, role, name, region, environment, config) VALUES (?,?,?,?,?,?)`,
			id, role, name, region, env, string(cfgJ))
		if err == nil {
			res.DeclaredNodes++
		}
	}

	if sel.ImportConfig {
		w, sk := applyTables(db, b.Tables, overwrite)
		res.Config += w
		res.Skipped += sk
	}

	return res
}

// ExportBackup crée un Backup complet depuis la DB (ou fichiers Core).
func ExportBackup(db *sql.DB) (*Backup, error) {
	b := &Backup{Version: "1", CreatedAt: time.Now()}

	// Proxies
	envs, err := coreproxy.LoadProductionEnvelopes(context.Background(), db)
	if err != nil {
		return nil, err
	}
	for _, e := range envs {
		var p BackupProxy
		p.ID = e.ID
		p.Name = e.Host
		p.Enabled = e.Enabled
		_ = json.Unmarshal(e.Config, &p.Config)
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
	trows, _ := db.Query(`SELECT id, token, role, COALESCE(rbac_role,''), node_name, node_endpoint, expires_at FROM tokens WHERE revoked=0 ORDER BY created_at`)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var t BackupToken
			var exp sql.NullString
			var rawTok string
			trows.Scan(&t.ID, &rawTok, &t.Role, &t.RBACRole, &t.NodeName, &t.NodeEndpoint, &exp) //nolint:errcheck
			_ = rawTok
			t.Token = "" // toujours rédigé à l'export
			if exp.Valid {
				s := exp.String
				t.ExpiresAt = &s
			}
			b.Tokens = append(b.Tokens, t)
		}
	}

	// Token scopes
	tsrows, _ := db.Query(`SELECT id, token_id, scope_type, scope_value FROM token_scopes ORDER BY token_id, scope_type, scope_value`)
	if tsrows != nil {
		defer tsrows.Close()
		for tsrows.Next() {
			var s BackupTokenScope
			tsrows.Scan(&s.ID, &s.TokenID, &s.ScopeType, &s.ScopeValue) //nolint:errcheck
			b.TokenScopes = append(b.TokenScopes, s)
		}
	}

	// PATs (user_api_tokens) — exporter les hashes (non-réversibles, comme /etc/shadow)
	patrows, _ := db.Query(`SELECT id, user_id, label, token_hash, token_prefix, expires_at FROM user_api_tokens WHERE revoked=0 ORDER BY created_at`)
	if patrows != nil {
		defer patrows.Close()
		for patrows.Next() {
			var p BackupPAT
			var exp sql.NullString
			patrows.Scan(&p.ID, &p.UserID, &p.Label, &p.TokenHash, &p.TokenPrefix, &exp) //nolint:errcheck
			if exp.Valid {
				s := exp.String
				p.ExpiresAt = &s
			}
			// Load scopes
			scopeRows, _ := db.Query(`SELECT scope FROM user_api_token_scopes WHERE token_id=? ORDER BY scope`, p.ID)
			if scopeRows != nil {
				for scopeRows.Next() {
					var sc string
					scopeRows.Scan(&sc) //nolint:errcheck
					p.Scopes = append(p.Scopes, sc)
				}
				scopeRows.Close()
			}
			b.PATs = append(b.PATs, p)
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

	// Declared nodes (topologie déclarée dans l'assistant infrastructure)
	dnrows, _ := db.Query(`SELECT id, role, name, region, environment, config, created_at FROM declared_nodes ORDER BY created_at`)
	if dnrows != nil {
		defer dnrows.Close()
		for dnrows.Next() {
			var id, role, name, region, env, cfg, createdAt string
			dnrows.Scan(&id, &role, &name, &region, &env, &cfg, &createdAt) //nolint:errcheck
			var cfgMap map[string]any
			json.Unmarshal([]byte(cfg), &cfgMap) //nolint:errcheck
			b.DeclaredNodes = append(b.DeclaredNodes, map[string]any{
				"id": id, "role": role, "name": name, "region": region,
				"environment": env, "config": cfgMap, "created_at": createdAt,
			})
		}
	}

	b.Tables = exportTables(db)

	return b, nil
}

// ExportConfigs lit les fichiers config JSON depuis le disque et les inclut dans le backup.
// paths : map "admin"→chemin, "core"→chemin, "agent:<name>"→chemin
func ExportConfigs(paths map[string]string) map[string]json.RawMessage {
	if len(paths) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(paths))
	for key, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var raw json.RawMessage = data
		out[key] = raw
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RestoreConfigs écrit les fichiers config JSON sur disque (restauration).
// paths : même map que pour ExportConfigs.
// Les clés absentes de configs sont ignorées ; les fichiers existants sont remplacés atomiquement.
func RestoreConfigs(configs map[string]json.RawMessage, paths map[string]string) error {
	for key, data := range configs {
		path, ok := paths[key]
		if !ok || path == "" {
			continue
		}
		if err := atomicWriteFile(path, data); err != nil {
			return fmt.Errorf("restore config %q → %s : %w", key, path, err)
		}
	}
	return nil
}

func atomicWriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".restore-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, path)
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
