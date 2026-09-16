// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

const configFilename = "config.yaml"

type SnippetEntry struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Config string `yaml:"config"` // JSON brut
}

type AlertChannelEntry struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Config  string `yaml:"config"` // JSON (peut contenir des secrets)
	Enabled bool   `yaml:"enabled"`
}

type AlertRuleEntry struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Scope       string `yaml:"scope"`    // JSON
	Triggers    string `yaml:"triggers"` // JSON
	Channels    string `yaml:"channels"` // JSON array of channel IDs
	CooldownSec int    `yaml:"cooldown_sec"`
	Priority    int    `yaml:"priority"`
	Enabled     bool   `yaml:"enabled"`
}

type IPProfileEntry struct {
	ID               string `yaml:"id"`
	Name             string `yaml:"name"`
	ProfileType      string `yaml:"profile_type"`
	Mode             string `yaml:"mode"`
	FeedURLs         string `yaml:"feed_urls"`          // JSON
	FeedFormat       string `yaml:"feed_format"`
	RefreshIntervalH int    `yaml:"refresh_interval_h"`
	CIDRs            string `yaml:"cidrs"` // JSON
	Enabled          bool   `yaml:"enabled"`
}

type AuthProviderEntry struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"`
	Config   string `yaml:"config"` // JSON (peut contenir des secrets)
	Enabled  bool   `yaml:"enabled"`
}

type ErrorPageAssetEntry struct {
	ID          string `yaml:"id"`
	Filename    string `yaml:"filename"`
	ContentType string `yaml:"content_type"`
	ContentB64  string `yaml:"content_b64"` // base64
}

type ErrorPageTemplateEntry struct {
	ID          string                `yaml:"id"`
	Name        string                `yaml:"name"`
	Description string                `yaml:"description"`
	Body        string                `yaml:"body"`
	ScopeType   string                `yaml:"scope_type"`
	ScopeID     string                `yaml:"scope_id,omitempty"`
	Assets      []ErrorPageAssetEntry `yaml:"assets,omitempty"`
}

// ConfigArchive est la racine de config.yaml — référentiel de configuration fonctionnelle.
type ConfigArchive struct {
	SchemaVersion      int                      `yaml:"schema_version"`
	Snippets           []SnippetEntry           `yaml:"snippets,omitempty"`
	AlertChannels      []AlertChannelEntry      `yaml:"alert_channels,omitempty"`
	AlertRules         []AlertRuleEntry         `yaml:"alert_rules,omitempty"`
	IPProfiles         []IPProfileEntry         `yaml:"ip_profiles,omitempty"`
	AuthProviders      []AuthProviderEntry      `yaml:"auth_providers,omitempty"`
	ErrorPageTemplates []ErrorPageTemplateEntry `yaml:"error_page_templates,omitempty"`
}

// ConfigStore lit et écrit config.yaml de façon atomique.
type ConfigStore struct {
	mu   sync.RWMutex
	path string
}

// NewConfigStore crée un ConfigStore ciblant <dir>/config.yaml.
func NewConfigStore(dir string) *ConfigStore {
	return &ConfigStore{path: filepath.Join(dir, configFilename)}
}

// SyncFromDB (re)construit config.yaml depuis la DB — appelé à chaque mutation.
func (s *ConfigStore) SyncFromDB(ctx context.Context, db *sql.DB) error {
	arc, err := s.buildFromDB(ctx, db)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(arc)
}

// LoadIntoDB ré-insère les données depuis le fichier si les tables cibles sont vides.
func (s *ConfigStore) LoadIntoDB(ctx context.Context, db *sql.DB) error {
	s.mu.RLock()
	arc, err := s.readLocked()
	s.mu.RUnlock()
	if err != nil || arc == nil {
		return err
	}

	var n int

	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM snippets`).Scan(&n)
	if n == 0 {
		for _, e := range arc.Snippets {
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO snippets(id,name,type,config) VALUES(?,?,?,?)`,
				e.ID, e.Name, e.Type, e.Config)
		}
	}

	n = 0
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_channels`).Scan(&n)
	if n == 0 {
		for _, e := range arc.AlertChannels {
			enabled := 0
			if e.Enabled {
				enabled = 1
			}
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO alert_channels(id,name,type,config,enabled) VALUES(?,?,?,?,?)`,
				e.ID, e.Name, e.Type, e.Config, enabled)
		}
	}

	n = 0
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_rules`).Scan(&n)
	if n == 0 {
		for _, e := range arc.AlertRules {
			enabled := 0
			if e.Enabled {
				enabled = 1
			}
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO alert_rules(id,name,scope,triggers,channels,cooldown_sec,priority,enabled) VALUES(?,?,?,?,?,?,?,?)`,
				e.ID, e.Name, e.Scope, e.Triggers, e.Channels, e.CooldownSec, e.Priority, enabled)
		}
	}

	n = 0
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_profiles`).Scan(&n)
	if n == 0 {
		for _, e := range arc.IPProfiles {
			enabled := 0
			if e.Enabled {
				enabled = 1
			}
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO ip_profiles(id,name,profile_type,mode,feed_urls,feed_format,refresh_interval_h,cidrs,enabled) VALUES(?,?,?,?,?,?,?,?,?)`,
				e.ID, e.Name, e.ProfileType, e.Mode, e.FeedURLs, e.FeedFormat, e.RefreshIntervalH, e.CIDRs, enabled)
		}
	}

	n = 0
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_providers`).Scan(&n)
	if n == 0 {
		for _, e := range arc.AuthProviders {
			enabled := 0
			if e.Enabled {
				enabled = 1
			}
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO auth_providers(id,name,provider,config,enabled) VALUES(?,?,?,?,?)`,
				e.ID, e.Name, e.Provider, e.Config, enabled)
		}
	}

	n = 0
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM error_page_templates`).Scan(&n)
	if n == 0 {
		for _, t := range arc.ErrorPageTemplates {
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO error_page_templates(id,name,description,body,scope_type,scope_id) VALUES(?,?,?,?,?,?)`,
				t.ID, t.Name, t.Description, t.Body, t.ScopeType, nullableStr(t.ScopeID))
			for _, a := range t.Assets {
				content, decErr := base64.StdEncoding.DecodeString(a.ContentB64)
				if decErr != nil {
					continue
				}
				db.ExecContext(ctx, //nolint:errcheck
					`INSERT OR IGNORE INTO error_page_assets(id,template_id,filename,content_type,content) VALUES(?,?,?,?,?)`,
					a.ID, t.ID, a.Filename, a.ContentType, content)
			}
		}
	}

	return nil
}

func (s *ConfigStore) buildFromDB(ctx context.Context, db *sql.DB) (*ConfigArchive, error) {
	arc := &ConfigArchive{SchemaVersion: 1}

	rows, err := db.QueryContext(ctx, `SELECT id,name,type,config FROM snippets ORDER BY name`)
	if err == nil {
		for rows.Next() {
			var e SnippetEntry
			if rows.Scan(&e.ID, &e.Name, &e.Type, &e.Config) == nil {
				arc.Snippets = append(arc.Snippets, e)
			}
		}
		rows.Close()
	}

	rows, err = db.QueryContext(ctx, `SELECT id,name,type,config,enabled FROM alert_channels ORDER BY name`)
	if err == nil {
		for rows.Next() {
			var e AlertChannelEntry
			var enabled int
			if rows.Scan(&e.ID, &e.Name, &e.Type, &e.Config, &enabled) == nil {
				e.Enabled = enabled == 1
				arc.AlertChannels = append(arc.AlertChannels, e)
			}
		}
		rows.Close()
	}

	rows, err = db.QueryContext(ctx,
		`SELECT id,name,scope,triggers,channels,cooldown_sec,priority,enabled FROM alert_rules ORDER BY priority DESC,name`)
	if err == nil {
		for rows.Next() {
			var e AlertRuleEntry
			var enabled int
			if rows.Scan(&e.ID, &e.Name, &e.Scope, &e.Triggers, &e.Channels, &e.CooldownSec, &e.Priority, &enabled) == nil {
				e.Enabled = enabled == 1
				arc.AlertRules = append(arc.AlertRules, e)
			}
		}
		rows.Close()
	}

	rows, err = db.QueryContext(ctx,
		`SELECT id,name,profile_type,mode,feed_urls,feed_format,refresh_interval_h,cidrs,enabled FROM ip_profiles ORDER BY name`)
	if err == nil {
		for rows.Next() {
			var e IPProfileEntry
			var enabled int
			if rows.Scan(&e.ID, &e.Name, &e.ProfileType, &e.Mode, &e.FeedURLs, &e.FeedFormat, &e.RefreshIntervalH, &e.CIDRs, &enabled) == nil {
				e.Enabled = enabled == 1
				arc.IPProfiles = append(arc.IPProfiles, e)
			}
		}
		rows.Close()
	}

	rows, err = db.QueryContext(ctx, `SELECT id,name,provider,config,enabled FROM auth_providers ORDER BY name`)
	if err == nil {
		for rows.Next() {
			var e AuthProviderEntry
			var enabled int
			if rows.Scan(&e.ID, &e.Name, &e.Provider, &e.Config, &enabled) == nil {
				e.Enabled = enabled == 1
				arc.AuthProviders = append(arc.AuthProviders, e)
			}
		}
		rows.Close()
	}

	rows, err = db.QueryContext(ctx,
		`SELECT id,name,description,body,scope_type,COALESCE(scope_id,'') FROM error_page_templates ORDER BY name`)
	if err == nil {
		tplIdx := map[string]int{}
		for rows.Next() {
			var t ErrorPageTemplateEntry
			if rows.Scan(&t.ID, &t.Name, &t.Description, &t.Body, &t.ScopeType, &t.ScopeID) == nil {
				tplIdx[t.ID] = len(arc.ErrorPageTemplates)
				arc.ErrorPageTemplates = append(arc.ErrorPageTemplates, t)
			}
		}
		rows.Close()

		arows, aErr := db.QueryContext(ctx,
			`SELECT id,template_id,filename,content_type,content FROM error_page_assets ORDER BY template_id,filename`)
		if aErr == nil {
			for arows.Next() {
				var a ErrorPageAssetEntry
				var tid string
				var content []byte
				if arows.Scan(&a.ID, &tid, &a.Filename, &a.ContentType, &content) == nil {
					a.ContentB64 = base64.StdEncoding.EncodeToString(content)
					if idx, ok := tplIdx[tid]; ok {
						arc.ErrorPageTemplates[idx].Assets = append(arc.ErrorPageTemplates[idx].Assets, a)
					}
				}
			}
			arows.Close()
		}
	}

	return arc, nil
}

func (s *ConfigStore) readLocked() (*ConfigArchive, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("archstore/config: read: %w", err)
	}
	var arc ConfigArchive
	if err := yaml.Unmarshal(data, &arc); err != nil {
		return nil, fmt.Errorf("archstore/config: parse: %w", err)
	}
	return &arc, nil
}

func (s *ConfigStore) writeLocked(arc *ConfigArchive) error {
	if arc.SchemaVersion == 0 {
		arc.SchemaVersion = 1
	}
	data, err := yaml.Marshal(arc)
	if err != nil {
		return fmt.Errorf("archstore/config: marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("archstore/config: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-config-*")
	if err != nil {
		return fmt.Errorf("archstore/config: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("archstore/config: write: %w", err)
	}
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("archstore/config: close: %w", err)
	}
	_ = os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("archstore/config: rename: %w", err)
	}
	return nil
}
