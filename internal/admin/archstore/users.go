// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

const usersFilename = "users.yaml"

// UserScopeEntry est un scope RBAC direct sur un utilisateur.
type UserScopeEntry struct {
	ID         string `yaml:"id"`
	ScopeType  string `yaml:"scope_type"`
	ScopeValue string `yaml:"scope_value"`
	AccessMode string `yaml:"access_mode"`
}

// UserEntry décrit un compte admin (hash bcrypt — aucun secret en clair).
type UserEntry struct {
	ID           string           `yaml:"id"`
	Email        string           `yaml:"email"`
	PasswordHash string           `yaml:"password_hash"` // bcrypt, non réversible
	Role         string           `yaml:"role"`
	Scopes       []UserScopeEntry `yaml:"scopes,omitempty"`
}

// PATEntry décrit un token API utilisateur (hash SHA-256 — non réversible).
type PATEntry struct {
	ID          string   `yaml:"id"`
	UserID      string   `yaml:"user_id"`
	Label       string   `yaml:"label"`
	TokenHash   string   `yaml:"token_hash"`   // SHA-256 du secret en clair
	TokenPrefix string   `yaml:"token_prefix"` // aperçu non secret
	Scopes      []string `yaml:"scopes"`
	ExpiresAt   string   `yaml:"expires_at,omitempty"` // RFC3339
}

// TeamScopeEntry est un scope RBAC attaché à une équipe.
type TeamScopeEntry struct {
	ID         string `yaml:"id"`
	ScopeType  string `yaml:"scope_type"`
	ScopeValue string `yaml:"scope_value"`
	AccessMode string `yaml:"access_mode"`
}

// TeamEntry décrit une équipe et ses membres/scopes.
type TeamEntry struct {
	ID      string           `yaml:"id"`
	Name    string           `yaml:"name"`
	Members []string         `yaml:"members,omitempty"` // user IDs
	Scopes  []TeamScopeEntry `yaml:"scopes,omitempty"`
}

// UsersArchive est la racine de users.yaml.
type UsersArchive struct {
	SchemaVersion int         `yaml:"schema_version"`
	Users         []UserEntry `yaml:"users"`
	PATs          []PATEntry  `yaml:"pats"`
	Teams         []TeamEntry `yaml:"teams,omitempty"`
}

// UserStore lit et écrit users.yaml.
type UserStore struct {
	mu   sync.RWMutex
	path string
}

// NewUserStore crée un UserStore ciblant <dir>/users.yaml.
func NewUserStore(dir string) *UserStore {
	return &UserStore{path: filepath.Join(dir, usersFilename)}
}

// SyncFromDB (re)construit le fichier depuis la DB — appelé à chaque mutation.
func (s *UserStore) SyncFromDB(ctx context.Context, db *sql.DB) error {
	archive, err := s.buildFromDB(ctx, db)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(archive)
}

// LoadIntoDB ré-insère users + PATs depuis le fichier si les tables sont vides.
func (s *UserStore) LoadIntoDB(ctx context.Context, db *sql.DB) error {
	s.mu.RLock()
	archive, err := s.readLocked()
	s.mu.RUnlock()
	if err != nil || archive == nil {
		return err
	}

	var userCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&userCount)
	if userCount == 0 {
		for _, u := range archive.Users {
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO users(id, email, password_hash, role) VALUES(?,?,?,?)`,
				u.ID, u.Email, u.PasswordHash, u.Role)
			for _, sc := range u.Scopes {
				db.ExecContext(ctx, //nolint:errcheck
					`INSERT OR IGNORE INTO user_scopes(id, user_id, scope_type, scope_value, access_mode) VALUES(?,?,?,?,?)`,
					sc.ID, u.ID, sc.ScopeType, sc.ScopeValue, sc.AccessMode)
			}
		}
	}

	var patCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_api_tokens`).Scan(&patCount)
	if patCount == 0 {
		for _, p := range archive.PATs {
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO user_api_tokens(id, user_id, label, token_hash, token_prefix, expires_at)
				 VALUES(?,?,?,?,?,?)`,
				p.ID, p.UserID, p.Label, p.TokenHash, p.TokenPrefix, nullableStr(p.ExpiresAt))
			for _, sc := range p.Scopes {
				db.ExecContext(ctx, //nolint:errcheck
					`INSERT OR IGNORE INTO user_api_token_scopes(token_id, scope) VALUES(?,?)`,
					p.ID, sc)
			}
		}
	}

	var teamCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM teams`).Scan(&teamCount)
	if teamCount == 0 {
		for _, te := range archive.Teams {
			db.ExecContext(ctx, //nolint:errcheck
				`INSERT OR IGNORE INTO teams(id, name) VALUES(?,?)`, te.ID, te.Name)
			for _, uid := range te.Members {
				db.ExecContext(ctx, //nolint:errcheck
					`INSERT OR IGNORE INTO team_members(team_id, user_id) VALUES(?,?)`, te.ID, uid)
			}
			for _, sc := range te.Scopes {
				db.ExecContext(ctx, //nolint:errcheck
					`INSERT OR IGNORE INTO team_scopes(id, team_id, scope_type, scope_value, access_mode) VALUES(?,?,?,?,?)`,
					sc.ID, te.ID, sc.ScopeType, sc.ScopeValue, sc.AccessMode)
			}
		}
	}

	return nil
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *UserStore) buildFromDB(ctx context.Context, db *sql.DB) (*UsersArchive, error) {
	archive := &UsersArchive{SchemaVersion: 1}

	urows, err := db.QueryContext(ctx,
		`SELECT id, email, password_hash, role FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("archstore/users: query users: %w", err)
	}
	defer urows.Close()
	userIdx := map[string]int{}
	for urows.Next() {
		var u UserEntry
		if urows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role) == nil {
			userIdx[u.ID] = len(archive.Users)
			archive.Users = append(archive.Users, u)
		}
	}
	urows.Close()

	// user_scopes — attachés à chaque UserEntry
	usrows, err := db.QueryContext(ctx,
		`SELECT id, user_id, scope_type, scope_value, access_mode FROM user_scopes ORDER BY user_id`)
	if err == nil {
		defer usrows.Close()
		for usrows.Next() {
			var sc UserScopeEntry
			var uid string
			if usrows.Scan(&sc.ID, &uid, &sc.ScopeType, &sc.ScopeValue, &sc.AccessMode) == nil {
				if idx, ok := userIdx[uid]; ok {
					archive.Users[idx].Scopes = append(archive.Users[idx].Scopes, sc)
				}
			}
		}
		usrows.Close()
	}

	prows, err := db.QueryContext(ctx,
		`SELECT id, user_id, label, token_hash, token_prefix,
		        COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', expires_at), '')
		 FROM user_api_tokens
		 WHERE revoked=0
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		 ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("archstore/users: query pats: %w", err)
	}
	defer prows.Close()
	patIdx := map[string]int{}
	for prows.Next() {
		var p PATEntry
		if prows.Scan(&p.ID, &p.UserID, &p.Label, &p.TokenHash, &p.TokenPrefix, &p.ExpiresAt) == nil {
			patIdx[p.ID] = len(archive.PATs)
			archive.PATs = append(archive.PATs, p)
		}
	}
	prows.Close()

	scrows, err := db.QueryContext(ctx,
		`SELECT token_id, scope FROM user_api_token_scopes ORDER BY token_id, scope`)
	if err == nil {
		defer scrows.Close()
		for scrows.Next() {
			var tid, sc string
			if scrows.Scan(&tid, &sc) == nil {
				if idx, ok := patIdx[tid]; ok {
					archive.PATs[idx].Scopes = append(archive.PATs[idx].Scopes, sc)
				}
			}
		}
	}

	// Teams + members + scopes
	trows, err := db.QueryContext(ctx, `SELECT id, name FROM teams ORDER BY name`)
	if err == nil {
		defer trows.Close()
		teamIdx := map[string]int{}
		for trows.Next() {
			var te TeamEntry
			if trows.Scan(&te.ID, &te.Name) == nil {
				teamIdx[te.ID] = len(archive.Teams)
				archive.Teams = append(archive.Teams, te)
			}
		}
		trows.Close()

		mrows, _ := db.QueryContext(ctx, `SELECT team_id, user_id FROM team_members ORDER BY team_id`)
		if mrows != nil {
			for mrows.Next() {
				var tid, uid string
				if mrows.Scan(&tid, &uid) == nil {
					if idx, ok := teamIdx[tid]; ok {
						archive.Teams[idx].Members = append(archive.Teams[idx].Members, uid)
					}
				}
			}
			mrows.Close()
		}

		tsrows, _ := db.QueryContext(ctx,
			`SELECT id, team_id, scope_type, scope_value, access_mode FROM team_scopes ORDER BY team_id`)
		if tsrows != nil {
			for tsrows.Next() {
				var sc TeamScopeEntry
				var tid string
				if tsrows.Scan(&sc.ID, &tid, &sc.ScopeType, &sc.ScopeValue, &sc.AccessMode) == nil {
					if idx, ok := teamIdx[tid]; ok {
						archive.Teams[idx].Scopes = append(archive.Teams[idx].Scopes, sc)
					}
				}
			}
			tsrows.Close()
		}
	}

	return archive, nil
}

func (s *UserStore) readLocked() (*UsersArchive, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("archstore/users: read: %w", err)
	}
	var archive UsersArchive
	if err := yaml.Unmarshal(data, &archive); err != nil {
		return nil, fmt.Errorf("archstore/users: parse: %w", err)
	}
	return &archive, nil
}

func (s *UserStore) writeLocked(archive *UsersArchive) error {
	if archive.SchemaVersion == 0 {
		archive.SchemaVersion = 1
	}
	data, err := yaml.Marshal(archive)
	if err != nil {
		return fmt.Errorf("archstore/users: marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("archstore/users: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-users-*")
	if err != nil {
		return fmt.Errorf("archstore/users: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("archstore/users: write: %w", err)
	}
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("archstore/users: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("archstore/users: chmod: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("archstore/users: rename: %w", err)
	}
	return nil
}
