// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package tokens gère la base locale des tokens d'authentification du Core.
// Chaque Core détient sa propre table : tokens Admin (push routes/certs)
// et tokens Agent (heartbeat/containers).
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS tokens (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL DEFAULT 'agent',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    revoked    INTEGER NOT NULL DEFAULT 0
);
`

// Role représente le rôle d'un token dans le Core.
type Role string

const (
	RoleAdmin Role = "admin" // Admin : push routes, certs, settings
	RoleAgent Role = "agent" // Agent : heartbeat, containers, events, logs
)

// Token est une entrée de la table locale.
type Token struct {
	ID        string
	Name      string
	Role      Role
	CreatedAt time.Time
	ExpiresAt *time.Time
	Revoked   bool
}

// Store est le gestionnaire de tokens du Core.
type Store struct {
	db *sql.DB
}

// Open ouvre (ou crée) la base SQLite au chemin donné.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("tokens: open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("tokens: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close ferme la base.
func (s *Store) Close() error { return s.db.Close() }

// Bootstrap insère un token initial si la table est vide.
// Utilisé au premier démarrage pour amorcer le token Admin depuis la config.
func (s *Store) Bootstrap(name, rawToken string, role Role) error {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE revoked=0`).Scan(&n)
	if n > 0 {
		return nil
	}
	_, err := s.insert(name, rawToken, role, nil)
	return err
}

// EnsureToken s'assure qu'un token est présent et non révoqué dans le store,
// en l'insérant s'il est absent. Utilisé après un appairage pour garantir
// la cohérence même si la DB n'est pas vide.
func (s *Store) EnsureToken(name, rawToken string, role Role) error {
	h := hash(rawToken)
	var revoked int
	err := s.db.QueryRow(`SELECT revoked FROM tokens WHERE token_hash=?`, h).Scan(&revoked)
	if err == sql.ErrNoRows {
		_, err = s.insert(name, rawToken, role, nil)
		return err
	}
	if err != nil {
		return err
	}
	// Token présent mais révoqué : le réactiver.
	if revoked != 0 {
		_, err = s.db.Exec(`UPDATE tokens SET revoked=0 WHERE token_hash=?`, h)
	}
	return err
}

// Create génère un nouveau token, l'insère et retourne la valeur en clair.
// prefix : "gpx_admin_" ou "gpx_agent_"
func (s *Store) Create(name string, role Role, ttl time.Duration) (rawToken string, id string, err error) {
	prefix := map[Role]string{
		RoleAdmin: "gpx_admin_",
		RoleAgent: "gpx_agent_",
	}[role]
	if prefix == "" {
		prefix = "gpx_"
	}

	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("tokens: rand: %w", err)
	}
	rawToken = prefix + hex.EncodeToString(b)

	var exp *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		exp = &t
	}

	id, err = s.insert(name, rawToken, role, exp)
	return rawToken, id, err
}

// Validate vérifie qu'un token en clair est valide (non révoqué, non expiré).
func (s *Store) Validate(rawToken string) (bool, error) {
	h := hash(rawToken)
	var revoked int
	var expiresAt *time.Time
	err := s.db.QueryRow(
		`SELECT revoked, expires_at FROM tokens WHERE token_hash=?`, h,
	).Scan(&revoked, &expiresAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if revoked != 0 {
		return false, nil
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return false, nil
	}
	return true, nil
}

// List retourne tous les tokens (sans les valeurs en clair).
func (s *Store) List() ([]Token, error) {
	rows, err := s.db.Query(
		`SELECT id, name, role, created_at, expires_at, revoked FROM tokens ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Token
	for rows.Next() {
		var t Token
		var exp *time.Time
		var rev int
		if err := rows.Scan(&t.ID, &t.Name, &t.Role, &t.CreatedAt, &exp, &rev); err != nil {
			continue
		}
		t.ExpiresAt = exp
		t.Revoked = rev != 0
		list = append(list, t)
	}
	return list, nil
}

// Revoke marque un token comme révoqué à partir de son ID.
func (s *Store) Revoke(id string) error {
	if id == "" {
		return fmt.Errorf("tokens: id vide")
	}
	res, err := s.db.Exec(`UPDATE tokens SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tokens: id %q introuvable", id)
	}
	return nil
}

// RevokeByRaw marque un token comme révoqué à partir de sa valeur en clair.
func (s *Store) RevokeByRaw(rawToken string) error {
	if rawToken == "" {
		return nil
	}
	_, err := s.db.Exec(`UPDATE tokens SET revoked=1 WHERE token_hash=?`, hash(rawToken))
	return err
}

// --------------------------------------------------------------------------

func (s *Store) insert(name, rawToken string, role Role, exp *time.Time) (string, error) {
	id := newID()
	h := hash(rawToken)
	_, err := s.db.Exec(
		`INSERT INTO tokens(id, name, token_hash, role, expires_at) VALUES(?,?,?,?,?)`,
		id, name, h, string(role), exp,
	)
	return id, err
}

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return strings.TrimRight(hex.EncodeToString(b), "0")
}
