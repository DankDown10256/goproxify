// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package bansdb fournit une base SQLite locale au Core pour les bans actifs,
// l'historique des bans et le journal d'erreurs proxy.
// Elle remplace les ring buffers en mémoire et le fichier bans.json.
package bansdb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultDir = "/etc/goproxify/bansdb"
	envPathKey = "GPX_BANSDB_PATH"
)

// Dir retourne le répertoire de la base (env GPX_BANSDB_PATH ou défaut).
func Dir() string {
	if p := os.Getenv(envPathKey); p != "" {
		return p
	}
	return defaultDir
}

// DB encapsule la connexion SQLite des bans Core.
type DB struct {
	db *sql.DB
}

// Open ouvre (ou crée) la base SQLite bans du Core.
func Open(dir string) (*DB, error) {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("bansdb: mkdir: %w", err)
	}
	dsn := filepath.Join(dir, "bans.db") +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("bansdb: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bansdb: migrate: %w", err)
	}
	return &DB{db: db}, nil
}

// Close ferme la connexion.
func (d *DB) Close() error { return d.db.Close() }

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS bans (
			id         TEXT PRIMARY KEY,
			ip         TEXT NOT NULL,
			domain     TEXT NOT NULL DEFAULT '',
			reason     TEXT NOT NULL DEFAULT '',
			source     TEXT NOT NULL DEFAULT 'native',
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans (ip)`,
		`CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans (expires_at)`,
		`CREATE TABLE IF NOT EXISTS ban_history (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ip         TEXT NOT NULL,
			source     TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bh_ip ON ban_history (ip)`,
		`CREATE INDEX IF NOT EXISTS idx_bh_created ON ban_history (created_at)`,
		`CREATE TABLE IF NOT EXISTS proxy_errors (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			host       TEXT NOT NULL,
			is_error   INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pe_host ON proxy_errors (host)`,
		`CREATE INDEX IF NOT EXISTS idx_pe_created ON proxy_errors (created_at)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// --- Bans actifs -----------------------------------------------------------

// UpsertBan insère ou remplace un ban actif.
func (d *DB) UpsertBan(id, ip, domain, reason, source string, expiresAt *time.Time) error {
	var exp *string
	if expiresAt != nil && !expiresAt.IsZero() {
		s := expiresAt.UTC().Format(time.RFC3339)
		exp = &s
	}
	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO bans (id, ip, domain, reason, source, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, ip, domain, reason, source, exp,
	)
	return err
}

// DeleteBan supprime un ban par son ID.
func (d *DB) DeleteBan(id string) error {
	_, err := d.db.Exec(`DELETE FROM bans WHERE id=?`, id)
	return err
}

// DeleteBansBySource supprime tous les bans d'une source (ex: "crowdsec").
func (d *DB) DeleteBansBySource(source string) error {
	_, err := d.db.Exec(`DELETE FROM bans WHERE source=?`, source)
	return err
}

// ActiveBans retourne tous les bans non expirés.
func (d *DB) ActiveBans() ([]BanRow, error) {
	rows, err := d.db.Query(
		`SELECT id, ip, domain, reason, source, expires_at, created_at
		 FROM bans WHERE expires_at IS NULL OR expires_at > datetime('now')
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBanRows(rows)
}

// PurgeExpiredBans supprime les bans expirés.
func (d *DB) PurgeExpiredBans() error {
	_, err := d.db.Exec(`DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')`)
	return err
}

// BanRow représente un ban actif en DB.
type BanRow struct {
	ID        string
	IP        string
	Domain    string
	Reason    string
	Source    string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

func scanBanRows(rows *sql.Rows) ([]BanRow, error) {
	var out []BanRow
	for rows.Next() {
		var r BanRow
		var exp, created string
		var expNull sql.NullString
		if err := rows.Scan(&r.ID, &r.IP, &r.Domain, &r.Reason, &r.Source, &expNull, &created); err != nil {
			return nil, err
		}
		if expNull.Valid {
			exp = expNull.String
			if t, err := time.Parse(time.RFC3339, exp); err == nil {
				r.ExpiresAt = &t
			}
		}
		if t, err := time.Parse("2006-01-02T15:04:05Z", created); err == nil {
			r.CreatedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Historique des bans --------------------------------------------------

// RecordBanEvent enregistre un ban dans l'historique.
func (d *DB) RecordBanEvent(ip, source string) error {
	_, err := d.db.Exec(
		`INSERT INTO ban_history (ip, source) VALUES (?, ?)`,
		ip, source,
	)
	return err
}

// RecentBanCount retourne le nombre de bans depuis `since` (source="" = toutes).
func (d *DB) RecentBanCount(since time.Time, source string) (int, error) {
	var n int
	var err error
	if source == "" {
		err = d.db.QueryRow(
			`SELECT COUNT(*) FROM ban_history WHERE created_at >= ?`,
			since.UTC().Format(time.RFC3339),
		).Scan(&n)
	} else {
		err = d.db.QueryRow(
			`SELECT COUNT(*) FROM ban_history WHERE created_at >= ? AND source=?`,
			since.UTC().Format(time.RFC3339), source,
		).Scan(&n)
	}
	return n, err
}

// RepeatBanIP retourne l'IP avec le plus de bans (≥ minCount) depuis `since`.
func (d *DB) RepeatBanIP(since time.Time, minCount int) (ip string, count int, err error) {
	row := d.db.QueryRow(
		`SELECT ip, COUNT(*) AS n FROM ban_history
		 WHERE created_at >= ?
		 GROUP BY ip HAVING n >= ?
		 ORDER BY n DESC LIMIT 1`,
		since.UTC().Format(time.RFC3339), minCount,
	)
	err = row.Scan(&ip, &count)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return ip, count, err
}

// BanHistorySince retourne les entrées d'historique depuis `since`.
func (d *DB) BanHistorySince(since time.Time) ([]HistoryRow, error) {
	rows, err := d.db.Query(
		`SELECT ip, source, created_at FROM ban_history
		 WHERE created_at >= ? ORDER BY created_at DESC LIMIT 1000`,
		since.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryRow
	for rows.Next() {
		var r HistoryRow
		var created string
		if err := rows.Scan(&r.IP, &r.Source, &created); err != nil {
			return nil, err
		}
		if t, err := time.Parse("2006-01-02T15:04:05Z", created); err == nil {
			r.CreatedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HistoryRow représente une entrée de l'historique des bans.
type HistoryRow struct {
	IP        string    `json:"ip"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// PurgeBanHistory supprime les entrées antérieures à `before`.
func (d *DB) PurgeBanHistory(before time.Time) error {
	_, err := d.db.Exec(
		`DELETE FROM ban_history WHERE created_at < ?`,
		before.UTC().Format(time.RFC3339),
	)
	return err
}

// --- Journal erreurs proxy ------------------------------------------------

// RecordProxyEvent enregistre une requête proxy (isError=true si status ≥ 500).
func (d *DB) RecordProxyEvent(host string, isError bool) error {
	isErr := 0
	if isError {
		isErr = 1
	}
	_, err := d.db.Exec(
		`INSERT INTO proxy_errors (host, is_error) VALUES (?, ?)`,
		host, isErr,
	)
	return err
}

// ProxyErrorRate retourne le pire taux d'erreurs HTTP parmi tous les domaines.
// Seuls les domaines avec > minRequests requêtes sont considérés.
func (d *DB) ProxyErrorRate(since time.Time, minRequests int) (rate float64, host string, err error) {
	rows, err := d.db.Query(
		`SELECT host,
		        COUNT(*) AS total,
		        SUM(is_error) AS errs
		 FROM proxy_errors
		 WHERE created_at >= ?
		 GROUP BY host
		 HAVING total >= ?
		 ORDER BY (CAST(errs AS REAL)/total) DESC
		 LIMIT 1`,
		since.UTC().Format(time.RFC3339), minRequests,
	)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	if rows.Next() {
		var total, errs int
		if err := rows.Scan(&host, &total, &errs); err != nil {
			return 0, "", err
		}
		if total > 0 {
			rate = float64(errs) / float64(total) * 100
		}
	}
	return rate, host, rows.Err()
}

// PurgeProxyErrors supprime les entrées antérieures à `before`.
func (d *DB) PurgeProxyErrors(before time.Time) error {
	_, err := d.db.Exec(
		`DELETE FROM proxy_errors WHERE created_at < ?`,
		before.UTC().Format(time.RFC3339),
	)
	return err
}
