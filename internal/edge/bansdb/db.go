// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package bansdb fournit une base SQLite locale à la passerelle pour les bans actifs,
// l'historique des bans et le journal d'erreurs proxy.
// Elle remplace les ring buffers en mémoire et le fichier bans.json.
package bansdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/edge/router"
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

// DB encapsule la connexion SQLite des bans passerelle.
type DB struct {
	db *sql.DB
}

// Open ouvre (ou crée) la base SQLite bans de la passerelle.
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
		`CREATE TABLE IF NOT EXISTS unbans (
			ip TEXT PRIMARY KEY,
			at TEXT NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	// Colonne ajoutée après coup : l'erreur « duplicate column » sur une base à jour est attendue.
	_, _ = db.Exec(`ALTER TABLE bans ADD COLUMN scope TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE bans ADD COLUMN signals TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE bans ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`)
	return nil
}

// --- Bans actifs -----------------------------------------------------------

// UpsertBan insère ou remplace un ban actif sans restriction de passerelle.
func (d *DB) UpsertBan(id, ip, domain, reason, source string, expiresAt *time.Time) error {
	return d.UpsertScopedBan(id, ip, domain, reason, source, "", expiresAt)
}

// UpsertScopedBan insère ou remplace un ban actif ; scope (nom de passerelle ou "group:<nom>") est conservé
// pour ne pas le transmettre aux pairs qu'il ne vise pas.
func (d *DB) UpsertScopedBan(id, ip, domain, reason, source, scope string, expiresAt *time.Time) error {
	return d.upsert(id, ip, domain, reason, source, scope, nil, "", expiresAt)
}

// UpsertRuntimeBan insère ou remplace un ban actif avec ce qui l'explique : signaux (Ephor, WAF) et User-Agent.
func (d *DB) UpsertRuntimeBan(b *router.RuntimeBan) error {
	return d.upsert(b.ID, b.IP, "", b.Reason, b.Source, b.Scope, b.Signals, b.UserAgent, b.ExpiresAt)
}

func (d *DB) upsert(id, ip, domain, reason, source, scope string, signals []router.BanSignal, userAgent string, expiresAt *time.Time) error {
	var exp *string
	if expiresAt != nil && !expiresAt.IsZero() {
		s := expiresAt.UTC().Format(time.RFC3339)
		exp = &s
	}
	var sig string
	if len(signals) > 0 {
		if raw, err := json.Marshal(signals); err == nil {
			sig = string(raw)
		}
	}
	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO bans (id, ip, domain, reason, source, scope, signals, user_agent, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ip, domain, reason, source, scope, sig, userAgent, exp,
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
		`SELECT id, ip, domain, reason, source, expires_at, created_at, scope, signals, user_agent
		 FROM bans WHERE expires_at IS NULL OR expires_at > ?
		 ORDER BY created_at DESC`,
		nowExpiry(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBanRows(rows)
}

// sqlTime est le format de CURRENT_TIMESTAMP (created_at) : les comparaisons SQL restent lexicographiques.
const sqlTime = "2006-01-02 15:04:05"

// nowExpiry est l'instant présent au format de bans.expires_at (RFC3339, écrit par UpsertBan) :
// datetime('now') compare mal ('T' > ' '), un ban expiré resterait actif jusqu'à minuit UTC.
func nowExpiry() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// Unban lève tous les bans de l'IP posés jusqu'à `at`, quelle que soit leur source, et retient la date
// du déban pour qu'un pair ne réinjecte pas un de ces bans (voir Unbans).
func (d *DB) Unban(ip string, at time.Time) error {
	ts := at.UTC().Format(sqlTime)
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM bans WHERE ip=? AND created_at <= ?`, ip, ts); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO unbans (ip, at) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET at=MAX(at, excluded.at)`,
		ip, ts,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// Unbans retourne la date du dernier déban de chaque IP.
func (d *DB) Unbans() (map[string]time.Time, error) {
	rows, err := d.db.Query(`SELECT ip, at FROM unbans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var ip, at string
		if err := rows.Scan(&ip, &at); err != nil {
			return nil, err
		}
		if t, err := time.Parse(sqlTime, at); err == nil {
			out[ip] = t
		}
	}
	return out, rows.Err()
}

// PurgeUnbans oublie les débans antérieurs à `before`.
func (d *DB) PurgeUnbans(before time.Time) error {
	_, err := d.db.Exec(`DELETE FROM unbans WHERE at < ?`, before.UTC().Format(sqlTime))
	return err
}

// PurgeExpiredBans supprime les bans expirés.
func (d *DB) PurgeExpiredBans() error {
	_, err := d.db.Exec(`DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?`, nowExpiry())
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
	Scope     string
	Signals   []router.BanSignal
	UserAgent string
}

func scanBanRows(rows *sql.Rows) ([]BanRow, error) {
	var out []BanRow
	for rows.Next() {
		var r BanRow
		var exp, created, signals string
		var expNull sql.NullString
		if err := rows.Scan(&r.ID, &r.IP, &r.Domain, &r.Reason, &r.Source, &expNull, &created, &r.Scope, &signals, &r.UserAgent); err != nil {
			return nil, err
		}
		if signals != "" {
			_ = json.Unmarshal([]byte(signals), &r.Signals)
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
			since.UTC().Format(sqlTime),
		).Scan(&n)
	} else {
		err = d.db.QueryRow(
			`SELECT COUNT(*) FROM ban_history WHERE created_at >= ? AND source=?`,
			since.UTC().Format(sqlTime), source,
		).Scan(&n)
	}
	return n, err
}

// BanCountForIP retourne le nombre de bans de la source posés sur l'IP depuis `since`, sans compter
// ceux qui précèdent son dernier déban (un déban manuel remet la récidive à zéro).
func (d *DB) BanCountForIP(ip, source string, since time.Time) (int, error) {
	var n int
	err := d.db.QueryRow(
		`SELECT COUNT(*) FROM ban_history
		 WHERE ip=? AND source=? AND created_at >= ?
		   AND created_at > COALESCE((SELECT at FROM unbans WHERE ip=?), '')`,
		ip, source, since.UTC().Format(sqlTime), ip,
	).Scan(&n)
	return n, err
}

// RepeatBanIP retourne l'IP avec le plus de bans (≥ minCount) depuis `since`.
func (d *DB) RepeatBanIP(since time.Time, minCount int) (ip string, count int, err error) {
	row := d.db.QueryRow(
		`SELECT ip, COUNT(*) AS n FROM ban_history
		 WHERE created_at >= ?
		 GROUP BY ip HAVING n >= ?
		 ORDER BY n DESC LIMIT 1`,
		since.UTC().Format(sqlTime), minCount,
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
		since.UTC().Format(sqlTime),
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
		before.UTC().Format(sqlTime),
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
		since.UTC().Format(sqlTime), minRequests,
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
		before.UTC().Format(sqlTime),
	)
	return err
}

// EraseIP supprime les bans et l'historique d'une IP (droit à l'effacement RGPD) et retourne le
// nombre de lignes retirées. Le déban (table unbans) reste : il empêche de reposer un ban levé.
func (d *DB) EraseIP(ips ...string) (int64, error) {
	var total int64
	for _, ip := range ips {
		for _, table := range []string{"bans", "ban_history"} {
			res, err := d.db.Exec(`DELETE FROM `+table+` WHERE ip = ?`, ip)
			if err != nil {
				return total, err
			}
			n, _ := res.RowsAffected()
			total += n
		}
	}
	return total, nil
}
