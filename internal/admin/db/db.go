// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package db gère l'initialisation SQLite et les migrations pour l'Administration.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	_ "modernc.org/sqlite" // pilote SQLite CGO-free
)

// Open ouvre (ou crée) la base SQLite au chemin indiqué et applique les migrations.
func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("création répertoire SQLite %q : %w", filepath.Dir(path), err)
	}

	// Les paramètres _pragma sont appliqués sur CHAQUE connexion créée par le pool,
	// contrairement à db.Exec("PRAGMA ...") qui n'affecte qu'une seule connexion.
	// busy_timeout=10000 : attend jusqu'à 10 s avant de retourner SQLITE_BUSY.
	// journal_mode=WAL : lectures concurrentes sans bloquer les écritures.
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ouverture SQLite %q : %w", path, err)
	}

	// WAL supporte plusieurs lecteurs simultanés et un seul écrivain.
	// busy_timeout (dans le DSN ci-dessus) gère les conflits d'écriture concurrents.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping SQLite %q : %w", path, err)
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migration SQLite : %w", err)
	}

	return db, nil
}

// migrate applique les CREATE TABLE IF NOT EXISTS au démarrage.
func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id           TEXT PRIMARY KEY,
			email        TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role         TEXT NOT NULL DEFAULT 'user',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS proxies (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			config     TEXT NOT NULL,
			enabled    INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id            TEXT PRIMARY KEY,
			token         TEXT UNIQUE NOT NULL,
			role          TEXT NOT NULL,
			node_name     TEXT NOT NULL,
			node_endpoint TEXT,
			expires_at    DATETIME,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			revoked       INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS certs (
			id         TEXT PRIMARY KEY,
			domain     TEXT UNIQUE NOT NULL,
			issuer     TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS snippets (
			id         TEXT PRIMARY KEY,
			name       TEXT UNIQUE NOT NULL,
			type       TEXT NOT NULL,
			config     TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			actor      TEXT NOT NULL,
			action     TEXT NOT NULL,
			resource   TEXT NOT NULL,
			detail     TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Nœuds enregistrés (Cores + Agents) avec leur dernier heartbeat
		`CREATE TABLE IF NOT EXISTS nodes (
			id           TEXT PRIMARY KEY,
			node_name    TEXT UNIQUE NOT NULL,
			role         TEXT NOT NULL,
			version      TEXT NOT NULL DEFAULT '',
			endpoint     TEXT NOT NULL DEFAULT '',
			cpu_pct      REAL,
			mem_pct      REAL,
			status       TEXT NOT NULL DEFAULT 'online',
			last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Historique des événements de santé et de lifecycle
		`CREATE TABLE IF NOT EXISTS node_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			node_name    TEXT NOT NULL,
			container_id TEXT,
			event_type   TEXT NOT NULL,
			detail       TEXT,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Canaux de notification (email, webhook, ntfy, gotify, jira, linear, github, gitlab, zammad, glpi)
		`CREATE TABLE IF NOT EXISTS alert_channels (
			id         TEXT PRIMARY KEY,
			name       TEXT UNIQUE NOT NULL,
			type       TEXT NOT NULL,
			config     TEXT NOT NULL DEFAULT '{}',
			enabled    INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Règles de routage d'alertes
		`CREATE TABLE IF NOT EXISTS alert_rules (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			scope        TEXT NOT NULL DEFAULT '{}',
			triggers     TEXT NOT NULL DEFAULT '[]',
			channels     TEXT NOT NULL DEFAULT '[]',
			cooldown_sec INTEGER NOT NULL DEFAULT 300,
			priority     INTEGER NOT NULL DEFAULT 0,
			enabled      INTEGER NOT NULL DEFAULT 1,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Journal des alertes émises (pour le cooldown et l'historique)
		`CREATE TABLE IF NOT EXISTS alert_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id      TEXT NOT NULL,
			trigger      TEXT NOT NULL,
			detail       TEXT NOT NULL DEFAULT '{}',
			channels     TEXT NOT NULL DEFAULT '[]',
			fired_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Logs agrégés (accès HTTP + système + agents)
		`CREATE TABLE IF NOT EXISTS logs (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts         DATETIME NOT NULL,
			level      TEXT NOT NULL DEFAULT 'info',
			component  TEXT NOT NULL DEFAULT 'admin',
			node_name  TEXT NOT NULL DEFAULT '',
			domain     TEXT NOT NULL DEFAULT '',
			method     TEXT NOT NULL DEFAULT '',
			path       TEXT NOT NULL DEFAULT '',
			status     INTEGER NOT NULL DEFAULT 0,
			ip         TEXT NOT NULL DEFAULT '',
			latency_ms INTEGER NOT NULL DEFAULT 0,
			bytes      INTEGER NOT NULL DEFAULT 0,
			message    TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_ts        ON logs (ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_level     ON logs (level)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_component ON logs (component)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_domain    ON logs (domain)`,
		// Prism : accès HTTP (status>0) filtrés par période ± domaine — partial indexes.
		`CREATE INDEX IF NOT EXISTS idx_logs_access_ts ON logs (ts) WHERE status > 0`,
		`CREATE INDEX IF NOT EXISTS idx_logs_access_domain_ts ON logs (domain, ts) WHERE status > 0`,
		// Bans IP (Fail2Ban, CrowdSec, natif)
		`CREATE TABLE IF NOT EXISTS security_bans (
			id         TEXT PRIMARY KEY,
			ip         TEXT NOT NULL,
			domain     TEXT NOT NULL DEFAULT '',
			reason     TEXT NOT NULL DEFAULT '',
			source     TEXT NOT NULL DEFAULT 'native',
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bans_ip ON security_bans (ip)`,
		// Décisions CrowdSec
		`CREATE TABLE IF NOT EXISTS security_threats (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ip         TEXT NOT NULL,
			scenario   TEXT NOT NULL DEFAULT '',
			origin     TEXT NOT NULL DEFAULT '',
			type       TEXT NOT NULL DEFAULT 'ban',
			duration   TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_threats_ip_scenario ON security_threats (ip, scenario)`,
		// CVE détectées sur les backends
		`CREATE TABLE IF NOT EXISTS security_cves (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			backend_url TEXT NOT NULL,
			cve_id      TEXT NOT NULL,
			cvss_score  REAL NOT NULL DEFAULT 0,
			description TEXT NOT NULL DEFAULT '',
			status      TEXT NOT NULL DEFAULT 'open',
			detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_cves_unique ON security_cves (backend_url, cve_id)`,
		`CREATE TABLE IF NOT EXISTS geoip_cache (
			ip           TEXT PRIMARY KEY,
			country_code TEXT NOT NULL DEFAULT '',
			country_name TEXT NOT NULL DEFAULT '',
			cached_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Planification des sauvegardes automatiques
		`CREATE TABLE IF NOT EXISTS backup_schedule (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '{}'
		)`,
		// Sauvegardes stockées (JSON complet)
		`CREATE TABLE IF NOT EXISTS backup_snapshots (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			schedule_id TEXT NOT NULL DEFAULT '',
			size        INTEGER NOT NULL DEFAULT 0,
			data        TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Historique par proxy (versioning)
		`CREATE TABLE IF NOT EXISTS proxy_history (
			id         TEXT PRIMARY KEY,
			proxy_id   TEXT NOT NULL,
			config     TEXT NOT NULL,
			note       TEXT NOT NULL DEFAULT 'auto',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_history ON proxy_history (proxy_id, created_at DESC)`,
		// Paramètres généraux de l'administration (clé/valeur)
		`CREATE TABLE IF NOT EXISTS settings (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// MFA : méthodes activées par utilisateur
		`CREATE TABLE IF NOT EXISTS user_mfa (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			method     TEXT NOT NULL,
			config     TEXT NOT NULL DEFAULT '{}',
			enabled    INTEGER NOT NULL DEFAULT 1,
			verified   INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, method)
		)`,
		// MFA : challenges en cours (OTP, WebAuthn)
		`CREATE TABLE IF NOT EXISTS user_mfa_challenges (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			method     TEXT NOT NULL,
			code_hash  TEXT NOT NULL DEFAULT '',
			data       TEXT NOT NULL DEFAULT '{}',
			expires_at DATETIME NOT NULL,
			used       INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// MFA : codes de secours (backup codes)
		`CREATE TABLE IF NOT EXISTS user_backup_codes (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			code_hash  TEXT NOT NULL,
			used       INTEGER NOT NULL DEFAULT 0,
			used_at    DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// MFA : appareils de confiance
		`CREATE TABLE IF NOT EXISTS user_trusted_devices (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			token_hash   TEXT NOT NULL UNIQUE,
			name         TEXT NOT NULL DEFAULT '',
			expires_at   DATETIME NOT NULL,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Fournisseurs SSO/Auth partagés (poussés vers les Cores)
		`CREATE TABLE IF NOT EXISTS auth_providers (
			id         TEXT PRIMARY KEY,
			name       TEXT UNIQUE NOT NULL,
			provider   TEXT NOT NULL,
			config     TEXT NOT NULL DEFAULT '{}',
			enabled    INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Profils de filtrage IP (listes publiques avec mise à jour automatique)
		`CREATE TABLE IF NOT EXISTS ip_profiles (
			id                TEXT PRIMARY KEY,
			name              TEXT UNIQUE NOT NULL,
			profile_type      TEXT NOT NULL DEFAULT 'custom',
			mode              TEXT NOT NULL DEFAULT 'deny',
			feed_urls         TEXT NOT NULL DEFAULT '[]',
			feed_format       TEXT NOT NULL DEFAULT 'plain',
			refresh_interval_h INTEGER NOT NULL DEFAULT 24,
			cidrs             TEXT NOT NULL DEFAULT '[]',
			last_updated_at   DATETIME,
			enabled           INTEGER NOT NULL DEFAULT 1,
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration : %w", err)
		}
	}

	// Scopes par token (RBAC côté Core — idempotent).
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS token_scopes (
			id          TEXT PRIMARY KEY,
			token_id    TEXT NOT NULL,
			scope_type  TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy')),
			scope_value TEXT NOT NULL,
			UNIQUE(token_id, scope_type, scope_value)
		)`,
		// rbac_role sur les tokens : 'admin' par défaut (comportement actuel inchangé)
		`ALTER TABLE tokens ADD COLUMN rbac_role TEXT NOT NULL DEFAULT 'admin'`,
		// PEM des certificats — stockés pour re-push après redémarrage Core
		`ALTER TABLE certs ADD COLUMN cert_pem TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE certs ADD COLUMN key_pem TEXT NOT NULL DEFAULT ''`,
	} {
		db.Exec(s) //nolint:errcheck
	}

	// Équipes et RBAC (idempotent).
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS teams (
			id         TEXT PRIMARY KEY,
			name       TEXT UNIQUE NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS team_members (
			team_id    TEXT NOT NULL,
			user_id    TEXT NOT NULL,
			PRIMARY KEY (team_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS team_scopes (
			id          TEXT PRIMARY KEY,
			team_id     TEXT NOT NULL,
			scope_type  TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy')),
			scope_value TEXT NOT NULL,
			access_mode TEXT NOT NULL DEFAULT 'read' CHECK(access_mode IN ('read','write')),
			UNIQUE(team_id, scope_type, scope_value)
		)`,
		// Mise à jour du CHECK sur users.role pour inclure 'operator'
		// SQLite ne supporte pas ALTER TABLE … MODIFY, on l'ignore si déjà présent.
	} {
		db.Exec(s) //nolint:errcheck
	}

	// Colonnes étendues pour logs et tables existantes (idempotent).
	for _, s := range []string{
		`ALTER TABLE logs ADD COLUMN referrer TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE logs ADD COLUMN node_name TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_logs_node_name ON logs (node_name)`,
		`CREATE TABLE IF NOT EXISTS fail2ban_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '{}')`,
		`CREATE TABLE IF NOT EXISTS vulnscan_state (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS crowdsec_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '{}')`,
		`ALTER TABLE nodes ADD COLUMN container_runtimes TEXT NOT NULL DEFAULT ''`,
		// Identité mutable et métadonnées nœud
		`ALTER TABLE nodes ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN region      TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN environment TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN tags        TEXT NOT NULL DEFAULT '[]'`,
		// Prism : indexes d'accès HTTP (bases déjà migrées avant l'ajout dans stmts).
		`CREATE INDEX IF NOT EXISTS idx_logs_access_ts ON logs (ts) WHERE status > 0`,
		`CREATE INDEX IF NOT EXISTS idx_logs_access_domain_ts ON logs (domain, ts) WHERE status > 0`,
	} {
		db.Exec(s) //nolint:errcheck
	}

	// Colonnes étendues pour audit_log (ajout idempotent — erreurs ignorées si déjà présentes).
	auditAlters := []string{
		`ALTER TABLE audit_log ADD COLUMN component     TEXT NOT NULL DEFAULT 'admin'`,
		`ALTER TABLE audit_log ADD COLUMN user_id       TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_log ADD COLUMN ip            TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_log ADD COLUMN severity      TEXT NOT NULL DEFAULT 'info'`,
		`ALTER TABLE audit_log ADD COLUMN resource_type TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_log ADD COLUMN resource_id   TEXT NOT NULL DEFAULT ''`,
		// raft_endpoint pour la topologie cluster poussée depuis Admin
		`ALTER TABLE tokens ADD COLUMN raft_endpoint TEXT`,
	}
	for _, s := range auditAlters {
		db.Exec(s) //nolint:errcheck — duplicate column errors are expected and safe to ignore
	}

	// Nœuds déclarés via l'assistant Infrastructure (non encore connectés).
	db.Exec(`CREATE TABLE IF NOT EXISTS declared_nodes (
		id         TEXT PRIMARY KEY,
		role       TEXT NOT NULL CHECK(role IN ('core','agent')),
		name       TEXT NOT NULL,
		region     TEXT NOT NULL DEFAULT '',
		environment TEXT NOT NULL DEFAULT '',
		config     TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck

	// Nœuds en attente d'acceptation (pairing_secret validé, admin pas encore accepté).
	db.Exec(`CREATE TABLE IF NOT EXISTS pending_nodes (
		id          TEXT PRIMARY KEY,
		node_name   TEXT NOT NULL,
		role        TEXT NOT NULL,
		version     TEXT NOT NULL DEFAULT '',
		remote_addr TEXT NOT NULL DEFAULT '',
		status      TEXT NOT NULL DEFAULT 'pending',
		token       TEXT NOT NULL DEFAULT '',
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck
	// Index pour dépiler rapidement les PENDING
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_nodes_name_role ON pending_nodes (node_name, role)`) //nolint:errcheck

	// Domaines gérés (certificats, fournisseur DNS, délégation inter-Core).
	db.Exec(`CREATE TABLE IF NOT EXISTS domains (
		id                    TEXT PRIMARY KEY,
		domain                TEXT UNIQUE NOT NULL,
		core_id               TEXT NOT NULL DEFAULT '',
		dns_provider          TEXT NOT NULL DEFAULT 'none',
		dns_credentials       TEXT NOT NULL DEFAULT '{}',
		cert_method           TEXT NOT NULL DEFAULT 'http',
		delegated_to_core_id  TEXT NOT NULL DEFAULT '',
		delegated_endpoint    TEXT NOT NULL DEFAULT '',
		delegation_mode       TEXT NOT NULL DEFAULT 'passthrough',
		cert_expires_at       DATETIME,
		created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck
	// Migration : ajout delegation_mode pour les installations existantes
	db.Exec(`ALTER TABLE domains ADD COLUMN delegation_mode TEXT NOT NULL DEFAULT 'passthrough'`) //nolint:errcheck

	// Migration : ajout du scope_type 'core' dans team_scopes et token_scopes.
	// SQLite ne supporte pas ALTER COLUMN, on recrée chaque table.
	// Les 5 étapes sont idempotentes : erreurs silencieuses sur les runs suivants.
	for _, s := range []string{
		// team_scopes
		`CREATE TABLE IF NOT EXISTS team_scopes_v2 (
			id          TEXT PRIMARY KEY,
			team_id     TEXT NOT NULL,
			scope_type  TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','core')),
			scope_value TEXT NOT NULL,
			access_mode TEXT NOT NULL DEFAULT 'read' CHECK(access_mode IN ('read','write')),
			UNIQUE(team_id, scope_type, scope_value)
		)`,
		// Préférer la copie avec access_mode (si la colonne existe)
		`INSERT OR IGNORE INTO team_scopes_v2 (id, team_id, scope_type, scope_value, access_mode)
		 SELECT id, team_id, scope_type, scope_value, access_mode FROM team_scopes`,
		// Fallback anciennes tables sans access_mode
		`INSERT OR IGNORE INTO team_scopes_v2 (id, team_id, scope_type, scope_value, access_mode)
		 SELECT id, team_id, scope_type, scope_value, 'read' FROM team_scopes`,
		`ALTER TABLE team_scopes RENAME TO team_scopes_old`,
		`ALTER TABLE team_scopes_v2 RENAME TO team_scopes`,
		`DROP TABLE IF EXISTS team_scopes_old`,
		// token_scopes
		`CREATE TABLE IF NOT EXISTS token_scopes_v2 (
			id          TEXT PRIMARY KEY,
			token_id    TEXT NOT NULL,
			scope_type  TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','core')),
			scope_value TEXT NOT NULL,
			UNIQUE(token_id, scope_type, scope_value)
		)`,
		`INSERT OR IGNORE INTO token_scopes_v2 SELECT * FROM token_scopes`,
		`ALTER TABLE token_scopes RENAME TO token_scopes_old`,
		`ALTER TABLE token_scopes_v2 RENAME TO token_scopes`,
		`DROP TABLE IF EXISTS token_scopes_old`,
	} {
		db.Exec(s) //nolint:errcheck
	}

	// Migration : promouvoir le premier admin créé en superadmin (rôle protégé).
	db.Exec(`
		UPDATE users SET role='superadmin'
		WHERE role='admin'
		  AND created_at = (SELECT MIN(created_at) FROM users WHERE role='admin')
		  AND (SELECT COUNT(*) FROM users WHERE role='superadmin') = 0
	`) //nolint:errcheck

	// Tokens API utilisateur (PAT) — distincts des tokens d'appairage Core/Agent.
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS user_api_tokens (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			label        TEXT NOT NULL DEFAULT '',
			token_hash   TEXT NOT NULL UNIQUE,
			token_prefix TEXT NOT NULL DEFAULT '',
			expires_at   DATETIME,
			revoked      INTEGER NOT NULL DEFAULT 0,
			last_used_at DATETIME,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_api_token_scopes (
			token_id TEXT NOT NULL,
			scope    TEXT NOT NULL,
			PRIMARY KEY (token_id, scope)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_api_tokens_user ON user_api_tokens (user_id)`,
	} {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration user_api_tokens : %w", err)
		}
	}

	if err := migrateRBACGrants(db); err != nil {
		return fmt.Errorf("migration rbac grants : %w", err)
	}

	// Lien snapshot → planification (rétention indépendante par planning).
	db.Exec(`ALTER TABLE backup_snapshots ADD COLUMN schedule_id TEXT NOT NULL DEFAULT ''`)                                //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_backup_snapshots_schedule ON backup_snapshots (schedule_id, created_at DESC)`) //nolint:errcheck

	// H12 : hash des tokens nœuds (lookup) — chiffrement appliqué au démarrage Admin si clé dispo.
	db.Exec(`ALTER TABLE tokens ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens (token_hash)`) //nolint:errcheck
	if err := migrateNodeTokenHashes(db); err != nil {
		return fmt.Errorf("migration token_hash : %w", err)
	}

	// Bibliothèque de pages d'erreur (templates HTML + assets) — scope Admin V1.
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS error_page_templates (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			body        TEXT NOT NULL,
			scope_type  TEXT NOT NULL DEFAULT 'admin',
			scope_id    TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS error_page_assets (
			id           TEXT PRIMARY KEY,
			template_id  TEXT NOT NULL,
			filename     TEXT NOT NULL,
			content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
			content      BLOB NOT NULL,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(template_id, filename)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_error_page_assets_tpl ON error_page_assets (template_id)`,
	} {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration error_page_templates : %w", err)
		}
	}

	// Destinations catalogue portail Access (par Core).
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS portal_destinations (
			id          TEXT PRIMARY KEY,
			core_name   TEXT NOT NULL,
			kind        TEXT NOT NULL,
			name        TEXT NOT NULL,
			host        TEXT NOT NULL DEFAULT '',
			port        INTEGER NOT NULL DEFAULT 0,
			agent_name  TEXT NOT NULL DEFAULT '',
			container   TEXT NOT NULL DEFAULT '',
			tags_json   TEXT NOT NULL DEFAULT '[]',
			enabled     INTEGER NOT NULL DEFAULT 1,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_destinations_core ON portal_destinations (core_name)`,
		`CREATE TABLE IF NOT EXISTS portal_users (
			id               TEXT PRIMARY KEY,
			email            TEXT NOT NULL UNIQUE,
			status           TEXT NOT NULL DEFAULT 'invited',
			tags_json        TEXT NOT NULL DEFAULT '[]',
			invite_token_hash TEXT NOT NULL DEFAULT '',
			invite_expires   TEXT NOT NULL DEFAULT '',
			home_core        TEXT NOT NULL,
			created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_users_core ON portal_users (home_core)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_users_invite ON portal_users (invite_token_hash)`,
		`CREATE TABLE IF NOT EXISTS portal_audit (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			core_name  TEXT NOT NULL DEFAULT '',
			ts         TEXT NOT NULL,
			actor      TEXT NOT NULL DEFAULT '',
			target_id  TEXT NOT NULL DEFAULT '',
			facade     TEXT NOT NULL DEFAULT '',
			success    INTEGER NOT NULL DEFAULT 0,
			detail     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_audit_core ON portal_audit (core_name, id DESC)`,
		`CREATE TABLE IF NOT EXISTS portal_page_templates (
			page_key   TEXT PRIMARY KEY,
			name       TEXT NOT NULL DEFAULT '',
			body       TEXT NOT NULL DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	} {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration portal_destinations/users : %w", err)
		}
	}

	return nil
}

// GetSetting lit un paramètre, retourne defVal si absent.
func GetSetting(db *sql.DB, key, defVal string) string {
	var v string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return defVal
	}
	return v
}

// migrateNodeTokenHashes remplit token_hash (et chiffre si clé configurée) pour les lignes legacy.
func migrateNodeTokenHashes(db *sql.DB) error {
	rows, err := db.Query(`SELECT id, token, COALESCE(token_hash,'') FROM tokens`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct{ id, tok, hash string }
	var list []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.tok, &r.hash) != nil {
			continue
		}
		list = append(list, r)
	}
	for _, r := range list {
		plain := r.tok
		if strings.HasPrefix(r.tok, "gpxnt1:") {
			if p, err := auth.OpenNodeToken(r.tok); err == nil {
				plain = p
			} else {
				continue
			}
		}
		if plain == "" {
			continue
		}
		hash := auth.HashNodeToken(plain)
		stored := auth.SealNodeToken(plain)
		if r.hash == hash && r.tok == stored {
			continue
		}
		if _, err := db.Exec(`UPDATE tokens SET token=?, token_hash=? WHERE id=?`, stored, hash, r.id); err != nil {
			return err
		}
	}
	return nil
}

// SetSetting persiste un paramètre.
func SetSetting(db *sql.DB, key, value string) error {
	_, err := db.Exec(
		`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
		key, value)
	return err
}

// WriteAudit insère une entrée dans le journal d'audit (compat ascendante).
func WriteAudit(db *sql.DB, actor, action, resource, detail string) error {
	_, err := db.Exec(
		`INSERT INTO audit_log (actor, action, resource, detail) VALUES (?, ?, ?, ?)`,
		actor, action, resource, detail,
	)
	return err
}
