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
	"github.com/vincamok/goproxify/internal/sqltime"
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
	// auto_vacuum(INCREMENTAL) ne s'applique qu'à une base créée avec (ou après un VACUUM) : il permet à
	// la purge des logs de rendre l'espace au disque. journal_size_limit tronque le WAL à 256 Mo après
	// un point de contrôle complet au lieu de le laisser à sa taille maximale.
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)" +
		"&_pragma=auto_vacuum(2)&_pragma=journal_size_limit(268435456)"
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
		// Nœuds enregistrés (Passerelles + Agents) avec leur dernier heartbeat
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
		`CREATE INDEX IF NOT EXISTS idx_logs_ip_ts     ON logs (ip, ts)`,
		// Cumuls d'accès par minute, calculés par les passerelles et envoyés à l'Admin (ADR 0012) : les tableaux de bord
		// les lisent, l'Admin ne reçoit plus les accès ordinaires. Aucune IP, aucun identifiant : données non
		// personnelles, conservées 400 jours. minute = AAAA-MM-JJTHH:MM en UTC.
		`CREATE TABLE IF NOT EXISTS logs_minute (
			minute         TEXT    NOT NULL,
			node_name      TEXT    NOT NULL DEFAULT '',
			domain         TEXT    NOT NULL DEFAULT '',
			status         INTEGER NOT NULL,
			requests       INTEGER NOT NULL,
			bytes          INTEGER NOT NULL DEFAULT 0,
			latency_ms_sum INTEGER NOT NULL DEFAULT 0,
			bots           INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (minute, node_name, domain, status)
		) WITHOUT ROWID`,
		// Erreurs client (4xx hors 404) par IP et par minute, envoyées par les passerelles pour le Fail2Ban global
		// (ADR 0012) : une IP en clair, donc gardées 24 h seulement et effacées avec l'IP.
		`CREATE TABLE IF NOT EXISTS edge_ip_errors (
			node_id TEXT    NOT NULL,
			minute  TEXT    NOT NULL,
			ip      TEXT    NOT NULL,
			errors  INTEGER NOT NULL,
			PRIMARY KEY (node_id, minute, ip)
		) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS idx_edge_ip_errors_minute ON edge_ip_errors (minute)`,
		// Dernière position reçue de chaque passerelle, par flux de logs (ADR 0012) : écrite dans la même transaction
		// que les lignes, elle dit à la passerelle d'où reprendre après une coupure.
		`CREATE TABLE IF NOT EXISTS edge_log_cursors (
			node_id    TEXT NOT NULL,
			stream     TEXT NOT NULL,
			last_seq   INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (node_id, stream)
		) WITHOUT ROWID`,
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
		// Historique des bans IP (créés et supprimés)
		`CREATE TABLE IF NOT EXISTS security_ban_history (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ip         TEXT NOT NULL,
			domain     TEXT NOT NULL DEFAULT '',
			action     TEXT NOT NULL DEFAULT 'banned',
			reason     TEXT NOT NULL DEFAULT '',
			source     TEXT NOT NULL DEFAULT 'native',
			ban_id     TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ban_history_ip ON security_ban_history (ip)`,
		// Décisions CrowdSec
		`CREATE TABLE IF NOT EXISTS security_threats (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			ip           TEXT NOT NULL,
			scenario     TEXT NOT NULL DEFAULT '',
			origin       TEXT NOT NULL DEFAULT '',
			type         TEXT NOT NULL DEFAULT 'ban',
			duration     TEXT NOT NULL DEFAULT '',
			edge_name    TEXT NOT NULL DEFAULT '',
			occurrences  INTEGER NOT NULL DEFAULT 1,
			last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
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
			edge_name   TEXT NOT NULL DEFAULT '',
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
		// Clés ECH (Encrypted Client Hello) : la clé retirée (retired=1) n'est plus publiée dans le DNS mais déchiffre encore
		`CREATE TABLE IF NOT EXISTS ech_keys (
			id              TEXT PRIMARY KEY,
			config_id       INTEGER NOT NULL,
			config_b64      TEXT NOT NULL,
			private_key_b64 TEXT NOT NULL,
			public_name     TEXT NOT NULL,
			retired         INTEGER NOT NULL DEFAULT 0,
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
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
		// Fournisseurs SSO/Auth partagés (poussés vers les passerelles)
		`CREATE TABLE IF NOT EXISTS auth_providers (
			id         TEXT PRIMARY KEY,
			name       TEXT UNIQUE NOT NULL,
			provider   TEXT NOT NULL,
			config     TEXT NOT NULL DEFAULT '{}',
			enabled    INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Plugins WebAssembly installés (poussés vers les passerelles, ADR 0008)
		`CREATE TABLE IF NOT EXISTS plugins (
			name       TEXT PRIMARY KEY,
			manifest   TEXT NOT NULL,
			sha256     TEXT NOT NULL,
			wasm       BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Clés publiques de confiance pour la signature des plugins
		`CREATE TABLE IF NOT EXISTS plugin_trusted_keys (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			public_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Dépôts de plugins (index JSON d'un serveur HTTPS)
		`CREATE TABLE IF NOT EXISTS plugin_repos (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL,
			url           TEXT NOT NULL UNIQUE,
			allow_private INTEGER NOT NULL DEFAULT 0,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
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
		`CREATE TABLE IF NOT EXISTS node_tunnel_configs (
			node_id    TEXT PRIMARY KEY,
			config     TEXT NOT NULL DEFAULT '{}',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration : %w", err)
		}
	}

	// Scopes par token (RBAC côté passerelle — idempotent).
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
		// PEM des certificats — stockés pour re-push après redémarrage passerelle
		`ALTER TABLE certs ADD COLUMN cert_pem TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE certs ADD COLUMN key_pem TEXT NOT NULL DEFAULT ''`,
		// Fournisseur DNS nommé (acme-providers.yaml) qui a émis le certificat, rejoué au renouvellement
		`ALTER TABLE certs ADD COLUMN acme_provider_id TEXT NOT NULL DEFAULT ''`,
		// Validateurs HTTP (ETag / Last-Modified) des feeds des profils IP
		`ALTER TABLE ip_profiles ADD COLUMN feed_cache TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE ip_profiles ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ip_profiles ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ip_profiles ADD COLUMN next_attempt_at DATETIME`,
		// Passerelle d'origine d'un ban ('' = ban global : admin, CrowdSec/Fail2Ban centraux)
		`ALTER TABLE security_bans ADD COLUMN edge_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE security_ban_history ADD COLUMN edge_name TEXT NOT NULL DEFAULT ''`,
		// Portée d'un ban : '' = toutes les passerelles, sinon nom d'une passerelle ou "group:<nom>"
		`ALTER TABLE security_bans ADD COLUMN target_scope TEXT NOT NULL DEFAULT ''`,
		// ASN dont ce ban est l'une des plages (0 = ban sans rapport avec un ASN)
		`ALTER TABLE security_bans ADD COLUMN asn INTEGER NOT NULL DEFAULT 0`,
		// Signaux (JSON) qui expliquent un ban automatique d'Ephor ou du WAF : nom, points, valeur observée
		`ALTER TABLE security_bans ADD COLUMN signals TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE security_ban_history ADD COLUMN signals TEXT NOT NULL DEFAULT ''`,
		// Dernier User-Agent vu pour l'IP quand une passerelle l'a bannie : dit quel client a provoqué le ban
		`ALTER TABLE security_bans ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE security_ban_history ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`,
		// Carte Prism : position approximative (ville) des IPs, renseignée par GeoResolver.
		`ALTER TABLE snippets ADD COLUMN description TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE geoip_cache ADD COLUMN lat REAL`,
		`ALTER TABLE geoip_cache ADD COLUMN lon REAL`,
		`ALTER TABLE geoip_cache ADD COLUMN city TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE geoip_cache ADD COLUMN region TEXT NOT NULL DEFAULT ''`,
		// Les sessions (JWT) émises avant cette date (secondes Unix) sont refusées : changement de mot de passe
		`ALTER TABLE users ADD COLUMN tokens_valid_after INTEGER NOT NULL DEFAULT 0`,
		// Clé de confiance qui a signé le plugin ('' = non signé)
		`ALTER TABLE plugins ADD COLUMN signed_by TEXT NOT NULL DEFAULT ''`,
		// Signature Ed25519 vérifiée à l'installation, poussée avec le paquet : une passerelle qui épingle des clés la revérifie
		`ALTER TABLE plugins ADD COLUMN signature TEXT NOT NULL DEFAULT ''`,
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
		// Permissions de capacité (ex. gdpr:reveal) accordées par le superadmin, en propre ou via une équipe.
		`CREATE TABLE IF NOT EXISTS user_permissions (
			user_id    TEXT NOT NULL,
			permission TEXT NOT NULL,
			PRIMARY KEY (user_id, permission)
		)`,
		`CREATE TABLE IF NOT EXISTS team_permissions (
			team_id    TEXT NOT NULL,
			permission TEXT NOT NULL,
			PRIMARY KEY (team_id, permission)
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
		`ALTER TABLE logs ADD COLUMN request_id TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_logs_request_id ON logs (request_id) WHERE request_id != ''`,
		`CREATE TABLE IF NOT EXISTS fail2ban_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '{}')`,
		`CREATE TABLE IF NOT EXISTS vulnscan_state (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS crowdsec_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '{}')`,
		`ALTER TABLE nodes ADD COLUMN container_runtimes TEXT NOT NULL DEFAULT ''`,
		// Identité mutable et métadonnées nœud
		`ALTER TABLE nodes ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN region      TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN environment TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN tags        TEXT NOT NULL DEFAULT '[]'`,
		// Les accès ordinaires ne sont plus dans cette table (ADR 0012) : les index qui servaient Prism disparaissent.
		`DROP INDEX IF EXISTS idx_logs_access_ts`,
		`DROP INDEX IF EXISTS idx_logs_access_ts_status`,
		`DROP INDEX IF EXISTS idx_logs_access_domain_ts`,
		`DROP INDEX IF EXISTS idx_logs_analytics_node`,
		// RGPD pseudonymisation : IP chiffrée (AES-GCM) — vide si mode anonymisation classique.
		`ALTER TABLE logs ADD COLUMN ip_enc TEXT NOT NULL DEFAULT ''`,
		// Empreinte HMAC de l'IP pseudonymisée : effacement Art. 17 par IP sans tout déchiffrer.
		`ALTER TABLE logs ADD COLUMN ip_hmac TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_logs_ip_hmac ON logs (ip_hmac) WHERE ip_hmac != ''`,
		// Clé de chiffrement RGPD (32 bytes random base64) — générée au premier démarrage.
		`CREATE TABLE IF NOT EXISTS gdpr_keys (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')`,
		// Effacements d'IP à rejouer aux passerelles à leur connexion (IP chiffrée par la clé RGPD, purgée avec la rétention des logs).
		`CREATE TABLE IF NOT EXISTS edge_erasure_queue (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_enc     TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// node_id : identifiant stable du nœud (edgeID/token), insensible à un
		// renommage de node_name — évite qu'un re-pairing (nouveau token_id
		// après régénération de edge.json) ne rende l'historique des logs
		// d'un nœud introuvable sous son ancien nom.
		`ALTER TABLE logs ADD COLUMN node_id TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_logs_node_id ON logs (node_id)`,
		// IP tronquée par la passerelle (anonymisation/pseudonymisation) : écartée par Fail2Ban.
		`ALTER TABLE logs ADD COLUMN ip_truncated INTEGER NOT NULL DEFAULT 0`,
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
	}
	for _, s := range auditAlters {
		db.Exec(s) //nolint:errcheck — duplicate column errors are expected and safe to ignore
	}

	// Nœuds déclarés via l'assistant Infrastructure (non encore connectés).
	db.Exec(`CREATE TABLE IF NOT EXISTS declared_nodes (
		id         TEXT PRIMARY KEY,
		role       TEXT NOT NULL CHECK(role IN ('edge','agent')),
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

	// Domaines gérés (certificats, fournisseur DNS, délégation inter-passerelle).
	db.Exec(`CREATE TABLE IF NOT EXISTS domains (
		id                    TEXT PRIMARY KEY,
		domain                TEXT UNIQUE NOT NULL,
		edge_id               TEXT NOT NULL DEFAULT '',
		dns_provider          TEXT NOT NULL DEFAULT 'none',
		dns_credentials       TEXT NOT NULL DEFAULT '{}',
		cert_method           TEXT NOT NULL DEFAULT 'http',
		delegated_to_edge_id  TEXT NOT NULL DEFAULT '',
		delegated_endpoint    TEXT NOT NULL DEFAULT '',
		delegation_mode       TEXT NOT NULL DEFAULT 'passthrough',
		cert_expires_at       DATETIME,
		created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck
	// Migration : ajout delegation_mode pour les installations existantes
	db.Exec(`ALTER TABLE domains ADD COLUMN delegation_mode TEXT NOT NULL DEFAULT 'passthrough'`) //nolint:errcheck

	// Migration : ajout du scope_type 'edge' dans team_scopes et token_scopes.
	// SQLite ne supporte pas ALTER COLUMN, on recrée chaque table.
	// Les 5 étapes sont idempotentes : erreurs silencieuses sur les runs suivants.
	for _, s := range []string{
		// team_scopes
		`CREATE TABLE IF NOT EXISTS team_scopes_v2 (
			id          TEXT PRIMARY KEY,
			team_id     TEXT NOT NULL,
			scope_type  TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','edge')),
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
			scope_type  TEXT NOT NULL CHECK(scope_type IN ('domain','server','proxy','edge')),
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

	// Tokens API utilisateur (PAT) — distincts des tokens d'appairage passerelle/Agent.
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

	// Fiabilité des sauvegardes : somme de contrôle, vérification, destinations externes et envois.
	db.Exec(`ALTER TABLE backup_snapshots ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''`)      //nolint:errcheck
	db.Exec(`ALTER TABLE backup_snapshots ADD COLUMN verified_at DATETIME`)                 //nolint:errcheck
	db.Exec(`CREATE TABLE IF NOT EXISTS backup_destinations (
		id         TEXT PRIMARY KEY,
		name       TEXT UNIQUE NOT NULL,
		type       TEXT NOT NULL,
		enabled    INTEGER NOT NULL DEFAULT 1,
		config     TEXT NOT NULL DEFAULT '{}',
		retention  INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck
	db.Exec(`CREATE TABLE IF NOT EXISTS backup_deliveries (
		snapshot_id    TEXT NOT NULL,
		destination_id TEXT NOT NULL,
		object_name    TEXT NOT NULL DEFAULT '',
		ok             INTEGER NOT NULL DEFAULT 0,
		error          TEXT NOT NULL DEFAULT '',
		size           INTEGER NOT NULL DEFAULT 0,
		sha256         TEXT NOT NULL DEFAULT '',
		at             DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (snapshot_id, destination_id)
	)`) //nolint:errcheck

	// H12 : hash des tokens nœuds (lookup) — chiffrement appliqué au démarrage Admin si clé dispo.
	db.Exec(`ALTER TABLE tokens ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens (token_hash)`) //nolint:errcheck
	if err := migrateNodeTokenHashes(db); err != nil {
		return fmt.Errorf("migration token_hash : %w", err)
	}

	// CA interne — autorité racine et certificats émis (clés PEM persistées sur disque, cf certs/internal-ca/).
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS internal_ca (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL UNIQUE,
			subject     TEXT NOT NULL,
			cert_pem    TEXT NOT NULL,
			not_after   DATETIME NOT NULL,
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS internal_ca_certs (
			id          TEXT PRIMARY KEY,
			ca_id       TEXT NOT NULL REFERENCES internal_ca(id) ON DELETE CASCADE,
			common_name TEXT NOT NULL,
			usage       TEXT NOT NULL CHECK(usage IN ('server','client')),
			sans_json   TEXT NOT NULL DEFAULT '[]',
			serial      TEXT NOT NULL,
			cert_pem    TEXT NOT NULL,
			not_after   DATETIME NOT NULL,
			revoked     INTEGER NOT NULL DEFAULT 0,
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_internal_ca_certs_ca ON internal_ca_certs (ca_id)`,
	} {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration internal_ca : %w", err)
		}
	}

	// Vulnérabilités (CVE) — passerelle d'origine, pour affichage côté Admin (vue agrégée multi-passerelle).
	db.Exec(`ALTER TABLE security_cves ADD COLUMN edge_name TEXT NOT NULL DEFAULT ''`) //nolint:errcheck

	// Vulnérabilités (CVE) — le proxy, le produit et la version sur lesquels la CVE a été trouvée, et d'où ils viennent
	// (« image » : inventaire des conteneurs de la passerelle ; « headers » : en-têtes du backend). ADR 0017.
	db.Exec(`ALTER TABLE security_cves ADD COLUMN host TEXT NOT NULL DEFAULT ''`)    //nolint:errcheck
	db.Exec(`ALTER TABLE security_cves ADD COLUMN product TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`ALTER TABLE security_cves ADD COLUMN version TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`ALTER TABLE security_cves ADD COLUMN source TEXT NOT NULL DEFAULT ''`)  //nolint:errcheck

	// Vulnérabilités (CVE) — exploitation active (catalogue CISA KEV) et probabilité d'exploitation
	// (score EPSS, FIRST.org), rafraîchis en fin de scan (internal/admin/vulnscan). Le SLA de correction
	// (délai attendu selon la gravité) n'est pas stocké : il est recalculé à la lecture depuis le réglage
	// `cve_sla_config` (table settings), pour refléter tout de suite un changement de seuils.
	db.Exec(`ALTER TABLE security_cves ADD COLUMN kev INTEGER NOT NULL DEFAULT 0`)     //nolint:errcheck
	db.Exec(`ALTER TABLE security_cves ADD COLUMN epss_score REAL NOT NULL DEFAULT 0`) //nolint:errcheck
	db.Exec(`ALTER TABLE security_cves ADD COLUMN epss_updated_at DATETIME`)           //nolint:errcheck

	// Menaces CrowdSec — passerelle d'origine + dernière observation (une même menace ip+scenario
	// était ré-émise régulièrement mais ignorée par l'unicité (ip, scenario), sans jamais
	// rafraîchir la date affichée côté Admin/Passerelle).
	db.Exec(`ALTER TABLE security_threats ADD COLUMN edge_name    TEXT NOT NULL DEFAULT ''`)           //nolint:errcheck
	db.Exec(`ALTER TABLE security_threats ADD COLUMN occurrences  INTEGER NOT NULL DEFAULT 1`)         //nolint:errcheck
	db.Exec(`ALTER TABLE security_threats ADD COLUMN last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP`) //nolint:errcheck
	db.Exec(`UPDATE security_threats SET last_seen_at = created_at WHERE last_seen_at IS NULL`)        //nolint:errcheck

	// RGPD : rétention individuelle par ligne + effacement par IP ou utilisateur.
	db.Exec(`ALTER TABLE logs ADD COLUMN user_id       TEXT NOT NULL DEFAULT ''`)    //nolint:errcheck
	db.Exec(`ALTER TABLE logs ADD COLUMN retained_until DATETIME`)                   //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_retained ON logs (retained_until)`) //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ip       ON logs (ip)`)             //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_user_id  ON logs (user_id)`)        //nolint:errcheck
	// Keyset pagination : index partiels sur id DESC par kind (access vs system).
	// Accélère WHERE id < ? AND status > 0 ORDER BY id DESC LIMIT n sans OFFSET.
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_access_id ON logs (id DESC) WHERE status > 0`) //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_system_id ON logs (id DESC) WHERE status = 0`) //nolint:errcheck

	// Contexte de sécurité de la requête d'origine (catégories WAF déclenchées, signal
	// Ephor) : la passerelle le calculait déjà et l'envoyait (ShipEntry), mais rien ne
	// le recevait ni ne le stockait — jeté silencieusement à l'ingestion. waf_matches est
	// un tableau JSON (ex. `["942100"]`), vide pour l'immense majorité des lignes propres.
	db.Exec(`ALTER TABLE logs ADD COLUMN waf_matches   TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`ALTER TABLE logs ADD COLUMN threat_signal TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	// Empreintes TLS JA3/JA4 du client (calculées au ClientHello par la passerelle).
	db.Exec(`ALTER TABLE logs ADD COLUMN tls_ja3 TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`ALTER TABLE logs ADD COLUMN tls_ja4 TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_tls_ja4 ON logs (tls_ja4) WHERE tls_ja4 != ''`) //nolint:errcheck
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_tls_ja3 ON logs (tls_ja3) WHERE tls_ja3 != ''`) //nolint:errcheck
	// Requêtes signalées par le WAF (activité affichée dans « Moteurs de sécurité ») : index partiel,
	// quasi vide face aux millions de lignes propres. Toute requête qui l'utilise doit répéter le
	// littéral `waf_matches != ''` pour que SQLite le choisisse.
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_waf_ts ON logs (ts) WHERE waf_matches != ''`) //nolint:errcheck

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

	// Destinations catalogue portail Access (par passerelle).
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS portal_destinations (
			id          TEXT PRIMARY KEY,
			edge_name   TEXT NOT NULL,
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
		`CREATE INDEX IF NOT EXISTS idx_portal_destinations_edge ON portal_destinations (edge_name)`,
		`CREATE TABLE IF NOT EXISTS portal_users (
			id               TEXT PRIMARY KEY,
			email            TEXT NOT NULL UNIQUE,
			status           TEXT NOT NULL DEFAULT 'invited',
			tags_json        TEXT NOT NULL DEFAULT '[]',
			invite_token_hash TEXT NOT NULL DEFAULT '',
			invite_expires   TEXT NOT NULL DEFAULT '',
			home_edge        TEXT NOT NULL,
			created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS portal_groups (
			id           TEXT PRIMARY KEY,
			edge_name    TEXT NOT NULL,
			name         TEXT NOT NULL,
			description  TEXT NOT NULL DEFAULT '',
			members_json TEXT NOT NULL DEFAULT '[]',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_groups_edge ON portal_groups (edge_name)`,
		`CREATE TABLE IF NOT EXISTS portal_dest_groups (
			id           TEXT PRIMARY KEY,
			edge_name    TEXT NOT NULL,
			name         TEXT NOT NULL,
			description  TEXT NOT NULL DEFAULT '',
			targets_json TEXT NOT NULL DEFAULT '[]',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_dest_groups_edge ON portal_dest_groups (edge_name)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_users_edge ON portal_users (home_edge)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_users_invite ON portal_users (invite_token_hash)`,
		`CREATE TABLE IF NOT EXISTS portal_audit (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			edge_name  TEXT NOT NULL DEFAULT '',
			ts         TEXT NOT NULL,
			actor      TEXT NOT NULL DEFAULT '',
			target_id  TEXT NOT NULL DEFAULT '',
			facade     TEXT NOT NULL DEFAULT '',
			success    INTEGER NOT NULL DEFAULT 0,
			detail     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_audit_edge ON portal_audit (edge_name, id DESC)`,
		`CREATE TABLE IF NOT EXISTS portal_access_requests (
			id           TEXT PRIMARY KEY,
			edge_name    TEXT NOT NULL,
			user_id      TEXT NOT NULL,
			username     TEXT NOT NULL DEFAULT '',
			target_id    TEXT NOT NULL,
			target_name  TEXT NOT NULL DEFAULT '',
			reason       TEXT NOT NULL DEFAULT '',
			duration_min INTEGER NOT NULL DEFAULT 0,
			status       TEXT NOT NULL DEFAULT 'pending',
			created_at   TEXT NOT NULL,
			decided_by   TEXT NOT NULL DEFAULT '',
			decided_at   TEXT NOT NULL DEFAULT '',
			expires_at   TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_portal_access_requests_edge ON portal_access_requests (edge_name, status)`,
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

	// Colonnes additives alert_events (ajoutées après la création initiale)
	for _, s := range []string{
		`ALTER TABLE alert_events ADD COLUMN message_title TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE alert_events ADD COLUMN message_body  TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE alert_events ADD COLUMN priority      INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE alert_events ADD COLUMN silenced      INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE alert_events ADD COLUMN acked         INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE alert_events ADD COLUMN acked_at      DATETIME`,
		`ALTER TABLE alert_events ADD COLUMN acked_by      TEXT NOT NULL DEFAULT ''`,
	} {
		_, _ = db.Exec(s) // sqlite ignore si la colonne existe déjà
	}

	// Colonnes additives alert_rules
	for _, s := range []string{
		`ALTER TABLE alert_rules ADD COLUMN group_window_sec INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE alert_rules ADD COLUMN escalation_json   TEXT NOT NULL DEFAULT '[]'`,
	} {
		_, _ = db.Exec(s)
	}

	// Automatisation : flux et mises en sourdine. Les tables des anciens moteurs (règles, planifications,
	// playbooks) sont remplacées par les flux (ADR 0009).
	for _, s := range []string{
		// Flux d'automatisation (internal/admin/automation) : un déclencheur, un
		// garde-fou et des étapes, dans definition_json. trigger_kind est aussi en
		// colonne pour filtrer les onglets Règles / Planifications / Playbooks.
		`CREATE TABLE IF NOT EXISTS flows (
			id              TEXT PRIMARY KEY,
			name            TEXT NOT NULL UNIQUE,
			description     TEXT NOT NULL DEFAULT '',
			enabled         INTEGER NOT NULL DEFAULT 1,
			trigger_kind    TEXT NOT NULL,
			definition_json TEXT NOT NULL,
			origin_json     TEXT NOT NULL DEFAULT '{"kind":"manual"}',
			version         INTEGER NOT NULL DEFAULT 1,
			created_by      TEXT NOT NULL DEFAULT '',
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS flow_state (
			flow_id         TEXT PRIMARY KEY,
			fire_count      INTEGER NOT NULL DEFAULT 0,
			last_fired_at   DATETIME,
			last_run_id     TEXT NOT NULL DEFAULT '',
			last_run_status TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS flow_versions (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			flow_id         TEXT NOT NULL,
			version         INTEGER NOT NULL,
			name            TEXT NOT NULL,
			description     TEXT NOT NULL DEFAULT '',
			enabled         INTEGER NOT NULL DEFAULT 1,
			definition_json TEXT NOT NULL,
			origin_json     TEXT NOT NULL DEFAULT '{}',
			created_by      TEXT NOT NULL DEFAULT '',
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_versions_flow ON flow_versions (flow_id, version DESC)`,
		// Exécutions : definition_json est la copie du flux au lancement (une
		// modification n'affecte pas une exécution en cours) ; cursor est la
		// prochaine étape, resume_at la reprise d'une attente ou l'échéance d'une
		// approbation. Une exécution survit ainsi à un redémarrage de l'Admin.
		`CREATE TABLE IF NOT EXISTS flow_runs (
			id              TEXT PRIMARY KEY,
			flow_id         TEXT NOT NULL,
			flow_name       TEXT NOT NULL,
			flow_version    INTEGER NOT NULL DEFAULT 0,
			definition_json TEXT NOT NULL DEFAULT '{}',
			source          TEXT NOT NULL DEFAULT '',
			trigger_kind    TEXT NOT NULL DEFAULT '',
			status          TEXT NOT NULL,
			cursor          TEXT NOT NULL DEFAULT '',
			context_json    TEXT NOT NULL DEFAULT '{}',
			resume_at       DATETIME,
			parent_run_id   TEXT NOT NULL DEFAULT '',
			parent_step_id  TEXT NOT NULL DEFAULT '',
			depth           INTEGER NOT NULL DEFAULT 0,
			error           TEXT NOT NULL DEFAULT '',
			started_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			finished_at     DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_runs_flow ON flow_runs (flow_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_runs_status ON flow_runs (status, resume_at)`,
		`CREATE TABLE IF NOT EXISTS flow_run_steps (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id      TEXT NOT NULL,
			step_id     TEXT NOT NULL,
			step_type   TEXT NOT NULL,
			status      TEXT NOT NULL,
			detail      TEXT NOT NULL DEFAULT '',
			output_json TEXT NOT NULL DEFAULT '',
			actor       TEXT NOT NULL DEFAULT '',
			flow        TEXT NOT NULL DEFAULT '',
			started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			finished_at DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_run_steps_run ON flow_run_steps (run_id, id)`,
		// Silences : suspendent temporairement les déclenchements des flux et le
		// routage des alertes, sur tout ou sur une liste de flux / règles d'alerte.
		`CREATE TABLE IF NOT EXISTS automation_silences (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			rule_ids   TEXT NOT NULL DEFAULT '[]',
			starts_at  DATETIME NOT NULL,
			ends_at    DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS workspaces (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_by  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS workspace_members (
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			entity_type  TEXT NOT NULL CHECK(entity_type IN ('user','team')),
			entity_id    TEXT NOT NULL,
			PRIMARY KEY (workspace_id, entity_type, entity_id)
		)`,
		`CREATE TABLE IF NOT EXISTS workspace_resources (
			workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			resource_type TEXT NOT NULL CHECK(resource_type IN ('proxy','domain','edge')),
			resource_id   TEXT NOT NULL,
			PRIMARY KEY (workspace_id, resource_type, resource_id)
		)`,
		`CREATE TABLE IF NOT EXISTS cert_deploy_targets (
			id          TEXT PRIMARY KEY,
			cert_id     TEXT NOT NULL,
			name        TEXT NOT NULL,
			type        TEXT NOT NULL CHECK(type IN ('webhook','pull_token','ssh_exec')),
			config      TEXT NOT NULL DEFAULT '{}',
			trigger_on  TEXT NOT NULL DEFAULT 'on_renewal' CHECK(trigger_on IN ('on_renewal','manual')),
			last_deploy DATETIME,
			last_status TEXT NOT NULL DEFAULT 'pending',
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cert_pull_tokens (
			id          TEXT PRIMARY KEY,
			cert_id     TEXT NOT NULL,
			target_id   TEXT,
			name        TEXT NOT NULL,
			token_hash  TEXT NOT NULL UNIQUE,
			format      TEXT NOT NULL DEFAULT 'pem',
			max_uses    INTEGER NOT NULL DEFAULT 1,
			uses        INTEGER NOT NULL DEFAULT 0,
			expires_at  DATETIME,
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS cert_deploy_history (
			id          TEXT PRIMARY KEY,
			target_id   TEXT NOT NULL,
			cert_id     TEXT NOT NULL,
			status      TEXT NOT NULL,
			message     TEXT NOT NULL DEFAULT '',
			deployed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	} {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migration automation: %w", err)
		}
	}

	// Tables des anciens moteurs d'automatisation, remplacées par les flux.
	for _, t := range []string{"rules_engine_rules", "rules_engine_rule_versions", "rules_engine_history",
		"rules_engine_pending_actions", "scheduled_tasks", "scheduled_task_runs", "playbooks", "playbook_runs"} {
		_, _ = db.Exec(`DROP TABLE IF EXISTS ` + t)
	}

	// Dates comparées en SQL à CURRENT_TIMESTAMP / datetime('now', …) mais longtemps écrites en
	// RFC3339 ou via un time.Time lié tel quel (t.String(), heure locale) : ramenées à son format.
	for _, c := range [][2]string{
		{"certs", "expires_at"},
		{"automation_silences", "starts_at"},
		{"automation_silences", "ends_at"},
		{"tokens", "expires_at"},
		{"user_api_tokens", "expires_at"},
		{"user_mfa_challenges", "expires_at"},
		{"user_trusted_devices", "expires_at"},
		{"domains", "updated_at"},
		{"domains", "cert_expires_at"},
		{"domains", "created_at"},
		{"ip_profiles", "next_attempt_at"},
	} {
		if err := sqltime.Normalize(db, c[0], c[1]); err != nil {
			return fmt.Errorf("normalisation %s.%s : %w", c[0], c[1], err)
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

// ListSettingsByPrefix retourne toutes les paires clé/valeur dont la clé commence par prefix.
func ListSettingsByPrefix(db *sql.DB, prefix string) map[string]string {
	rows, err := db.Query(`SELECT key, value FROM settings WHERE key LIKE ?`, prefix+"%")
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			out[k] = v
		}
	}
	return out
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
