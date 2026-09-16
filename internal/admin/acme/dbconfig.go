// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"database/sql"
)

const (
	settingEnabled      = "acme.enabled"
	settingEmail        = "acme.email"
	settingDirectoryURL = "acme.directory_url"
	settingDNSType      = "acme.dns_type"
)

// DBConfig contient la config ACME persistée en base.
type DBConfig struct {
	Enabled      bool
	Email        string
	DirectoryURL string
	DNSType      string
}

// LoadConfig lit la config ACME depuis la table settings.
func LoadConfig(db *sql.DB) DBConfig {
	var cfg DBConfig
	rows, err := db.Query(
		`SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?)`,
		settingEnabled, settingEmail, settingDirectoryURL, settingDNSType,
	)
	if err != nil {
		return cfg
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		switch k {
		case settingEnabled:
			cfg.Enabled = v == "true"
		case settingEmail:
			cfg.Email = v
		case settingDirectoryURL:
			cfg.DirectoryURL = v
		case settingDNSType:
			cfg.DNSType = v
		}
	}
	return cfg
}

// SaveConfig persiste la config ACME dans la table settings.
func SaveConfig(db *sql.DB, cfg DBConfig) error {
	enabled := "false"
	if cfg.Enabled {
		enabled = "true"
	}
	entries := [][2]string{
		{settingEnabled, enabled},
		{settingEmail, cfg.Email},
		{settingDirectoryURL, cfg.DirectoryURL},
		{settingDNSType, cfg.DNSType},
	}
	for _, e := range entries {
		_, err := db.Exec(
			`INSERT INTO settings (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`,
			e[0], e[1],
		)
		if err != nil {
			return err
		}
	}
	return nil
}
