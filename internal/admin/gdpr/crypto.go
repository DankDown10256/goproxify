// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package gdpr garde la clé de pseudonymisation RGPD de l'Admin et la file des effacements à rejouer aux
// passerelles. Les primitives de chiffrement sont dans internal/ipcrypt.
package gdpr

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

const keyRow = "ip_pseudonymize_key"

// EnsureKey génère (ou charge) la clé AES-GCM 256 bits stockée dans la table gdpr_keys.
// Retourne la clé brute de 32 octets.
func EnsureKey(db *sql.DB) ([]byte, error) {
	var encoded string
	err := db.QueryRow(`SELECT value FROM gdpr_keys WHERE key = ?`, keyRow).Scan(&encoded)
	if err == nil && encoded != "" {
		raw, err2 := base64.StdEncoding.DecodeString(encoded)
		if err2 != nil {
			return nil, fmt.Errorf("gdpr: décodage clé : %w", err2)
		}
		return raw, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("gdpr: lecture clé : %w", err)
	}

	key, err := ipcrypt.NewKey()
	if err != nil {
		return nil, err
	}
	encoded = base64.StdEncoding.EncodeToString(key)
	_, err = db.Exec(`INSERT OR REPLACE INTO gdpr_keys (key, value) VALUES (?, ?)`, keyRow, encoded)
	if err != nil {
		return nil, fmt.Errorf("gdpr: persistance clé : %w", err)
	}
	return key, nil
}

// LoadKey lit la clé de pseudonymisation sans la créer : une commande locale qui relit des logs ne doit jamais en fabriquer
// une neuve, qui rendrait silencieusement les IP pseudonymisées illisibles. Absente : (nil, nil).
func LoadKey(db *sql.DB) ([]byte, error) {
	var encoded string
	err := db.QueryRow(`SELECT value FROM gdpr_keys WHERE key = ?`, keyRow).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && encoded == "") {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gdpr: lecture clé : %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("gdpr: décodage clé : %w", err)
	}
	return raw, nil
}
