// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package gdpr fournit les primitives de chiffrement pour la pseudonymisation RGPD.
package gdpr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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

	// Génération d'une nouvelle clé aléatoire 256 bits.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("gdpr: génération clé : %w", err)
	}
	encoded = base64.StdEncoding.EncodeToString(key)
	_, err = db.Exec(`INSERT OR REPLACE INTO gdpr_keys (key, value) VALUES (?, ?)`, keyRow, encoded)
	if err != nil {
		return nil, fmt.Errorf("gdpr: persistance clé : %w", err)
	}
	return key, nil
}

// Encrypt chiffre plaintext avec AES-GCM et retourne la valeur encodée en base64.
// Format : nonce(12B) || ciphertext.
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt déchiffre une valeur produite par Encrypt.
func Decrypt(key []byte, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("gdpr: décodage base64 : %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", errors.New("gdpr: données chiffrées trop courtes")
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("gdpr: déchiffrement : %w", err)
	}
	return string(plain), nil
}
