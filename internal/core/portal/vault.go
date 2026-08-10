// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

// VaultPayload mappe targetID → creds.
type VaultPayload map[string]TargetCreds

// HashPassword bcrypt pour auth locale.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword vérifie un hash bcrypt.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// DeriveVaultKey dérive une clé AES-256 depuis le mot de passe user + userID.
func DeriveVaultKey(userID, password string) [32]byte {
	r := hkdf.New(sha256.New, []byte(password), []byte("goproxify-portal-vault:"+userID), nil)
	var key [32]byte
	_, _ = io.ReadFull(r, key[:])
	return key
}

// SealVault chiffre le payload avec la clé user.
func SealVault(key [32]byte, payload VaultPayload) ([]byte, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return encryptWithKey(plain, key)
}

// OpenVault déchiffre le payload.
func OpenVault(key [32]byte, blob []byte) (VaultPayload, error) {
	if len(blob) == 0 {
		return VaultPayload{}, nil
	}
	plain, err := decryptWithKey(blob, key)
	if err != nil {
		return nil, fmt.Errorf("vault decrypt: %w", err)
	}
	var payload VaultPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, err
	}
	if payload == nil {
		payload = VaultPayload{}
	}
	return payload, nil
}

// PutTargetCreds met à jour les creds d'une cible dans le vault persisté.
func PutTargetCreds(store *Store, userID string, vaultKey [32]byte, targetID string, creds TargetCreds) error {
	blob := store.VaultBlob(userID)
	payload, err := OpenVault(vaultKey, blob)
	if err != nil {
		return err
	}
	payload[targetID] = creds
	sealed, err := SealVault(vaultKey, payload)
	if err != nil {
		return err
	}
	return store.SetVaultBlob(userID, sealed)
}

// DeleteTargetCreds retire les secrets d'une cible du vault.
func DeleteTargetCreds(store *Store, userID string, vaultKey [32]byte, targetID string) error {
	blob := store.VaultBlob(userID)
	payload, err := OpenVault(vaultKey, blob)
	if err != nil {
		return err
	}
	delete(payload, targetID)
	sealed, err := SealVault(vaultKey, payload)
	if err != nil {
		return err
	}
	return store.SetVaultBlob(userID, sealed)
}

// GetTargetCreds lit les creds d'une cible.
func GetTargetCreds(store *Store, userID string, vaultKey [32]byte, targetID string) (TargetCreds, bool, error) {
	blob := store.VaultBlob(userID)
	payload, err := OpenVault(vaultKey, blob)
	if err != nil {
		return TargetCreds{}, false, err
	}
	c, ok := payload[targetID]
	return c, ok, nil
}

// VaultEntryMeta métadonnées coffre sans secrets (pour GET /api/vault).
type VaultEntryMeta struct {
	TargetID      string `json:"target_id"`
	Username      string `json:"username,omitempty"` // login SSH (identité, pas secret)
	HasPassword   bool   `json:"has_password"`
	HasPrivateKey bool   `json:"has_private_key"`
}

// ListVaultMeta liste les entrées coffre sans jamais exposer password/clé.
func ListVaultMeta(store *Store, userID string, vaultKey [32]byte) ([]VaultEntryMeta, error) {
	blob := store.VaultBlob(userID)
	payload, err := OpenVault(vaultKey, blob)
	if err != nil {
		return nil, err
	}
	out := make([]VaultEntryMeta, 0, len(payload))
	for id, c := range payload {
		out = append(out, VaultEntryMeta{
			TargetID:      id,
			Username:      c.Username,
			HasPassword:   c.Password != "",
			HasPrivateKey: c.PrivateKey != "",
		})
	}
	return out, nil
}
