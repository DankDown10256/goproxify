// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

const backupEncPrefix = "GPXBK1:"

// backupKey dérive une clé 32 octets depuis GPX_BACKUP_KEY (optionnel).
func backupKey() ([]byte, bool) {
	raw := strings.TrimSpace(os.Getenv("GPX_BACKUP_KEY"))
	if raw == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], true
}

func sealSnapshot(plain []byte) ([]byte, error) {
	key, ok := backupKey()
	if !ok {
		return plain, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, plain, nil)
	return []byte(backupEncPrefix + base64.StdEncoding.EncodeToString(out)), nil
}

func openSnapshot(data []byte) ([]byte, error) {
	s := string(data)
	if !strings.HasPrefix(s, backupEncPrefix) {
		return data, nil
	}
	key, ok := backupKey()
	if !ok {
		return nil, fmt.Errorf("snapshot chiffré — définir GPX_BACKUP_KEY")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, backupEncPrefix))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext trop court")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
