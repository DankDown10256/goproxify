// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const nodeTokenEncPrefix = "gpxnt1:"

var (
	nodeTokMu  sync.RWMutex
	nodeTokKey []byte // nil = pas de chiffrement (hash seul)
)

// ConfigureNodeTokenKey active le chiffrement AES-GCM des tokens nœuds au repos.
// Clé = SHA-256(GPX_NODE_TOKEN_KEY) ou dérivée de jwtSecret si env vide.
func ConfigureNodeTokenKey(jwtSecret string) {
	raw := strings.TrimSpace(os.Getenv("GPX_NODE_TOKEN_KEY"))
	if raw == "" {
		raw = strings.TrimSpace(jwtSecret)
	}
	nodeTokMu.Lock()
	defer nodeTokMu.Unlock()
	if raw == "" {
		nodeTokKey = nil
		return
	}
	sum := sha256.Sum256([]byte(raw))
	nodeTokKey = sum[:]
}

func nodeKey() []byte {
	nodeTokMu.RLock()
	defer nodeTokMu.RUnlock()
	return nodeTokKey
}

// HashNodeToken SHA-256 hex (lookup inbound, comme PAT).
func HashNodeToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// SealNodeToken chiffre le token pour stockage DB (ou laisse en clair si pas de clé).
func SealNodeToken(plain string) string {
	key := nodeKey()
	if key == nil || plain == "" || strings.HasPrefix(plain, nodeTokenEncPrefix) {
		return plain
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return plain
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plain
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plain
	}
	out := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return nodeTokenEncPrefix + base64.StdEncoding.EncodeToString(out)
}

// OpenNodeToken déchiffre un token stocké (passthrough si legacy clair).
func OpenNodeToken(stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, nodeTokenEncPrefix) {
		return stored, nil
	}
	key := nodeKey()
	if key == nil {
		return "", fmt.Errorf("token chiffré — configurer GPX_NODE_TOKEN_KEY ou JWT secret")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, nodeTokenEncPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext trop court")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// PlainNodeToken déchiffre un token stocké ; en cas d'échec retourne la valeur telle quelle.
func PlainNodeToken(stored string) string {
	p, err := OpenNodeToken(stored)
	if err != nil || p == "" {
		return stored
	}
	return p
}

// PrepareNodeTokenForStore retourne (valeur colonne token, token_hash).
func PrepareNodeTokenForStore(plain string) (stored, hash string) {
	hash = HashNodeToken(plain)
	stored = SealNodeToken(plain)
	return stored, hash
}
