// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// InviteTTL durée de validité d'une invitation.
const InviteTTL = 72 * time.Hour

// NewInviteToken génère un jeton brut (à envoyer par email).
func NewInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("invite token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashInviteToken SHA-256 hex du jeton brut.
func HashInviteToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// InviteExpiryRFC3339 retourne maintenant + InviteTTL en UTC.
func InviteExpiryRFC3339() string {
	return time.Now().UTC().Add(InviteTTL).Format(time.RFC3339)
}

// InviteExpired indique si la date RFC3339 est passée (vide = expiré).
func InviteExpired(expiresRFC3339 string) bool {
	if expiresRFC3339 == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, expiresRFC3339)
	if err != nil {
		return true
	}
	return time.Now().UTC().After(t)
}
