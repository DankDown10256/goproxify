// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const BackupCodeCount = 10

// GenerateBackupCodes génère N codes de secours aléatoires au format XXXX-XXXX-XXXX.
// Retourne les codes en clair (à afficher une seule fois) et leurs hashes bcrypt.
func GenerateBackupCodes() (plain []string, hashes []string, err error) {
	for i := 0; i < BackupCodeCount; i++ {
		b := make([]byte, 6)
		if _, err = rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("backup codes: génération : %w", err)
		}
		code := formatBackupCode(hex.EncodeToString(b))
		plain = append(plain, code)

		h, err := bcrypt.GenerateFromPassword([]byte(strings.ReplaceAll(code, "-", "")), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, fmt.Errorf("backup codes: hash : %w", err)
		}
		hashes = append(hashes, string(h))
	}
	return plain, hashes, nil
}

// CheckBackupCode vérifie un code de secours contre un hash bcrypt.
// Le code est normalisé (tirets supprimés, minuscules).
func CheckBackupCode(hash, code string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalized)) == nil
}

// formatBackupCode formate 12 hex chars en XXXX-XXXX-XXXX.
func formatBackupCode(s string) string {
	s = strings.ToUpper(s)
	if len(s) < 12 {
		s = s + strings.Repeat("0", 12-len(s))
	}
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}
