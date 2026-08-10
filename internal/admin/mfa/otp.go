// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateOTP génère un code numérique à N chiffres (défaut 6).
func GenerateOTP(digits int) (string, error) {
	if digits <= 0 {
		digits = 6
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n), nil
}
