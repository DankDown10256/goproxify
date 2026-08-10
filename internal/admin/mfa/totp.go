// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package mfa fournit les primitives de double authentification (2FA/MFA).
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// TOTPSecret génère un secret TOTP aléatoire encodé en base32.
func TOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPCode retourne le code TOTP courant pour un secret donné.
func TOTPCode(secret string) (string, error) {
	return totpAt(secret, time.Now())
}

// TOTPVerify vérifie un code TOTP en acceptant une fenêtre de ±1 intervalle (30 s).
func TOTPVerify(secret, code string) bool {
	t := time.Now()
	for _, offset := range []int64{-1, 0, 1} {
		candidate, err := totpAt(secret, t.Add(time.Duration(offset)*30*time.Second))
		if err != nil {
			continue
		}
		if candidate == strings.TrimSpace(code) {
			return true
		}
	}
	return false
}

// TOTPProvisionURI génère l'URI otpauth:// pour le QR code.
func TOTPProvisionURI(secret, email, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, email, secret, issuer,
	)
}

func totpAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("totp: décodage secret : %w", err)
	}
	counter := uint64(math.Floor(float64(t.Unix()) / 30))
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := (binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}
