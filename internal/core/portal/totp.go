// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
)

// TOTPSecret génère un secret TOTP base32.
func TOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPCode code courant (tests).
func TOTPCode(secret string) (string, error) {
	return totpAt(secret, time.Now())
}

// TOTPVerify accepte ±1 fenêtre de 30s.
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

// TOTPProvisionURI URI otpauth pour QR.
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

// EmailOTPTTL durée de validité d'un OTP email.
const EmailOTPTTL = 10 * time.Minute

// MFAChallengeTTL durée du challenge post-login.
const MFAChallengeTTL = 5 * time.Minute

// HashEmailOTP SHA-256 hex du code OTP.
func HashEmailOTP(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

// NewEmailOTPCode génère un code numérique 6 chiffres.
func NewEmailOTPCode() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", n%1_000_000), nil
}

// UserHas2FA indique si au moins une méthode est active.
func UserHas2FA(u UserRecord) bool {
	return u.TOTPEnabled || u.EmailOTPEnabled
}

// User2FAMethods liste les méthodes actives.
func User2FAMethods(u UserRecord) []string {
	var m []string
	if u.TOTPEnabled {
		m = append(m, "totp")
	}
	if u.EmailOTPEnabled {
		m = append(m, "email")
	}
	return m
}
