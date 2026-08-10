// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := auth.HashPassword("monmotdepasse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash vide")
	}

	if !auth.CheckPassword(hash, "monmotdepasse") {
		t.Error("CheckPassword: devrait valider le bon mot de passe")
	}
	if auth.CheckPassword(hash, "mauvais") {
		t.Error("CheckPassword: ne devrait pas valider un mauvais mot de passe")
	}
}

func TestSignAndVerifyJWT(t *testing.T) {
	secret := "test_secret_jwt"
	userID := "user-abc-123"

	tokenStr, err := auth.SignJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("token JWT vide")
	}

	got, err := auth.VerifyJWT(tokenStr, secret)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if got != userID {
		t.Errorf("VerifyJWT: attendu %q, reçu %q", userID, got)
	}
}

func TestVerifyJWTExpired(t *testing.T) {
	secret := "test_secret_jwt"
	tokenStr, err := auth.SignJWT("u1", secret, -time.Second)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	_, err = auth.VerifyJWT(tokenStr, secret)
	if err == nil {
		t.Error("VerifyJWT: devrait échouer sur un token expiré")
	}
}

func TestVerifyJWTBadSecret(t *testing.T) {
	tokenStr, err := auth.SignJWT("u1", "secret1", time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	_, err = auth.VerifyJWT(tokenStr, "secret2")
	if err == nil {
		t.Error("VerifyJWT: devrait échouer avec un mauvais secret")
	}
}

func TestVerifyJWTRejectsMFAPending(t *testing.T) {
	secret := "test_secret_jwt"
	pending, err := auth.SignMFAPendingToken("user-mfa", secret)
	if err != nil {
		t.Fatalf("SignMFAPendingToken: %v", err)
	}
	if _, err := auth.VerifyJWT(pending, secret); err == nil {
		t.Fatal("VerifyJWT: doit rejeter un token mfa_pending")
	}
	uid, err := auth.VerifyMFAPendingToken(pending, secret)
	if err != nil || uid != "user-mfa" {
		t.Fatalf("VerifyMFAPendingToken: uid=%q err=%v", uid, err)
	}
}

func TestSecureEqual(t *testing.T) {
	if !auth.SecureEqual("abc", "abc") {
		t.Error("SecureEqual: égalité attendue")
	}
	if auth.SecureEqual("abc", "abd") {
		t.Error("SecureEqual: inégalité attendue")
	}
	if auth.SecureEqual("abc", "abcd") {
		t.Error("SecureEqual: longueurs différentes")
	}
}

func TestGenerateToken(t *testing.T) {
	cases := []struct {
		role, prefix string
	}{
		{"core", "gpx_core_"},
		{"agent", "gpx_join_"},
	}
	for _, tc := range cases {
		tok := auth.GenerateToken(tc.role, "node-1")
		if !strings.HasPrefix(tok, tc.prefix) {
			t.Errorf("GenerateToken(%q): attendu préfixe %q, reçu %q", tc.role, tc.prefix, tok)
		}
		hex := strings.TrimPrefix(tok, tc.prefix)
		if len(hex) != 32 {
			t.Errorf("GenerateToken(%q): partie hex doit faire 32 chars, reçu %d (%q)", tc.role, len(hex), hex)
		}
	}

	// Unicité : deux appels doivent produire des tokens différents
	t1 := auth.GenerateToken("core", "n1")
	t2 := auth.GenerateToken("core", "n1")
	if t1 == t2 {
		t.Error("GenerateToken: deux appels identiques ne devraient pas produire le même token")
	}
}
