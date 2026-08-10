// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mfa"
)

func TestMediumM1_WebAuthnLoginRequiresPending(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "m1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	secret := "test-jwt-secret-m1"
	h := &MFAHandler{
		DB:        db,
		Store:     mfa.NewStore(db),
		JWTSecret: secret,
		WebAuthn:  nil, // 503 après auth pour begin ; finish teste 401 avant
	}

	// finish sans mfa_token → 401
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/webauthn/login/finish",
		bytes.NewReader([]byte(`{"challenge_id":"x","response":{}}`)))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("finish sans pending: got %d want 401", rr.Code)
	}

	// begin sans mfa_token → 401
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/webauthn/login/begin",
		bytes.NewReader([]byte(`{}`)))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("begin sans pending: got %d want 401", rr.Code)
	}

	pending, err := adminauth.SignMFAPendingToken("user-1", secret)
	if err != nil {
		t.Fatal(err)
	}

	// begin avec pending valide : passe le gate MFA (503 = WebAuthn non configuré, pas 401)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/webauthn/login/begin",
		bytes.NewReader([]byte(`{"mfa_token":`+jsonQuote(pending)+`}`)))
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatal("begin avec pending ne doit pas être 401")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("begin avec pending + WebAuthn nil: got %d want 503", rr.Code)
	}

	// finish avec pending valide : passe le gate MFA (503 WebAuthn nil, pas 401)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/webauthn/login/finish",
		bytes.NewReader([]byte(`{"mfa_token":`+jsonQuote(pending)+`,"challenge_id":"x","response":{}}`)))
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatal("finish avec pending ne doit pas être 401")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("finish avec pending + WebAuthn nil: got %d want 503", rr.Code)
	}

	// Contrat : pending → JWT session (chemin post-ValidateLogin)
	uid, err := adminauth.VerifyMFAPendingToken(pending, secret)
	if err != nil || uid != "user-1" {
		t.Fatalf("pending: %q %v", uid, err)
	}
	tok, err := adminauth.SignJWT(uid, secret, time.Hour)
	if err != nil || tok == "" {
		t.Fatalf("JWT après pending: %v", err)
	}
	if _, err := adminauth.VerifyJWT(tok, secret); err != nil {
		t.Fatalf("JWT vérif: %v", err)
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
