// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Tests de revue P0 #1 — comportement attendu AVANT / APRÈS correctif.
// Aujourd'hui validateJWT accepte alg=none et HS* sans secret : ces tests doivent
// échouer sur main actuel et passer une fois le fix appliqué.

func reviewJWTPayload(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"sub": "attacker",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iss": "https://idp.example",
		"aud": "gpx",
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestReviewP0_ValidateJWTRejectsAlgNone(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tok := hdr + "." + reviewJWTPayload(t) + "."
	if _, err := validateJWT(tok, nil, "", ""); err == nil {
		t.Fatal("alg=none doit être refusé (pas de vérification de signature)")
	}
}

func TestReviewP0_ValidateJWTRejectsEmptyAlg(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	tok := hdr + "." + reviewJWTPayload(t) + ".e30"
	if _, err := validateJWT(tok, nil, "", ""); err == nil {
		t.Fatal("alg vide doit être refusé")
	}
}

func TestReviewP0_ValidateJWTRejectsHSWithoutVerification(t *testing.T) {
	// Token HS256 avec signature bidon, sans JWKS ni secret configuré côté validateJWT.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	tok := hdr + "." + reviewJWTPayload(t) + "." + base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	if _, err := validateJWT(tok, &jwksCache{}, "", ""); err == nil {
		t.Fatal("HS256 sans secret/JWKS doit être refusé")
	}
}

func TestReviewP0_JWTValidationMiddlewareRejectsAlgNone(t *testing.T) {
	cfg := &router.JWTConfig{
		Enabled: true,
		JWKSURL: "https://idp.example/jwks", // présent mais non utilisé pour alg=none
	}
	var hit bool
	h := JWTValidation(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tok := hdr + "." + reviewJWTPayload(t) + "."
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if hit {
		t.Fatal("handler aval ne doit pas être atteint avec alg=none")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}
