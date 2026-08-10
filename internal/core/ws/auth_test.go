// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateAdminHMACEmptySecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/admin", nil)
	if err := ValidateAdminHMAC(req, ""); err == nil {
		t.Fatal("secret vide doit être refusé (fail-closed)")
	}
}

func TestValidateAdminHMACValid(t *testing.T) {
	secret := "pairing-secret-test"
	req := httptest.NewRequest(http.MethodGet, "/ws/admin", nil)
	req.Header.Set(hmacHeader, BuildAdminSignature(secret, http.MethodGet, "/ws/admin"))
	if err := ValidateAdminHMAC(req, secret); err != nil {
		t.Fatalf("HMAC valide: %v", err)
	}
}

func TestValidateAdminHMACMissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/admin", nil)
	if err := ValidateAdminHMAC(req, "secret"); err == nil {
		t.Fatal("header manquant doit être refusé")
	}
}

func TestValidateAdminHMACBadSig(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/admin", nil)
	req.Header.Set(hmacHeader, BuildAdminSignature("other", http.MethodGet, "/ws/admin"))
	if err := ValidateAdminHMAC(req, "secret"); err == nil {
		t.Fatal("mauvaise signature doit être refusée")
	}
}
