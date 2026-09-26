// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import "testing"

// Revue P1 #12 — contrat discovery OIDC (sans HTTP : SSRF bloque le loopback httptest).

func TestReviewP1_OIDCDiscoverRejectsEmptyAuthorize(t *testing.T) {
	if err := oidcEndpointsValid("", "https://idp.example/token"); err == nil {
		t.Fatal("authorization_endpoint vide doit être refusé")
	}
}

func TestReviewP1_OIDCDiscoverRejectsEmptyToken(t *testing.T) {
	if err := oidcEndpointsValid("https://idp.example/authorize", ""); err == nil {
		t.Fatal("token_endpoint vide doit être refusé")
	}
}

func TestReviewP1_OIDCDiscoverAcceptsValidDoc(t *testing.T) {
	if err := oidcEndpointsValid("https://idp.example/authorize", "https://idp.example/token"); err != nil {
		t.Fatalf("endpoints valides: %v", err)
	}
}
