// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestExtractJWTClaim(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"preferred_username":"bob","sub":"123"}`))
	tok := "hdr." + payload + ".sig"
	if got := extractJWTClaim(tok, "preferred_username"); got != "bob" {
		t.Fatalf("got %q", got)
	}
	if got := extractJWTClaim(tok, "sub"); got != "123" {
		t.Fatalf("got %q", got)
	}
}

func TestProviderSupportsOIDC(t *testing.T) {
	sso := &router.SSOConfig{
		Provider: "keycloak",
		OIDC: &router.OIDCConfig{
			IssuerURL: "https://id.example/realms/x",
			ClientID:  "portal",
		},
	}
	if !providerSupportsOIDC(sso) {
		t.Fatal("expected oidc support")
	}
	sso.Provider = "basic"
	if providerSupportsOIDC(sso) {
		t.Fatal("basic should not be oidc")
	}
}

func TestPortalOIDCRedirectURI(t *testing.T) {
	h := &HTTPServer{cfg: &Config{PublicHost: "sshportal.example.fr"}}
	sso := &router.SSOConfig{OIDC: &router.OIDCConfig{}}
	got := h.portalOIDCRedirectURI(sso)
	want := "https://sshportal.example.fr/api/oidc/callback"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	sso.OIDC.RedirectURL = "https://custom/cb"
	if h.portalOIDCRedirectURI(sso) != "https://custom/cb" {
		t.Fatal("override")
	}
}

func TestSignUnsignHMAC(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"state": "abc"})
	signed := signHMAC("sec", payload)
	got := unsignHMAC("sec", signed)
	if string(got) != string(payload) {
		t.Fatalf("%s", got)
	}
	if unsignHMAC("wrong", signed) != nil {
		t.Fatal("expected fail")
	}
}
