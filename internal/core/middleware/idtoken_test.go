// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSafeLocalRedirect(t *testing.T) {
	cases := map[string]string{
		"":                    "/",
		"/":                   "/",
		"/app?x=1":            "/app?x=1",
		"/ok#frag":            "/ok#frag",
		"//evil.com":          "/",
		"https://evil.com":    "/",
		"http://evil.com/x":   "/",
		"\\\\evil":            "/",
		"/ok\r\nLocation: x":  "/",
	}
	for in, want := range cases {
		if got := SafeLocalRedirect(in); got != want {
			t.Errorf("SafeLocalRedirect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVerifyOIDCIDToken_HS256(t *testing.T) {
	secret := "client-secret"
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss":"https://idp.example",
		"aud":"portal-client",
		"sub":"u1",
		"nonce":"n-abc",
		"exp":` + jsonNum(time.Now().Add(time.Hour).Unix()) + `,
		"preferred_username":"alice"
	}`))
	msg := header + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	tok := msg + "." + sig

	claims, err := VerifyOIDCIDToken(tok, "", "https://idp.example", "portal-client", "n-abc", secret)
	if err != nil {
		t.Fatal(err)
	}
	if ClaimString(claims, "preferred_username") != "alice" {
		t.Fatalf("claims=%v", claims)
	}

	if _, err := VerifyOIDCIDToken(tok, "", "https://idp.example", "portal-client", "wrong-nonce", secret); err == nil {
		t.Fatal("nonce mismatch attendu")
	}
	if _, err := VerifyOIDCIDToken(tok, "", "https://idp.example", "portal-client", "n-abc", "bad"); err == nil {
		t.Fatal("bad secret attendu")
	}
	noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	if _, err := VerifyOIDCIDToken(noneHdr+"."+payload+".", "", "https://idp.example", "portal-client", "n-abc", secret); err == nil {
		t.Fatal("alg none doit échouer")
	}
}

func jsonNum(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
