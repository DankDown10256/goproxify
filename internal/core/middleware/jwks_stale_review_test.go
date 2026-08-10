// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReviewP2_JWKSServesStaleOnRefreshFail(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kid": "k1", "kty": "RSA", "n": n, "e": e,
			}},
		})
	}))
	t.Cleanup(srv.Close)

	c := &jwksCache{url: srv.URL, client: srv.Client()}
	pub, err := c.get("k1")
	if err != nil || pub == nil {
		t.Fatalf("premier fetch: %v", err)
	}
	c.mu.Lock()
	c.expiry = time.Now().Add(-time.Second)
	c.mu.Unlock()

	pub2, err := c.get("k1")
	if err != nil {
		t.Fatalf("refresh échoué doit servir stale: %v", err)
	}
	if pub2.N.Cmp(pub.N) != 0 {
		t.Fatal("clé stale inattendue")
	}
}
