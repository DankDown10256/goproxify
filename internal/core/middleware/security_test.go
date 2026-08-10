// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestRateLimitBlocksAndRetryAfter(t *testing.T) {
	// Store isolé pour le test
	old := rlStore
	rlStore = &rateLimitStore{
		buckets:    make(map[string]*rateLimiter),
		idleTTL:    old.idleTTL,
		purgeEvery: old.purgeEvery,
	}
	t.Cleanup(func() { rlStore = old })

	cfg := &router.RateLimitConfig{RequestsPerSecond: 1, Burst: 1}
	h := RateLimit(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second: %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After: %q", rr.Header().Get("Retry-After"))
	}

	// Autre IP XFF = bucket distinct
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "203.0.113.10:12345"
	req2.Header.Set("X-Forwarded-For", "198.51.100.8")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req2)
	if rr.Code != http.StatusOK {
		t.Fatalf("other client: %d", rr.Code)
	}
}

func TestBotUABlacklistAndMonitor(t *testing.T) {
	nextOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	block := BotProtection(&router.BotConfig{Enabled: true, Mode: "block"})(nextOK)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "sqlmap/1.0")
	block.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("block ua: %d", rr.Code)
	}

	monitor := BotProtection(&router.BotConfig{Enabled: true, Mode: "monitor"})(nextOK)
	rr = httptest.NewRecorder()
	monitor.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("monitor should pass: %d", rr.Code)
	}
}

func TestBotJSChallengeHMAC(t *testing.T) {
	secret := "test-secret-key"
	nextOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := BotProtection(&router.BotConfig{
		Enabled:         true,
		Mode:            "challenge",
		JSChallenge:     true,
		ChallengeSecret: secret,
	})(nextOK)

	// Sans cookie → challenge HTML
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/app?x=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "_gpx_bot=") {
		t.Fatalf("challenge page missing: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "</script>") && strings.Contains(rr.Body.String(), `"/app?x=1"`) {
		// redirect JSON-escaped — OK
	}

	// Cookie forgé → refusé
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.AddCookie(&http.Cookie{Name: "_gpx_bot", Value: "aaaaaaaaaaaaaaaa.deadbeef"})
	h.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "Checking your browser") {
		t.Fatal("forged cookie should not pass")
	}

	// Cookie signé → OK
	token := "0123456789abcdef0123456789abcdef"
	signed := token + "." + signChallengeToken(secret, token)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.AddCookie(&http.Cookie{Name: "_gpx_bot", Value: signed})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("valid cookie: %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBotChallengeEscapesRedirect(t *testing.T) {
	h := BotProtection(&router.BotConfig{
		Enabled:         true,
		JSChallenge:     true,
		ChallengeSecret: "s",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, `/x?q="</script><script>alert(1)</script>`, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, `"</script><script>`) {
		t.Fatal("unescaped script breakout in challenge page")
	}
}
