// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"10m", 10 * time.Minute},
		{"1h", time.Hour},
		{"30s", 30 * time.Second},
		{"60", 60 * time.Second},
		{"invalid", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := parseTTL(tc.in)
		if got != tc.want {
			t.Errorf("parseTTL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestResolveTTL_ValidRules(t *testing.T) {
	cfg := &router.CacheConfig{
		ValidRules: []router.CacheValidRule{
			{StatusCodes: []int{200}, TTL: "5m"},
			{StatusCodes: []int{404}, TTL: "10s"},
		},
	}
	if got := resolveTTL(200, http.Header{}, cfg); got != 5*time.Minute {
		t.Errorf("got %v, want 5m", got)
	}
	if got := resolveTTL(404, http.Header{}, cfg); got != 10*time.Second {
		t.Errorf("got %v, want 10s", got)
	}
	if got := resolveTTL(500, http.Header{}, cfg); got != 0 {
		t.Errorf("got %v, want 0 (no matching rule)", got)
	}
}

func TestResolveTTL_Fallback(t *testing.T) {
	h := http.Header{"Cache-Control": []string{"max-age=120"}}
	if got := resolveTTL(200, h, nil); got != 120*time.Second {
		t.Errorf("got %v, want 120s", got)
	}
	h2 := http.Header{"Cache-Control": []string{"no-store"}}
	if got := resolveTTL(200, h2, nil); got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

func TestIsBypass_Header(t *testing.T) {
	cfg := &router.CacheConfig{BypassHeaders: []string{"X-No-Cache"}}
	req := httptest.NewRequest("GET", "/", nil)
	if isBypass(req, cfg) {
		t.Fatal("should not bypass without the header")
	}
	req.Header.Set("X-No-Cache", "1")
	if !isBypass(req, cfg) {
		t.Fatal("should bypass when header is set")
	}
}

func TestIsBypass_Cookie(t *testing.T) {
	cfg := &router.CacheConfig{BypassCookies: []string{"session"}}
	req := httptest.NewRequest("GET", "/", nil)
	if isBypass(req, cfg) {
		t.Fatal("should not bypass without cookie")
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	if !isBypass(req, cfg) {
		t.Fatal("should bypass when cookie is present")
	}
}

func TestMiddlewareWithConfig_CacheHitMiss(t *testing.T) {
	dir := t.TempDir()
	dc := New(dir)
	cfg := &router.CacheConfig{
		Enabled:    true,
		ValidRules: []router.CacheValidRule{{StatusCodes: []int{200}, TTL: "1m"}},
	}

	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})
	h := dc.MiddlewareWithConfig(cfg)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first request should be MISS, got %q", rec.Header().Get("X-Cache"))
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("second request should be HIT, got %q", rec2.Header().Get("X-Cache"))
	}
	if calls != 1 {
		t.Errorf("backend should only be called once, got %d", calls)
	}
}

func TestMiddlewareWithConfig_BypassSkipsCache(t *testing.T) {
	dir := t.TempDir()
	dc := New(dir)
	cfg := &router.CacheConfig{
		Enabled:       true,
		ValidRules:    []router.CacheValidRule{{TTL: "1m"}},
		BypassHeaders: []string{"X-Bypass"},
	}

	calls := 0
	h := dc.MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bypass", nil)
	req.Header.Set("X-Bypass", "true")
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if calls != 2 {
		t.Errorf("bypass should call backend every time, got %d", calls)
	}
}
