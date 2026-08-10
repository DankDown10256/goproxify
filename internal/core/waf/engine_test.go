// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestInspectSQLi(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	r := httptest.NewRequest(http.MethodGet, "/x?q=1+UNION+SELECT+password+FROM+users", nil)
	matches := e.Inspect(r, 1)
	if len(matches) == 0 {
		t.Fatal("expected SQLi match")
	}
}

func TestExcludeIDsPerRoute(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	r := httptest.NewRequest(http.MethodGet, "/x?q=1+UNION+SELECT+password+FROM+users", nil)
	if len(e.Inspect(r, 1, 942100)) != 0 {
		// 942100 is primary SQLi; other SQLi rules may still match
	}
	// Exclude all SQLi rule IDs
	matches := e.Inspect(r, 1, 942100, 942110, 942120)
	for _, m := range matches {
		if m.Category == "sqli" {
			t.Fatalf("sqli should be excluded, got %#v", m)
		}
	}
}

func TestMiddlewareBlockAndDetect(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	block := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "block"}, next)
	rr := httptest.NewRecorder()
	block.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("block: got %d", rr.Code)
	}

	detect := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "detect"}, next)
	rr = httptest.NewRecorder()
	detect.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("detect: got %d", rr.Code)
	}
	if rr.Header().Get("X-WAF-Match") == "" {
		t.Fatal("detect: missing X-WAF-Match")
	}
}
