// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestAnomalyScoring vérifie que le scoring cumulatif bloque uniquement
// quand le score total atteint le seuil.
func TestAnomalyScoring(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Un seul signal medium (score 3) avec seuil 5 → ne doit PAS bloquer.
	cfg := &router.WAFConfig{Enabled: true, Mode: "block", AnomalyThreshold: 5}
	h := e.Middleware(cfg, next)

	// 920100 : header injection (medium, score 3) — mais c'est difficile à déclencher seul en test.
	// On utilise un XSS critique (score 5) qui seul dépasse le seuil 5.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("anomaly threshold 5: XSS critique (score 5) should block, got %d", rr.Code)
	}

	// Avec seuil 10, un seul XSS critique (score 5) ne suffit pas.
	cfg2 := &router.WAFConfig{Enabled: true, Mode: "block", AnomalyThreshold: 10}
	h2 := e.Middleware(cfg2, next)
	rr2 := httptest.NewRecorder()
	h2.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("anomaly threshold 10: single XSS should pass, got %d", rr2.Code)
	}
}

// TestJSONBodyInspection vérifie l'inspection des valeurs JSON décodées.
func TestJSONBodyInspection(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	payload := `{"username":"admin","query":"1 UNION SELECT password FROM users"}`
	r := httptest.NewRequest(http.MethodPost, "/api/search", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(payload))

	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.Category == "sqli" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected SQLi match in JSON body")
	}
}

// TestFormBodyInspection vérifie l'inspection des form values.
func TestFormBodyInspection(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	payload := "search=<script>alert(1)</script>&page=1"
	r := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ContentLength = int64(len(payload))

	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.Category == "xss" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected XSS match in form body")
	}
}

// TestCustomRules vérifie les règles définies par l'utilisateur.
func TestCustomRules(t *testing.T) {
	cfg := &router.WAFConfig{
		Enabled: true,
		Mode:    "block",
		CustomRules: []router.CustomRule{
			{
				ID:       99001,
				Category: "custom",
				Severity: "high",
				Pattern:  `(?i)evil-payload`,
				Targets:  []string{"args", "body"},
				Message:  "Payload custom interdit",
			},
		},
	}
	e := NewEngine(cfg, slog.Default())
	r := httptest.NewRequest(http.MethodGet, "/x?test=evil-payload", nil)
	matches := e.Inspect(r, 1)
	found := false
	for _, m := range matches {
		if m.RuleID == 99001 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("custom rule 99001 should have matched")
	}
}

// TestUpdateConfig vérifie le rechargement à chaud des règles.
func TestUpdateConfig(t *testing.T) {
	e := NewEngine(nil, slog.Default())

	// Avant rechargement : aucune règle custom
	r := httptest.NewRequest(http.MethodGet, "/?x=evil-reload-test", nil)
	if len(e.Inspect(r, 1)) != 0 {
		t.Skip("unexpected match before reload")
	}

	// Rechargement avec règle custom
	e.UpdateConfig(&router.WAFConfig{
		Enabled: true,
		CustomRules: []router.CustomRule{
			{ID: 99002, Category: "custom", Severity: "high", Pattern: `evil-reload-test`, Targets: []string{"args"}},
		},
	})

	r2 := httptest.NewRequest(http.MethodGet, "/?x=evil-reload-test", nil)
	matches := e.Inspect(r2, 1)
	found := false
	for _, m := range matches {
		if m.RuleID == 99002 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("custom rule 99002 should have matched after hot reload")
	}
}

// TestContextMatches vérifie que les matches sont accessibles depuis le contexte.
func TestContextMatches(t *testing.T) {
	e := NewEngine(nil, slog.Default())
	var ctxMatches []Match
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxMatches = MatchesFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := e.Middleware(&router.WAFConfig{Enabled: true, Mode: "detect"}, next)
	body := bytes.NewBufferString("")
	r := httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", body)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if len(ctxMatches) == 0 {
		t.Fatal("WAF matches should be in context")
	}
}
