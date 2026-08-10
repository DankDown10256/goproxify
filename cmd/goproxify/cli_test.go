// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

func TestParseTTLHours(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0", 0},
		{"", 0},
		{"24", 24},
		{"24h", 24},
		{"7d", 168},
		{"2h", 2},
		{"30m", 1}, // arrondi min 1h
	}
	for _, c := range cases {
		got, err := parseTTLHours(c.in)
		if err != nil {
			t.Fatalf("parseTTLHours(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseTTLHours(%q)=%d want %d", c.in, got, c.want)
		}
	}
	if _, err := parseTTLHours("nope"); err == nil {
		t.Fatal("expected error for invalid TTL")
	}
}

func TestDetectImportFormat(t *testing.T) {
	cases := map[string]string{
		"nginx.conf":     "nginx",
		"traefik.yml":    "traefik-yaml",
		"traefik.yaml":   "traefik-yaml",
		"routes.toml":    "traefik-toml",
		"Caddyfile":      "caddy",
		"haproxy.cfg":    "haproxy",
		"proxies.json":   "json",
		"backup.gpx-admin-backup": "goproxify",
	}
	for path, want := range cases {
		if got := detectImportFormat(path); got != want {
			t.Errorf("detectImportFormat(%q)=%q want %q", path, got, want)
		}
	}
}

func TestFilterProxiesBySelect(t *testing.T) {
	in := []importer.DetectedProxy{
		{Host: "app.example.fr"},
		{Host: "api.example.fr"},
		{Host: "other.example.fr"},
	}
	got := filterProxiesBySelect(in, "app.example.fr, API.example.fr")
	if len(got) != 2 {
		t.Fatalf("got %d want 2", len(got))
	}
	got = filterProxiesBySelect(in, "")
	if len(got) != 3 {
		t.Fatalf("empty select should keep all, got %d", len(got))
	}
}

func TestMaskToken(t *testing.T) {
	tok := "gpx_core_abcdef0123456789"
	m := maskToken(tok)
	if m == tok || len(m) >= len(tok) {
		t.Fatalf("maskToken did not mask: %q", m)
	}
}

func TestAdminClientDoJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/tokens" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "1", "token": "gpx_core_abc", "role": "core"})
	}))
	defer srv.Close()

	c := &adminClient{base: srv.URL, token: "test-tok", client: srv.Client()}
	var out map[string]string
	if _, err := c.DoJSON("POST", "/api/v1/tokens", map[string]string{"role": "core"}, &out, 201); err != nil {
		t.Fatal(err)
	}
	if out["id"] != "1" {
		t.Fatalf("unexpected: %v", out)
	}
}

func TestAlertTestOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/alert-channels/ch1/test" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()
	c := &adminClient{base: srv.URL, token: "t", client: srv.Client()}
	if err := alertTestOne(c, "ch1"); err != nil {
		t.Fatal(err)
	}
}

func TestCollectImportFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(f1, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := collectImportFiles(f1)
	if err != nil || len(files) != 1 {
		t.Fatalf("file: %v %v", files, err)
	}
	files, err = collectImportFiles(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("dir: %v %v", files, err)
	}
}
