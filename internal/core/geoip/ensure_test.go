// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsure_SkipIfExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, []byte("already-here"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Ne doit pas appeler le réseau ni openMMDB.
	if err := Ensure(path, "http://127.0.0.1:1/nope", slog.Default()); err != nil {
		t.Fatal(err)
	}
}

func TestEnsure_DownloadWhenMissing(t *testing.T) {
	prev := openMMDB
	openMMDB = func(string) error { return nil }
	defer func() { openMMDB = prev }()

	payload := make([]byte, minDBBytes+8)
	for i := range payload {
		payload[i] = 'x'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("User-Agent attendu")
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "geoip", "GeoLite2-Country.mmdb")
	if err := Ensure(path, srv.URL, slog.Default()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload) {
		t.Fatalf("taille=%d want %d", len(got), len(payload))
	}
}

func TestEnsure_RejectTooSmall(t *testing.T) {
	prev := openMMDB
	openMMDB = func(string) error { return nil }
	defer func() { openMMDB = prev }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tiny"))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "db.mmdb")
	if err := Ensure(path, srv.URL, nil); err == nil {
		t.Fatal("attendu erreur fichier trop petit")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("le fichier final ne doit pas exister")
	}
}

func TestBootstrap_Disabled(t *testing.T) {
	if err := Bootstrap(false, "/nope", "http://127.0.0.1:1", nil); err != nil {
		t.Fatal(err)
	}
}
