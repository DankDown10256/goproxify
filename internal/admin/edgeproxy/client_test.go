// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilesEnabled(t *testing.T) {
	if !FilesEnabled() {
		t.Fatal("expected files mode always enabled")
	}
}

func TestClientPublishRoundTrip(t *testing.T) {
	var created, dryrun, promote bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/proxies/revisions", func(w http.ResponseWriter, r *http.Request) {
		created = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "p1", "revision": "r1", "host": "a.example.fr", "status": "pending",
			"enabled": true, "config": map[string]any{"id": "p1", "host": "a.example.fr"},
		})
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", func(w http.ResponseWriter, r *http.Request) {
		dryrun = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "p1", "revision": "r1", "status": "validated",
			"dry_run": map[string]any{"ok": true, "errors": []string{}},
			"config":  map[string]any{"id": "p1"},
		})
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", func(w http.ResponseWriter, r *http.Request) {
		promote = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "p1", "host": "a.example.fr", "status": "production",
			"enabled": true, "config": map[string]any{"id": "p1", "host": "a.example.fr"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.HTTP = srv.Client()
	env, err := c.Publish(context.Background(), Target{Endpoint: srv.URL, Token: "t"}, "p1", "a.example.fr", true,
		json.RawMessage(`{"id":"p1","host":"a.example.fr","type":"http","backends":[{"url":"http://127.0.0.1:1","weight":1}],"lb":"round_robin"}`),
		"admin")
	if err != nil {
		t.Fatal(err)
	}
	if !created || !dryrun || !promote {
		t.Fatalf("flow incomplete created=%v dry=%v promote=%v", created, dryrun, promote)
	}
	if env.Status != "production" || env.Host != "a.example.fr" {
		t.Fatalf("%+v", env)
	}
}
