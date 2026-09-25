// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// TestMetricsSummaryDecryptsTokenBeforeBearer vérifie que le proxy
// GET /internal/v1/metrics/summary vers Core envoie le token en clair même
// quand tokens.token est chiffré au repos (auth.SealNodeToken) — même bug
// que backends_health.go et corepush/pusher.go.
func TestMetricsSummaryDecryptsTokenBeforeBearer(t *testing.T) {
	auth.ConfigureNodeTokenKey("test-jwt-secret")
	defer auth.ConfigureNodeTokenKey("")

	plainToken := "gpx_core_plaintext_xyz789"
	stored, _ := auth.PrepareNodeTokenForStore(plainToken)

	var gotAuth string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{}`)) //nolint:errcheck
	}))
	defer core.Close()

	dir := t.TempDir()
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(
		`INSERT INTO nodes (id, node_name, role) VALUES ('core-1', 'core-1', 'core')`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'core', 'core-1', ?)`,
		"tok-1", stored, core.URL,
	); err != nil {
		t.Fatal(err)
	}

	h := &NodesHandler{DB: db}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/core-1/metrics-summary", nil)
	h.metricsSummary(rec, req, "core-1")

	if gotAuth != "Bearer "+plainToken {
		t.Fatalf("Authorization reçu par Core = %q, attendu %q", gotAuth, "Bearer "+plainToken)
	}
}
