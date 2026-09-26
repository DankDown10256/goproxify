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
// GET /internal/v1/metrics/summary vers passerelle envoie le token en clair même
// quand tokens.token est chiffré au repos (auth.SealNodeToken) — même bug
// que backends_health.go et edgepush/pusher.go.
func TestMetricsSummaryDecryptsTokenBeforeBearer(t *testing.T) {
	auth.ConfigureNodeTokenKey("test-jwt-secret")
	defer auth.ConfigureNodeTokenKey("")

	plainToken := "gpx_edge_plaintext_xyz789"
	stored, _ := auth.PrepareNodeTokenForStore(plainToken)

	var gotAuth string
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{}`)) //nolint:errcheck
	}))
	defer edge.Close()

	dir := t.TempDir()
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(
		`INSERT INTO nodes (id, node_name, role) VALUES ('edge-1', 'edge-1', 'edge')`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'edge', 'edge-1', ?)`,
		"tok-1", stored, edge.URL,
	); err != nil {
		t.Fatal(err)
	}

	h := &NodesHandler{DB: db}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/edge-1/metrics-summary", nil)
	h.metricsSummary(rec, req, "edge-1")

	if gotAuth != "Bearer "+plainToken {
		t.Fatalf("Authorization reçu par passerelle = %q, attendu %q", gotAuth, "Bearer "+plainToken)
	}
}
