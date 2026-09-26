// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// TestBackendsHealthDecryptsTokenBeforeBearer reproduit le bug corrigé :
// tokens.token peut être chiffré au repos (auth.SealNodeToken), tandis que
// Passerelle ne connaît que le hash du token EN CLAIR (pushAdminToken le
// déchiffre avant de l'envoyer à passerelle). Sans déchiffrement symétrique ici,
// le Bearer envoyé ne matchait jamais → 401 permanent dès que le
// chiffrement est actif. Vérifie que la passerelle (simulé) reçoit bien le
// token en clair.
func TestBackendsHealthDecryptsTokenBeforeBearer(t *testing.T) {
	auth.ConfigureNodeTokenKey("test-jwt-secret")
	defer auth.ConfigureNodeTokenKey("")

	plainToken := "gpx_edge_plaintext_abc123"
	stored, _ := auth.PrepareNodeTokenForStore(plainToken)

	var gotAuth string
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"backends": map[string]string{"http://b:80": "up"}}) //nolint:errcheck
	}))
	defer edge.Close()

	dir := t.TempDir()
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(
		`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'edge', 'edge-1', ?)`,
		"tok-1", stored, edge.URL,
	); err != nil {
		t.Fatal(err)
	}

	h := &BackendsHealthHandler{DB: db}
	_ = h.fetchFromEdges(context.Background())

	if gotAuth != "Bearer "+plainToken {
		t.Fatalf("Authorization reçu par passerelle = %q, attendu %q", gotAuth, "Bearer "+plainToken)
	}
}
