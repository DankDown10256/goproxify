// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgepush

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// TestActiveEdgesDecryptsToken vérifie qu'activeEdges() renvoie le token en
// clair même quand tokens.token est chiffré au repos (auth.SealNodeToken).
// C'est ce token qui est ensuite posé comme Bearer par post() pour pousser
// routes et certificats vers passerelle — sans ce déchiffrement, tous les push
// échouaient en 401 dès que le chiffrement était actif.
func TestActiveEdgesDecryptsToken(t *testing.T) {
	auth.ConfigureNodeTokenKey("test-jwt-secret")
	defer auth.ConfigureNodeTokenKey("")

	plainToken := "gpx_edge_plaintext_routes"
	stored, _ := auth.PrepareNodeTokenForStore(plainToken)

	dir := t.TempDir()
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(
		`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'edge', 'edge-1', 'http://edge-1:8000')`,
		"tok-1", stored,
	); err != nil {
		t.Fatal(err)
	}

	p := New(db, slog.Default())
	edges, err := p.activeEdges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("attendu 1 edge, got %d", len(edges))
	}
	if edges[0].Token != plainToken {
		t.Fatalf("Token = %q, attendu le token en clair %q (pas la valeur chiffrée stockée)", edges[0].Token, plainToken)
	}
}
