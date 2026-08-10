// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

func TestDomainScopePattern(t *testing.T) {
	cases := map[string]string{
		"*.comprenonsnous.fr": "*.comprenonsnous.fr",
		"comprenonsnous.fr":   "*.comprenonsnous.fr",
		"www.comprenonsnous.fr": "www.comprenonsnous.fr",
		"api.dev.example.fr":  "api.dev.example.fr",
	}
	for in, want := range cases {
		if got := rbac.DomainScopePattern(in); got != want {
			t.Fatalf("DomainScopePattern(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestEnsureDomainScope(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "ensure_scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	must := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	adminTok := uuid.New().String()
	restrictedTok := uuid.New().String()
	viewerTok := uuid.New().String()
	must(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES (?,?,?,?,?)`,
		adminTok, "tok-admin", "core", "core-admin", "admin")
	must(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES (?,?,?,?,?)`,
		restrictedTok, "tok-rest", "core", "core-rest", "admin")
	must(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES (?,?,?,?,?)`,
		viewerTok, "tok-view", "core", "core-view", "viewer")
	must(`INSERT INTO token_scopes (id, token_id, scope_type, scope_value) VALUES (?,?,?,?)`,
		uuid.New().String(), restrictedTok, "domain", "*.other.fr")

	// Admin sans scope → no-op
	val, added, err := rbac.EnsureDomainScope(ctx, db, adminTok, "comprenonsnous.fr")
	if err != nil || added || val != "" {
		t.Fatalf("admin global: val=%q added=%v err=%v", val, added, err)
	}

	// Restreint sans couverture → insert *.apex
	val, added, err = rbac.EnsureDomainScope(ctx, db, restrictedTok, "comprenonsnous.fr")
	if err != nil || !added || val != "*.comprenonsnous.fr" {
		t.Fatalf("restricted add: val=%q added=%v err=%v", val, added, err)
	}

	// Déjà couvert → no-op
	val, added, err = rbac.EnsureDomainScope(ctx, db, restrictedTok, "*.comprenonsnous.fr")
	if err != nil || added {
		t.Fatalf("already covered: val=%q added=%v err=%v", val, added, err)
	}

	// Viewer sans scope → doit ajouter (sinon ne reçoit rien)
	val, added, err = rbac.EnsureDomainScope(ctx, db, viewerTok, "exemple.fr")
	if err != nil || !added || val != "*.exemple.fr" {
		t.Fatalf("viewer add: val=%q added=%v err=%v", val, added, err)
	}

	scopes, err := rbac.TokenScopes(ctx, db, restrictedTok)
	if err != nil {
		t.Fatal(err)
	}
	if !rbac.MatchCertName(scopes, "www.comprenonsnous.fr") {
		t.Fatal("scope *.comprenonsnous.fr doit couvrir www")
	}
}
