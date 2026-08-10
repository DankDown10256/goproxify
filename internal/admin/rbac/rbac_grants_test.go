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
	"github.com/vincamok/goproxify/internal/core/router"
)

func TestUserEffectiveGrantsAndCanProxy(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	route := &router.Route{ID: "p1", Host: "api.example.io"}

	must := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t.local','x','user')`)
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('a','a@t.local','x','admin')`)

	if rbac.CanReadProxy(ctx, db, "u", route) || rbac.CanWriteProxy(ctx, db, "u", route) {
		t.Fatal("user sans grant ne doit rien pouvoir")
	}
	if !rbac.CanReadProxy(ctx, db, "a", route) || !rbac.CanWriteProxy(ctx, db, "a", route) {
		t.Fatal("admin sans grant doit tout pouvoir")
	}

	must(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), "u", "domain", "*.example.io", "read")
	if !rbac.CanReadProxy(ctx, db, "u", route) {
		t.Fatal("grant read doit permettre lecture")
	}
	if rbac.CanWriteProxy(ctx, db, "u", route) {
		t.Fatal("grant read ne doit pas permettre écriture")
	}

	must(`UPDATE user_scopes SET access_mode='write' WHERE user_id='u'`)
	if !rbac.CanWriteProxy(ctx, db, "u", route) {
		t.Fatal("grant write doit permettre écriture")
	}

	// Team write + user read same scope → write (max)
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('m','m@t.local','x','user')`)
	tid := uuid.New().String()
	must(`INSERT INTO teams (id, name) VALUES (?, ?)`, tid, "T")
	must(`INSERT INTO team_members (team_id, user_id) VALUES (?, ?)`, tid, "m")
	must(`INSERT INTO team_scopes (id, team_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), tid, "domain", "*.example.io", "write")
	must(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), "m", "domain", "*.example.io", "read")
	grants, err := rbac.UserEffectiveGrants(ctx, db, "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Mode != rbac.AccessWrite {
		t.Fatalf("max mode attendu write, got %#v", grants)
	}
	if !rbac.CanWriteProxy(ctx, db, "m", route) {
		t.Fatal("union max write")
	}

	// Admin scopé
	must(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), "a", "domain", "*.other.io", "write")
	other := &router.Route{ID: "p2", Host: "api.example.io"}
	if rbac.CanReadProxy(ctx, db, "a", other) {
		t.Fatal("admin scopé ne doit pas voir hors grant")
	}
}
