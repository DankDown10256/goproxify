// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

func TestAvailableScopesByRole(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	insert := func(id, role string) {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?,?,?,?)`,
			id, id+"@t.local", "x", role)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("v", "user")
	insert("o", "user")
	insert("a", "admin")
	_, _ = db.Exec(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), "o", "domain", "*.io", "write")

	ctx := context.Background()
	viewer := rbac.AvailableScopesForUser(ctx, db, "v")
	if contains(viewer, rbac.ScopeProxiesWrite) || contains(viewer, rbac.ScopeUsersRead) {
		t.Fatalf("user sans grant write: scopes trop larges: %v", viewer)
	}
	if !contains(viewer, rbac.ScopeProxiesRead) {
		t.Fatal("user doit avoir proxies:read")
	}

	op := rbac.AvailableScopesForUser(ctx, db, "o")
	if !contains(op, rbac.ScopeProxiesWrite) || contains(op, rbac.ScopeProxiesDelete) {
		t.Fatalf("user avec grant write: %v", op)
	}

	adm := rbac.AvailableScopesForUser(ctx, db, "a")
	if !contains(adm, rbac.ScopeUsersRead) || !contains(adm, rbac.ScopeProxiesDelete) {
		t.Fatalf("admin scopes: %v", adm)
	}
}

func TestEffectiveHasScopeIntersection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u','e','x','user')`)
	db.Exec(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), "u", "domain", "*", "write")

	plain := auth.GeneratePAT()
	db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES (?,?,?,?,?)`,
		"p", "u", "t", auth.HashPAT(plain), auth.PATPreview(plain))
	db.Exec(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES ('p', ?)`, rbac.ScopeProxiesRead)
	db.Exec(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES ('p', ?)`, rbac.ScopeProxiesWrite)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	var gotRead, gotWrite, gotDelete bool
	h := auth.RequireAuth("secret", db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRead = rbac.EffectiveHasScope(r.Context(), db, rbac.ScopeProxiesRead)
		gotWrite = rbac.EffectiveHasScope(r.Context(), db, rbac.ScopeProxiesWrite)
		gotDelete = rbac.EffectiveHasScope(r.Context(), db, rbac.ScopeProxiesDelete)
	}))
	rr := &responseDiscard{}
	h.ServeHTTP(rr, req)
	if !gotRead || !gotWrite {
		t.Fatalf("read=%v write=%v", gotRead, gotWrite)
	}
	if gotDelete {
		t.Fatal("delete ne doit pas passer (user n'a pas proxies:delete)")
	}

	// Retirer le grant write → write disparaît malgré le scope PAT
	db.Exec(`UPDATE user_scopes SET access_mode='read' WHERE user_id='u'`)
	gotWrite = false
	h.ServeHTTP(rr, req)
	if gotWrite {
		t.Fatal("après perte grant write, write doit être refusé")
	}
}

func TestToolRequiredScope(t *testing.T) {
	if rbac.ToolRequiredScope("list_proxies") != rbac.ScopeProxiesRead {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("create_proxy") != rbac.ScopeProxiesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("update_proxy") != rbac.ScopeProxiesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("set_proxy_enabled") != rbac.ScopeProxiesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("delete_proxy") != rbac.ScopeProxiesDelete {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("list_agents") != rbac.ScopeNodesRead {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("approve_agent") != rbac.ScopeNodesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("revoke_agent") != rbac.ScopeNodesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("list_declared_nodes") != rbac.ScopeNodesRead {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("create_bootstrap_ticket") != rbac.ScopeNodesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("accept_node") != rbac.ScopeNodesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("list_security_bans") != rbac.ScopeAuditRead {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("create_security_ban") != rbac.ScopeSecurityWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("delete_security_ban") != rbac.ScopeSecurityWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("get_portal_config") != rbac.ScopePortalRead {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("list_portal_users") != rbac.ScopePortalRead {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("invite_portal_user") != rbac.ScopePortalWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("push_portal_templates") != rbac.ScopePortalWrite {
		t.Fatal()
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type responseDiscard struct{}

func (responseDiscard) Header() http.Header       { return http.Header{} }
func (responseDiscard) Write([]byte) (int, error) { return 0, nil }
func (responseDiscard) WriteHeader(statusCode int) {}
