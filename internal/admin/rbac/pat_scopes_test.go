// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
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
	if rbac.ToolRequiredScope("purge_proxy_cache") != rbac.ScopeProxiesWrite {
		t.Error("purge_proxy_cache doit exiger proxies:write")
	}
	if rbac.ToolRequiredScope("set_proxy_enabled") != rbac.ScopeProxiesWrite {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("delete_proxy") != rbac.ScopeProxiesDelete {
		t.Fatal()
	}
	if rbac.ToolRequiredScope("list_alert_events") != rbac.ScopeAlertsRead {
		t.Fatal("list_alert_events doit exiger alerts:read")
	}
	for _, tool := range []string{"get_prism_anomalies", "get_prism_geo"} {
		if rbac.ToolRequiredScope(tool) != rbac.ScopeLogsRead {
			t.Fatalf("%s doit exiger logs:read", tool)
		}
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
	for _, tool := range []string{"ban_ip", "unban_ip"} {
		if got := rbac.ToolRequiredScope(tool); got != rbac.ScopeSecurityWrite {
			t.Fatalf("%s : scope %q, attendu %s", tool, got, rbac.ScopeSecurityWrite)
		}
	}
	for _, tool := range []string{"create_security_ban", "delete_security_ban", "ban_ip", "unban_ip"} {
		if !slices.Contains(rbac.ToolsForScope(rbac.ScopeSecurityWrite), tool) {
			t.Fatalf("ToolsForScope(security:write) sans %s", tool)
		}
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

// Outils MCP et routes REST équivalentes exigent le même scope ; les écritures ne
// passent plus avec un scope de lecture que tout compte peut détenir.
func TestToolScopesMatchREST(t *testing.T) {
	for _, c := range []struct{ tool, method, path string }{
		{"get_cert_status", http.MethodGet, "/api/v1/certs/acme-monitor"},
		{"list_cert_deploy_targets", http.MethodGet, "/api/v1/certs/c1/deploy-targets"},
		{"obtain_cert", http.MethodPost, "/api/v1/certs"},
		{"import_cert", http.MethodPost, "/api/v1/certs/import"},
		{"trigger_cert_deploy", http.MethodPost, "/api/v1/certs/c1/deploy-targets/t1/trigger"},
		{"list_internal_cas", http.MethodGet, "/api/v1/internal-ca"},
		{"list_cert_deploy_types", http.MethodGet, "/api/v1/cert-deploy-types"},
		{"list_dns_providers", http.MethodGet, "/api/v1/acme/providers"},
		{"list_dns_provider_types", http.MethodGet, "/api/v1/acme/provider-types"},
		{"list_discovery_sources", http.MethodGet, "/api/v1/discovery-sources"},
		{"get_ech_status", http.MethodGet, "/api/v1/ech"},
		{"list_internal_certs", http.MethodGet, "/api/v1/internal-ca/ca1/certs"},
		{"create_internal_ca", http.MethodPost, "/api/v1/internal-ca"},
		{"issue_internal_cert", http.MethodPost, "/api/v1/internal-ca/ca1/certs"},
		{"revoke_internal_cert", http.MethodDelete, "/api/v1/internal-ca/ca1/certs/x"},
		{"create_domain", http.MethodPost, "/api/v1/domains"},
		{"renew_domain", http.MethodPost, "/api/v1/domains/d1/renew"},
		{"rotate_cert", http.MethodPost, "/api/v1/domains/d1/renew"},
		{"set_container_route_enabled", http.MethodPut, "/api/v1/discovered-containers/enabled"},
		{"list_alert_channels", http.MethodGet, "/api/v1/alert-channels"},
		{"list_alert_channel_types", http.MethodGet, "/api/v1/alert-channel-types"},
		{"create_alert_channel", http.MethodPost, "/api/v1/alert-channels"},
		{"delete_alert_rule", http.MethodDelete, "/api/v1/alert-rules/r1"},
		{"ack_alert_event", http.MethodPost, "/api/v1/alert-events/e1/ack"},
		{"list_security_engine_types", http.MethodGet, "/api/v1/security/engine-types"},
		{"get_waf_activity", http.MethodGet, "/api/v1/security/waf-activity"},
		{"list_plugins", http.MethodGet, "/api/v1/plugins"},
		{"list_auth_providers", http.MethodGet, "/api/v1/auth-providers"},
		{"list_auth_provider_types", http.MethodGet, "/api/v1/auth-provider-types"},
		{"create_auth_provider", http.MethodPost, "/api/v1/auth-providers"},
		{"list_ip_profiles", http.MethodGet, "/api/v1/ip-profiles"},
		{"delete_ip_profile", http.MethodDelete, "/api/v1/ip-profiles/p1"},
		{"create_snippet", http.MethodPost, "/api/v1/snippets"},
		{"list_detector_types", http.MethodGet, "/api/v1/detector-types"},
		{"list_flows", http.MethodGet, "/api/v1/automation/flows"},
		{"run_flow", http.MethodPost, "/api/v1/automation/flows/f1/run"},
		{"simulate_flow", http.MethodPost, "/api/v1/automation/simulate"},
		{"list_flow_runs", http.MethodGet, "/api/v1/automation/runs"},
		{"decide_flow_run", http.MethodPost, "/api/v1/automation/runs/r1/approve"},
		{"get_automation_catalog", http.MethodGet, "/api/v1/automation/catalog"},
		{"install_flow_template", http.MethodPost, "/api/v1/automation/templates/t1/install"},
		{"list_silences", http.MethodGet, "/api/v1/automation/silences"},
		{"create_silence", http.MethodPost, "/api/v1/automation/silences"},
		{"export_automation", http.MethodGet, "/api/v1/automation/export"},
		{"import_automation", http.MethodPost, "/api/v1/automation/import"},
	} {
		want := rbac.RequiredScopeForRequest(httptest.NewRequest(c.method, c.path, nil))
		if got := rbac.ToolRequiredScope(c.tool); got != want || got == "" {
			t.Errorf("%s : scope %q, route %s %s : %q", c.tool, got, c.method, c.path, want)
		}
	}
}

func TestToolRequiresAdmin(t *testing.T) {
	for _, tool := range []string{
		"list_flows", "list_internal_cas", "get_flow_run", "decide_flow_run", "list_auth_providers",
		"list_security_bans", "get_waf_activity", "list_backups", "list_agents", "get_architecture", "simulate_ephor_config", "get_ephor_references", "suggest_ephor_thresholds",
		"get_portal_config", "push_portal_templates",
	} {
		if !rbac.ToolRequiresAdmin(tool) {
			t.Errorf("%s : route REST adminOnly, l'outil doit l'être aussi", tool)
		}
	}
	for _, tool := range []string{
		"list_proxies", "get_audit_log", "list_alert_channels", "list_ip_profiles", "list_certs",
		"list_domains", "list_logs", "list_declared_nodes", "create_snippet",
	} {
		if rbac.ToolRequiresAdmin(tool) {
			t.Errorf("%s : route REST ouverte aux comptes user, l'outil ne doit pas exiger admin", tool)
		}
	}
}

func TestWriteScopesAreAdminOnly(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, u := range []struct{ id, role string }{{"u", "user"}, {"a", "admin"}, {"s", "superadmin"}} {
		if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?,?,?,?)`,
			u.id, u.id+"@t.local", "x", u.role); err != nil {
			t.Fatal(err)
		}
	}
	// Grant write : ouvre proxies:write / snippets:write, pas les nouveaux scopes d'écriture.
	_, _ = db.Exec(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?,?,?,?,?)`,
		uuid.New().String(), "u", "domain", "*", "write")

	ctx := context.Background()
	for _, scope := range []string{rbac.ScopeAlertsWrite, rbac.ScopeDomainsWrite, rbac.ScopeCertsWrite} {
		if !rbac.IsKnownScope(scope) {
			t.Fatalf("%s absent du catalogue", scope)
		}
		if rbac.UserCanHoldScope(ctx, db, "u", scope) {
			t.Errorf("user ne doit pas détenir %s", scope)
		}
		for _, id := range []string{"a", "s"} {
			if !rbac.UserCanHoldScope(ctx, db, id, scope) {
				t.Errorf("%s doit détenir %s", id, scope)
			}
		}
	}
}

func TestPortalTerminalContentNeedsWriteScope(t *testing.T) {
	scope := func(method, path string) string {
		return rbac.RequiredScopeForRequest(httptest.NewRequest(method, path, nil))
	}
	for _, c := range []struct{ method, path, want string }{
		{http.MethodGet, "/api/v1/portal/recordings?edge=a", rbac.ScopePortalRead},
		{http.MethodGet, "/api/v1/portal/recordings/abc?edge=a", rbac.ScopePortalWrite},
		{http.MethodGet, "/api/v1/portal/sessions?edge=a", rbac.ScopePortalRead},
		{http.MethodGet, "/api/v1/portal/sessions/abc/watch?edge=a", rbac.ScopePortalWrite},
		{http.MethodDelete, "/api/v1/portal/sessions/abc?edge=a", rbac.ScopePortalWrite},
	} {
		if got := scope(c.method, c.path); got != c.want {
			t.Errorf("%s %s: %q, attendu %q", c.method, c.path, got, c.want)
		}
	}
}

// Les fournisseurs DNS portent les identifiants d'API des zones : un PAT sans certs:write ne les modifie pas.
func TestACMEProvidersNeedCertsScope(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{http.MethodGet, "/api/v1/acme/providers", rbac.ScopeCertsRead},
		{http.MethodGet, "/api/v1/acme/provider-types", rbac.ScopeCertsRead},
		{http.MethodPost, "/api/v1/acme/providers", rbac.ScopeCertsWrite},
		{http.MethodPut, "/api/v1/acme/providers/p1", rbac.ScopeCertsWrite},
		{http.MethodDelete, "/api/v1/acme/providers/p1", rbac.ScopeCertsWrite},
	} {
		if got := rbac.RequiredScopeForRequest(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Errorf("%s %s: %q, attendu %q", c.method, c.path, got, c.want)
		}
	}
}
