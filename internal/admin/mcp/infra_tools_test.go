// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestInfraToolsRegistered(t *testing.T) {
	found := map[string]bool{}
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		found[name] = true
	}
	for _, name := range []string{
		"list_declared_nodes", "get_topology_live", "get_architecture", "create_declared_node", "delete_declared_node",
		"create_bootstrap_ticket", "list_hosts", "create_host_join_ticket", "accept_node", "reject_node",
	} {
		if !found[name] {
			t.Fatalf("outil manquant: %s", name)
		}
	}
}

func TestCreateDeclaredNodeTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-declared.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &Handler{DB: db}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	created, err := h.toolCreateDeclaredNode(r, map[string]any{
		"role": "edge", "name": "edge-main", "region": "eu",
		"config": map[string]any{"ha_group": "g1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := created.(map[string]any)
	if m["name"] != "edge-main" || m["id"] == "" {
		t.Fatalf("create: %v", created)
	}
	listed, err := h.toolListDeclaredNodes(r)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := listed.([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("list: %v", listed)
	}
}

func TestCreateBootstrapTicketTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-boot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &Handler{
		DB: db,
		ResolvePublicURL: func(r *http.Request) string {
			return "https://admin.example"
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	out, err := h.toolCreateBootstrapTicket(r, map[string]any{
		"host_name":     "host-1",
		"edge_endpoint": "http://192.0.2.10:8000",
		"node_names":    []any{"edge-main"},
		"ttl_hours":     float64(12),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["token"] == "" || m["install_cmd"] == "" {
		t.Fatalf("ticket: %v", out)
	}
	if !strings.Contains(m["url"].(string), "https://admin.example/i/") {
		t.Fatalf("url: %v", m["url"])
	}
	if !strings.HasPrefix(m["qr_code"].(string), "data:image/png;base64,") {
		t.Fatalf("qr missing")
	}
}

func TestDeclaredResourceList(t *testing.T) {
	h := &Handler{}
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var resp rpcResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	result, _ := resp.Result.(map[string]any)
	resources, _ := result["resources"].([]any)
	found := false
	for _, r := range resources {
		m, _ := r.(map[string]any)
		if m["uri"] == "goproxify://declared-nodes" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("resource declared-nodes manquante")
	}
}

func TestGetArchitectureToolReadsCurrentAndVersion(t *testing.T) {
	h := &Handler{}
	if _, err := h.toolGetArchitecture(nil); err == nil {
		t.Fatal("sans store, l'outil doit signaler que architecture.json est indisponible")
	}
	store := archstore.New(t.TempDir())
	if err := store.Upsert(archstore.NodeEntry{ID: "a", Role: "edge", Name: "un"}); err != nil {
		t.Fatal(err)
	}
	h.ArchStore = store
	out, err := h.toolGetArchitecture(map[string]any{})
	arch, ok := out.(*archstore.Architecture)
	if err != nil || !ok || len(arch.Nodes) != 1 || arch.Nodes[0].Name != "un" {
		t.Fatalf("architecture courante attendue : %+v err %v", out, err)
	}
	if _, err := h.toolGetArchitecture(map[string]any{"version": "../x"}); err == nil {
		t.Fatal("un nom de version invalide doit être refusé")
	}
}

func TestHostsTools(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-hosts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	if _, err := (&Handler{DB: db}).toolListHosts(r); err == nil {
		t.Fatal("sans gestionnaire d'hôtes, l'outil doit échouer")
	}

	store := archstore.New(t.TempDir())
	for _, n := range []archstore.NodeEntry{
		{ID: "dn_e", Role: "edge", Name: "main-edge", Endpoint: "http://main-edge:8000",
			Config: json.RawMessage(`{"host":"main","reachable_host":"192.168.1.10:8000"}`)},
		{ID: "dn_a", Role: "agent", Name: "nas-agent",
			Config: json.RawMessage(`{"host":"nas","reachable_host":"192.168.1.50","target_edge":"main-edge"}`)},
	} {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{DB: db, Hosts: &api.HostsHandler{
		DB: db, Arch: store, PublicURL: func(*http.Request) string { return "https://admin.example:9443" },
	}}

	listed, err := h.toolListHosts(r)
	if err != nil {
		t.Fatal(err)
	}
	rows := listed.([]api.HostRow)
	if len(rows) != 2 || rows[1].Name != "nas" || rows[1].Status != "pending" {
		t.Fatalf("hôtes = %+v", rows)
	}

	if _, err := h.toolCreateHostJoinTicket(r, map[string]any{}); err == nil {
		t.Fatal("host est requis")
	}
	out, err := h.toolCreateHostJoinTicket(r, map[string]any{"host": "nas"})
	if err != nil {
		t.Fatal(err)
	}
	tk := out.(*api.JoinTicket)
	if tk.Host != "nas" || !strings.HasPrefix(tk.SpecURL, "https://admin.example:9443/api/v1/join/") || tk.Token == "" {
		t.Fatalf("ticket = %+v", tk)
	}
	if _, err := h.toolCreateHostJoinTicket(r, map[string]any{"host": "absent"}); err == nil {
		t.Fatal("un hôte inconnu doit être refusé")
	}
}
