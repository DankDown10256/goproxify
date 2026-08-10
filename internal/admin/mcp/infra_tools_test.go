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

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestInfraToolsRegistered(t *testing.T) {
	found := map[string]bool{}
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		found[name] = true
	}
	for _, name := range []string{
		"list_declared_nodes", "create_declared_node", "delete_declared_node",
		"create_bootstrap_ticket", "accept_node", "reject_node",
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
		"role": "core", "name": "core-edge", "region": "eu",
		"config": map[string]any{"ha_group": "g1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := created.(map[string]any)
	if m["name"] != "core-edge" || m["id"] == "" {
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
		"host_name":     "edge-1",
		"core_endpoint": "http://192.0.2.10:8000",
		"node_names":    []any{"core-edge"},
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
