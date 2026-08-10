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

func TestPortalToolsRegistered(t *testing.T) {
	found := map[string]bool{}
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		found[name] = true
	}
	for _, name := range []string{
		"get_portal_config", "update_portal_config", "push_portal",
		"list_portal_destinations", "invite_portal_user", "list_portal_templates", "push_portal_templates",
	} {
		if !found[name] {
			t.Fatalf("outil manquant: %s", name)
		}
	}
}

func TestPortalGetConfigTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = admindb.SetSetting(db, "portal.config.core-a", `{"enabled":true,"public_host":"access.example","ssh_port":2222}`)

	h := &Handler{DB: db}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	out, err := h.toolGetPortalConfig(r, map[string]any{"core": "core-a"})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("type %T", out)
	}
	if m["public_host"] != "access.example" {
		t.Fatalf("config: %v", out)
	}
}

func TestPortalCreateDestinationTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-portal-dest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &Handler{DB: db}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	created, err := h.toolCreatePortalDestination(r, map[string]any{
		"core_name": "core-a", "name": "bastion", "kind": "ssh",
		"host": "10.0.0.1", "port": float64(22), "tags": []any{"prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := created.(map[string]any)
	if m["name"] != "bastion" || m["id"] == "" {
		t.Fatalf("create: %v", created)
	}
	listed, err := h.toolListPortalDestinations(r, map[string]any{"core": "core-a"})
	if err != nil {
		t.Fatal(err)
	}
	lm := listed.(map[string]any)
	dests, _ := lm["destinations"].([]any)
	if len(dests) != 1 {
		t.Fatalf("list: %v", listed)
	}
}

func TestPortalResourceList(t *testing.T) {
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
		if m["uri"] == "goproxify://portal/templates" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("ressource portal/templates manquante")
	}
}
