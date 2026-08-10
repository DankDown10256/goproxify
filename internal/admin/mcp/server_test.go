// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func setupMCPDB(t *testing.T) *Handler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Handler{DB: db, Log: slog.Default()}
}

func TestCreateUpdateEnableProxy(t *testing.T) {
	h := setupMCPDB(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	created, err := h.toolCreateProxy(r, map[string]any{
		"host": "app.example.com", "backend": "http://10.0.0.5:3000",
		"tls_enabled": true, "lb": "adaptive",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := created.(map[string]any)
	id, _ := m["id"].(string)
	if id == "" || m["lb"] != "adaptive" {
		t.Fatalf("create: %v", created)
	}

	updated, err := h.toolUpdateProxy(r, map[string]any{
		"id": id, "backend": "http://10.0.0.6:3000", "lb": "round_robin",
	})
	if err != nil {
		t.Fatal(err)
	}
	um := updated.(map[string]any)
	cfg, _ := um["config"].(map[string]any)
	if cfg["lb"] != "round_robin" {
		t.Fatalf("update lb: %v", cfg)
	}

	disabled, err := h.toolSetProxyEnabled(r, map[string]any{"id": id, "enabled": false})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.(map[string]any)["enabled"] != false {
		t.Fatalf("disable: %v", disabled)
	}
}

func TestSecurityBanCRUD(t *testing.T) {
	h := setupMCPDB(t)
	var pushed int
	h.OnBansChange = func() { pushed++ }
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	created, err := h.toolCreateSecurityBan(r, map[string]any{
		"ip": "203.0.113.10", "reason": "mcp-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := created.(map[string]any)
	id, _ := m["id"].(string)
	if id == "" || m["permanent"] != true {
		t.Fatalf("create: %v", created)
	}
	if pushed != 1 {
		t.Fatalf("push=%d", pushed)
	}

	listed, err := h.toolListSecurityBans(r, map[string]any{"active_only": true, "source": "native"})
	if err != nil {
		t.Fatal(err)
	}
	items := listed.([]map[string]any)
	if len(items) != 1 {
		t.Fatalf("list: %v", listed)
	}

	if _, err := h.toolDeleteSecurityBan(r, id); err != nil {
		t.Fatal(err)
	}
	if pushed != 2 {
		t.Fatalf("push after delete=%d", pushed)
	}

	ov, err := h.toolGetSecurityOverview(r)
	if err != nil {
		t.Fatal(err)
	}
	if ov.(map[string]any)["active_bans"].(int) != 0 {
		t.Fatalf("overview: %v", ov)
	}
}

func TestListAgentsApprove(t *testing.T) {
	h := setupMCPDB(t)
	var approved, revoked string
	h.ListAgents = func() []AgentInfo {
		return []AgentInfo{{ID: "ag1", Name: "ag1", Status: "pending"}}
	}
	h.ApproveAgent = func(id string) { approved = id }
	h.RevokeAgent = func(id string) { revoked = id }

	listed, err := h.toolListAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.([]AgentInfo)) != 1 {
		t.Fatalf("list: %v", listed)
	}
	if _, err := h.toolApproveAgent("ag1"); err != nil {
		t.Fatal(err)
	}
	if approved != "ag1" {
		t.Fatalf("approved=%q", approved)
	}
	if _, err := h.toolRevokeAgent("ag1"); err != nil {
		t.Fatal(err)
	}
	if revoked != "ag1" {
		t.Fatalf("revoked=%q", revoked)
	}
}

func TestToolsListIncludesNewTools(t *testing.T) {
	h := setupMCPDB(t)
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck
	want := map[string]bool{
		"update_proxy": true, "set_proxy_enabled": true, "list_agents": true,
		"approve_agent": true, "list_security_bans": true, "get_security_overview": true,
	}
	for _, tool := range resp.Result.Tools {
		delete(want, tool.Name)
	}
	if len(want) > 0 {
		t.Fatalf("missing tools: %v", want)
	}
}
