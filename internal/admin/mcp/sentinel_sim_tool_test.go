// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

func TestSimulateSentinelTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-sim.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	ins := func(at time.Time, ip, path string, status int, component string) {
		_, err := db.Exec(`INSERT INTO logs (ts, component, domain, method, path, status, ip) VALUES (?, ?, 'a.test', 'GET', ?, ?, ?)`,
			at.Format(time.RFC3339Nano), component, path, status, ip)
		if err != nil {
			t.Fatal(err)
		}
	}
	ins(now.Add(-10*time.Minute), "9.9.9.9", "/wp-admin/login", 200, "edge")
	ins(now.Add(-9*time.Minute), "9.9.9.9", "/home", 200, "edge")
	ins(now.Add(-8*time.Minute), "8.8.8.8", "/home", 200, "edge")
	ins(now.Add(-7*time.Minute), "[pseudonymisé]", "/wp-admin", 200, "edge")
	ins(now.Add(-6*time.Minute), "7.7.7.7", "/wp-admin", 200, "admin")
	ins(now.Add(-3*time.Hour), "6.6.6.6", "/wp-admin", 200, "edge")

	h := &Handler{DB: db}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	out, err := h.toolSimulateSentinel(r, map[string]any{
		"config": map[string]any{"custom_lists": map[string]any{"paths": []any{"/wp-admin"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["events_replayed"] != 3 || m["skipped_unattributable_ip"] != 1 {
		t.Fatalf("events=%v skipped=%v", m["events_replayed"], m["skipped_unattributable_ip"])
	}
	cand := m["candidate"].(threat.SimReport)
	if cand.Blocked != 2 || cand.LegitBlocked != 2 || cand.BlockedIPs != 1 {
		t.Fatalf("candidate: %+v", cand)
	}
	if base := m["current"].(threat.SimReport); base.Blocked != 0 {
		t.Fatalf("baseline should block nothing: %+v", base)
	}
	if d := m["delta"].(map[string]int); d["blocked"] != 2 || d["bans"] != 1 {
		t.Fatalf("delta: %v", d)
	}
}

func TestSimulateSentinelToolRequiresConfig(t *testing.T) {
	h := &Handler{}
	if _, err := h.toolSimulateSentinel(httptest.NewRequest(http.MethodPost, "/mcp", nil), map[string]any{}); err == nil {
		t.Fatal("config manquant doit échouer")
	}
}
