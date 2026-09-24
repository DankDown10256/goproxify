// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func pf(v float64) *float64 { return &v }

func TestComputeNodeLive(t *testing.T) {
	online := nodeLive{Status: "online"}
	cases := []struct {
		name     string
		node     nodeLive
		tc       trafficCounts
		risk     int
		factor   string
		level    string
		lowTraff bool
	}{
		{"calme", online, trafficCounts{total: 600}, 0, "none", "low", false},
		{"trafic faible ignoré", online, trafficCounts{total: 5, blocked: 5, errors: 0}, 0, "none", "low", true},
		{"refus de sécurité", online, trafficCounts{total: 100, blocked: 30}, 60, "blocked", "high", false},
		{"erreurs 5xx", online, trafficCounts{total: 100, errors: 10}, 40, "errors", "medium", false},
		{"saturation cpu", nodeLive{Status: "online", CPUPCT: pf(85)}, trafficCounts{}, 50, "resources", "medium", true},
		{"hors ligne", nodeLive{Status: "offline"}, trafficCounts{}, 100, "offline", "high", true},
		{"plafonné à 100", online, trafficCounts{total: 100, blocked: 100}, 100, "blocked", "high", false},
	}
	for _, c := range cases {
		got := computeNodeLive(c.node, c.tc, time.Minute)
		if got.Risk != c.risk || got.RiskFactor != c.factor || got.RiskLevel != c.level || got.LowTraffic != c.lowTraff {
			t.Errorf("%s: risk=%d factor=%s level=%s low=%v", c.name, got.Risk, got.RiskFactor, got.RiskLevel, got.LowTraffic)
		}
	}
	if got := computeNodeLive(online, trafficCounts{total: 120}, time.Minute); got.RPS != 2 {
		t.Errorf("rps = %v, want 2", got.RPS)
	}
}

func TestNodesLiveEndpoint(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO nodes (id, node_name, role, status, cpu_pct, mem_pct) VALUES ('c1','core-a','core','online',10,20), ('c2','core-b','core','online',10,20)`); err != nil {
		t.Fatal(err)
	}
	ins := func(node string, at time.Time, status int, component string) {
		if _, err := db.Exec(`INSERT INTO logs (ts, component, node_name, domain, method, path, status, ip) VALUES (?, ?, ?, 'a.test', 'GET', '/', ?, '1.2.3.4')`,
			at.UTC().Format(time.RFC3339Nano), component, node, status); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	for i := 0; i < 40; i++ {
		ins("core-a", now.Add(-10*time.Second), 200, "core")
	}
	for i := 0; i < 20; i++ {
		ins("core-a", now.Add(-5*time.Second), 403, "core")
	}
	ins("core-a", now.Add(-10*time.Minute), 500, "core") // hors fenêtre
	ins("core-a", now.Add(-5*time.Second), 500, "admin") // logs de l'Admin lui-même exclus

	h := &NodesHandler{DB: db, Log: slog.Default()}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nodes/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var res topologyLive
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	by := map[string]nodeLive{}
	for _, n := range res.Nodes {
		by[n.NodeName] = n
	}
	a, b := by["core-a"], by["core-b"]
	if a.Requests != 60 || a.RiskFactor != "blocked" || a.Risk != 67 || a.RiskLevel != "high" {
		t.Fatalf("core-a: %+v", a)
	}
	if b.Requests != 0 || b.Risk != 0 || !b.LowTraffic {
		t.Fatalf("core-b: %+v", b)
	}
	if res.WindowSec != 60 {
		t.Fatalf("window: %d", res.WindowSec)
	}
}
