// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
)

func TestProgressPct(t *testing.T) {
	cases := []struct{ done, total, want int }{
		{0, 0, 100},
		{0, 4, 0},
		{1, 4, 25},
		{4, 4, 100},
		{5, 4, 100},
	}
	for _, c := range cases {
		if got := progressPct(c.done, c.total); got != c.want {
			t.Fatalf("progressPct(%d,%d)=%d want %d", c.done, c.total, got, c.want)
		}
	}
}

func TestLoadBackends_ReadsBackendsArray(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Proxies servis par un faux passerelle.
	proxies := []*proxystore.Envelope{
		{ID: "p1", Host: "app.example.com", Enabled: true, Status: proxystore.StatusProduction,
			Config: json.RawMessage(`{"host":"app.example.com","type":"http","backends":[{"url":"http://10.0.0.5:3000","weight":1},{"url":"http://10.0.0.6:3000"}]}`)},
		{ID: "p2", Host: "agent.example.com", Enabled: true, Status: proxystore.StatusProduction,
			Config: json.RawMessage(`{"host":"agent.example.com","type":"http","backends":["http://10.0.0.7:80"]}`)},
		{ID: "p3", Host: "off.example.com", Enabled: false, Status: proxystore.StatusProduction,
			Config: json.RawMessage(`{"host":"off.example.com","type":"http","backends":[{"url":"http://10.0.0.8:80"}]}`)},
		{ID: "p4", Host: "redis", Enabled: true, Status: proxystore.StatusProduction,
			Config: json.RawMessage(`{"host":"redis","type":"tcp","listen_port":6379,"backends":[{"url":"10.0.0.9:6379"}]}`)},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"production": proxies})
	}))
	t.Cleanup(srv.Close)
	_, _ = db.Exec(`INSERT INTO tokens (id, node_name, role, token, node_endpoint, revoked)
		VALUES ('tok-vs','edge-vs','edge','gpx_edge_vstesttoken',?,0)`, srv.URL)

	s := New(db, slog.Default(), "")
	got := s.loadBackends()
	want := []string{
		"http://10.0.0.5:3000",
		"http://10.0.0.6:3000",
		"http://10.0.0.7:80",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("loadBackends() = %v, want %v", got, want)
	}
}
