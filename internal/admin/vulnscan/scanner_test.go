// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
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

	_, err = db.Exec(
		`INSERT INTO proxies (id, name, config, enabled) VALUES
		 (?, ?, ?, 1),
		 (?, ?, ?, 1),
		 (?, ?, ?, 0),
		 (?, ?, ?, 1)`,
		"p1", "app",
		`{"host":"app.example.com","type":"http","backends":[{"url":"http://10.0.0.5:3000","weight":1},{"url":"http://10.0.0.6:3000"}]}`,
		"p2", "agent",
		`{"host":"agent.example.com","type":"http","backends":["http://10.0.0.7:80"]}`,
		"p3", "disabled",
		`{"host":"off.example.com","type":"http","backends":[{"url":"http://10.0.0.8:80"}]}`,
		"p4", "tcp",
		`{"host":"redis","type":"tcp","listen_port":6379,"backends":[{"url":"10.0.0.9:6379"}]}`,
	)
	if err != nil {
		t.Fatal(err)
	}

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
