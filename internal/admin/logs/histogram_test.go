// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestHistogram(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := New(d)
	now := time.Now().UTC()
	ins := func(at time.Time, level string, status, n int) {
		for i := 0; i < n; i++ {
			d.Exec(`INSERT INTO logs (ts, level, component, status, message) VALUES (?,?,?,?,?)`, at.Format(time.RFC3339), level, "admin", status, "m")
		}
	}
	ins(now.Add(-3*time.Hour), "info", 0, 5)
	ins(now.Add(-3*time.Hour), "warn", 0, 2)
	ins(now.Add(-1*time.Hour), "error", 0, 3)
	ins(now.Add(-1*time.Hour), "info", 200, 4) // accès HTTP : hors logs système

	pts, err := s.Histogram(SearchParams{Kind: "system"}, "hour")
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 {
		t.Fatalf("2 tranches attendues, got %+v", pts)
	}
	if pts[0].Total != 7 || pts[0].Warn != 2 || pts[0].Error != 0 {
		t.Errorf("première tranche : %+v", pts[0])
	}
	if pts[1].Total != 3 || pts[1].Error != 3 {
		t.Errorf("seconde tranche : %+v", pts[1])
	}
	onlyErr, _ := s.Histogram(SearchParams{Kind: "system", Level: "error"}, "day")
	if len(onlyErr) != 1 || onlyErr[0].Total != 3 {
		t.Errorf("filtre de niveau : %+v", onlyErr)
	}
}
