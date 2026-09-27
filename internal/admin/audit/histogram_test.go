// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package audit

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
	l := New(d, 90)
	now := time.Now().UTC()
	ins := func(at time.Time, actor, action, sev string, n int) {
		for i := 0; i < n; i++ {
			if _, err := d.Exec(`INSERT INTO audit_log (component, actor, action, resource, severity, created_at) VALUES ('admin',?,?,'r',?,?)`,
				actor, action, sev, at.Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
		}
	}
	ins(now.Add(-3*time.Hour), "alice", "proxy.update", "info", 4)
	ins(now.Add(-3*time.Hour), "alice", "token.create", "warning", 1)
	ins(now.Add(-1*time.Hour), "bob", "ban.create", "critical", 2)

	pts, err := l.Histogram(SearchParams{From: now.Add(-24 * time.Hour)}, "hour")
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 || pts[0].Total != 5 || pts[0].Warn != 1 || pts[1].Critical != 2 {
		t.Fatalf("tranches inattendues : %+v", pts)
	}
	byActor, _ := l.Histogram(SearchParams{Actor: "bob"}, "day")
	if len(byActor) != 1 || byActor[0].Total != 2 {
		t.Errorf("filtre sur l'acteur : %+v", byActor)
	}
}
