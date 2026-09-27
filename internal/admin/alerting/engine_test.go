// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestCooldownIsPerNode(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	d.Exec(`INSERT INTO alert_rules (id, name, scope, triggers, channels, cooldown_sec, priority, enabled) VALUES ('r1','SLO','{}','["slo_burn"]','[]',3600,1,1)`)

	e := New(d, slog.Default())
	t.Cleanup(e.Stop)
	fire := func(node string) {
		e.eval(Event{Trigger: TriggerSLOBurn, Severity: SevCritical, NodeName: node, Component: "admin"})
	}
	fire("paris-01")
	fire("paris-01") // dans le délai de rappel : ignorée
	fire("lyon-03")  // autre passerelle : doit passer

	var n int
	d.QueryRow(`SELECT COUNT(*) FROM alert_events`).Scan(&n)
	if n != 2 {
		t.Fatalf("2 alertes attendues (une par passerelle, doublon filtré), got %d", n)
	}
}
