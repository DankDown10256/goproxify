// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

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

func TestSubscribeReceivesEveryEvent(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e := New(d, slog.Default())
	t.Cleanup(e.Stop)
	got := make(chan Event, 2)
	e.Subscribe(func(ev Event) { got <- ev })
	e.Emit(Event{Trigger: TriggerFleetBan, Detail: map[string]any{"ip": "1.2.3.4"}})
	select {
	case ev := <-got:
		if ev.Trigger != TriggerFleetBan || ev.Detail["ip"] != "1.2.3.4" {
			t.Fatalf("événement reçu : %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abonné non appelé")
	}
}

func TestTriggerOutputsOnlyKnownTriggers(t *testing.T) {
	known := map[TriggerType]bool{}
	for _, tr := range AllTriggers {
		known[tr] = true
		if TriggerLabels[tr] == "" {
			t.Errorf("%s sans libellé", tr)
		}
	}
	for tr := range TriggerOutputs {
		if !known[tr] {
			t.Errorf("TriggerOutputs : %s absent d'AllTriggers", tr)
		}
	}
}
