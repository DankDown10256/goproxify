// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestSLOEvents(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	at := time.Now().UTC().Add(-20 * time.Minute).Format(time.RFC3339)
	ins := func(node string, status, n int) {
		for i := 0; i < n; i++ {
			d.Exec(`INSERT INTO logs (ts, domain, node_name, ip, status) VALUES (?,?,?,?,?)`, at, "a.fr", node, "1.1.1.1", status)
		}
	}
	ins("paris-01", 200, 400)
	ins("lyon-03", 200, 80)
	ins("lyon-03", 502, 20) // 20 % de 5xx : budget épuisé

	m := New(d, slog.Default(), nil, DefaultConfig())
	evs := m.sloEvents(context.Background())
	byNode := map[string]alerting.Event{}
	for _, e := range evs {
		byNode[e.NodeName] = e
	}
	if e, ok := byNode["lyon-03"]; !ok || e.Severity != alerting.SevCritical || e.Trigger != alerting.TriggerSLOBurn {
		t.Fatalf("alerte critique attendue pour lyon-03 : %+v", evs)
	}
	if _, ok := byNode["paris-01"]; ok {
		t.Errorf("paris-01 est sain, aucune alerte attendue : %+v", evs)
	}
	if _, ok := byNode[""]; !ok {
		t.Errorf("l'SLO de la flotte (4 %% de 5xx sur 500) doit aussi alerter : %+v", evs)
	}

	off := New(d, slog.Default(), nil, Config{})
	if len(off.sloEvents(context.Background())) != 0 {
		t.Error("SLOTarget = 0 doit désactiver l'alerte")
	}
}
