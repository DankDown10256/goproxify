// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestFacets(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := New(d)
	now := time.Now().UTC().Format(time.RFC3339)
	ins := func(level, comp, node string, status, n int) {
		for i := 0; i < n; i++ {
			d.Exec(`INSERT INTO logs (ts, level, component, node_name, status, message) VALUES (?,?,?,?,?,?)`, now, level, comp, node, status, "m")
		}
	}
	ins("info", "edge", "paris-01", 200, 5)
	ins("warn", "edge", "paris-01", 200, 2)
	ins("error", "admin", "", 0, 3)

	facets, err := s.Facets(SearchParams{}, []string{"level", "component", "node_name", "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if len(facets["level"]) != 3 {
		t.Fatalf("3 niveaux attendus : %+v", facets["level"])
	}
	if facets["level"][0].Value != "info" || facets["level"][0].Count != 5 {
		t.Errorf("niveau le plus fréquent attendu 'info':5, got %+v", facets["level"][0])
	}
	if len(facets["node_name"]) != 1 || facets["node_name"][0].Value != "paris-01" {
		t.Errorf("node_name (vides exclus) : %+v", facets["node_name"])
	}
	if _, ok := facets["unknown"]; ok {
		t.Error("un champ inconnu ne doit pas apparaître")
	}

	scoped, _ := s.Facets(SearchParams{Level: "warn"}, []string{"component"})
	if len(scoped["component"]) != 1 || scoped["component"][0].Count != 2 {
		t.Errorf("facettes filtrées : %+v", scoped["component"])
	}
}
