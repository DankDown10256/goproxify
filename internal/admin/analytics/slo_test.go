// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestGetSLO(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	now := time.Now().UTC()
	ins := func(at time.Time, status, n int) {
		for i := 0; i < n; i++ {
			d.Exec(`INSERT INTO logs (ts, domain, ip, status) VALUES (?,?,?,?)`, at.Format(time.RFC3339), "a.fr", "1.1.1.1", status)
		}
	}
	// 10 jours sains, puis la dernière heure à 5 % d'erreurs 5xx.
	ins(now.AddDate(0, 0, -10), 200, 1000)
	ins(now.Add(-30*time.Minute), 200, 95)
	ins(now.Add(-30*time.Minute), 502, 5)

	s := GetSLO(context.Background(), d, Params{}, 99.9, 30)
	if s.Requests != 1100 || s.Errors != 5 {
		t.Fatalf("volumes inattendus : %+v", s)
	}
	if s.Availability < 99.4 || s.Availability > 99.6 {
		t.Errorf("disponibilité inattendue : %v", s.Availability)
	}
	// budget = 1,1 erreur tolérée, 5 consommées : épuisé.
	if s.State != "exhausted" || s.BudgetLeft != 0 {
		t.Errorf("budget épuisé attendu : %+v", s)
	}
	if s.Burn1h < 40 {
		t.Errorf("burn 1h attendu ≈ 50, got %v", s.Burn1h)
	}

	calm := GetSLO(context.Background(), d, Params{Proxy: "inconnu.fr"}, 99.9, 30)
	if calm.State != "ok" || calm.Availability != 100 {
		t.Errorf("sans trafic : %+v", calm)
	}
}

func TestSLOTargetSetting(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()

	if got := LoadSLOTarget(ctx, d); got != DefaultSLOTarget {
		t.Fatalf("défaut attendu %v, got %v", DefaultSLOTarget, got)
	}
	if err := SaveSLOTarget(ctx, d, 99.5); err != nil {
		t.Fatal(err)
	}
	if err := SaveSLOTarget(ctx, d, 99.95); err != nil { // remplace la valeur précédente
		t.Fatal(err)
	}
	if got := LoadSLOTarget(ctx, d); got != 99.95 {
		t.Fatalf("objectif enregistré attendu 99.95, got %v", got)
	}
	if s := GetSLO(ctx, d, Params{}, 0, 30); s.Target != 99.95 {
		t.Errorf("GetSLO sans objectif doit lire le réglage : %+v", s)
	}
	if s := GetSLO(ctx, d, Params{}, 99, 30); s.Target != 99 {
		t.Errorf("un objectif explicite prime : %+v", s)
	}
	for _, v := range []float64{0, 50, 100, 120} {
		if ValidSLOTarget(v) {
			t.Errorf("%v ne doit pas être un objectif valide", v)
		}
	}
}

func TestSLOTargetPerNode(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()

	if err := SaveSLOTarget(ctx, d, 99, ""); err != nil { // objectif global
		t.Fatal(err)
	}
	if got := LoadSLOTarget(ctx, d, "paris-01"); got != 99 {
		t.Fatalf("sans override, la passerelle doit lire le global (99), got %v", got)
	}
	if HasSLOTargetOverride(ctx, d, "paris-01") {
		t.Error("aucun override attendu avant SaveSLOTarget avec un nœud")
	}

	if err := SaveSLOTarget(ctx, d, 99.99, "paris-01"); err != nil {
		t.Fatal(err)
	}
	if got := LoadSLOTarget(ctx, d, "paris-01"); got != 99.99 {
		t.Fatalf("override attendu 99.99 pour paris-01, got %v", got)
	}
	if got := LoadSLOTarget(ctx, d, "lyon-03"); got != 99 {
		t.Fatalf("lyon-03 sans override doit rester au global (99), got %v", got)
	}
	if got := LoadSLOTarget(ctx, d); got != 99 {
		t.Fatalf("l'objectif global ne doit pas être affecté par l'override de paris-01, got %v", got)
	}
	if !HasSLOTargetOverride(ctx, d, "paris-01") {
		t.Error("override attendu pour paris-01")
	}

	if s := GetSLO(ctx, d, Params{NodeName: "paris-01"}, 0, 30); s.Target != 99.99 {
		t.Errorf("GetSLO doit résoudre l'objectif par passerelle : %+v", s)
	}

	if err := ClearSLOTarget(ctx, d, "paris-01"); err != nil {
		t.Fatal(err)
	}
	if got := LoadSLOTarget(ctx, d, "paris-01"); got != 99 {
		t.Fatalf("après ClearSLOTarget, retour au global (99) attendu, got %v", got)
	}
}
