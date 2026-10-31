// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// violate injecte n requêtes hors politique ; served : le backend les sert ; blocked : le contrôle les refuse.
func violate(c *Collector, n int, reason, method, path string, served, blocked bool, ipOf func(i int) string) {
	for i := 0; i < n; i++ {
		status := 404
		if served {
			status = 200
		}
		o := obs("r1", "a.test", req(method, strings.ReplaceAll(path, "{int}", fmt.Sprint(1000+i))), ipOf(i), status, "", true)
		o.Violation, o.Blocked = reason, blocked
		c.Observe(o)
	}
}

func clients(n int) func(int) string {
	return func(i int) string { return fmt.Sprintf("10.1.0.%d", i%n+1) }
}

func suggestion(rep Report, key string) (Suggestion, bool) {
	for _, s := range rep.Suggestions {
		if s.Key == key {
			return s, true
		}
	}
	return Suggestion{}, false
}

func TestServedViolationsBecomeHighConfidenceSuggestionsOverSeveralDays(t *testing.T) {
	c, ck := newTest()
	violate(c, 12, "unknown_path", "GET", "/nouveau/{int}", true, false, clients(6))
	rep, _ := c.Report("r1", ModeLearn)
	if len(rep.Suggestions) != 0 {
		t.Fatalf("un seul jour ne suffit pas : %+v", rep.Suggestions)
	}
	ck.advance(24 * time.Hour)
	violate(c, 12, "unknown_path", "GET", "/nouveau/{int}", true, false, clients(6))
	rep, _ = c.Report("r1", ModeLearn)
	s, ok := suggestion(rep, "unknown_path GET /nouveau/{int}")
	if !ok || s.Confidence != "high" || s.Days != 2 || s.CleanClients < 5 || s.Legit != 24 || len(s.Cautions) != 0 {
		t.Fatalf("suggestion : %+v (%v)", s, ok)
	}
	if sum, _ := c.Summary("r1", ModeLearn); sum.Suggestions != 1 {
		t.Errorf("le résumé doit compter les suggestions : %d", sum.Suggestions)
	}
}

func TestRefusedViolationsNeedMoreEvidenceAndAreLowConfidence(t *testing.T) {
	c, ck := newTest()
	for day := 0; day < 3; day++ {
		violate(c, 8, "unknown_path", "GET", "/rapports/{int}", false, true, clients(7))
		ck.advance(24 * time.Hour)
	}
	rep, _ := c.Report("r1", ModeLearn)
	s, ok := suggestion(rep, "unknown_path GET /rapports/{int}")
	if !ok || s.Confidence != "low" || s.Blocked != 24 || len(s.Cautions) == 0 {
		t.Fatalf("refusées depuis des clients propres : %+v (%v)", s, ok)
	}

	// Deux jours seulement : pas assez pour des requêtes refusées.
	short, ck2 := newTest()
	for day := 0; day < 2; day++ {
		violate(short, 8, "unknown_path", "GET", "/rapports/{int}", false, true, clients(7))
		ck2.advance(24 * time.Hour)
	}
	rep, _ = short.Report("r1", ModeLearn)
	if len(rep.Suggestions) != 0 {
		t.Errorf("deux jours de requêtes refusées : %+v", rep.Suggestions)
	}
}

func TestProbesAndFewClientsAreNeverSuggested(t *testing.T) {
	c, ck := newTest()
	for day := 0; day < 4; day++ {
		violate(c, 30, "unknown_path", "GET", "/wp-login.php", true, false, clients(20))
		violate(c, 30, "unknown_path", "GET", "/.env", false, true, clients(20))
		violate(c, 30, "unknown_path", "GET", "/un-seul-client", true, false, clients(1))
		ck.advance(24 * time.Hour)
	}
	rep, _ := c.Report("r1", ModeLearn)
	if len(rep.Suggestions) != 0 {
		t.Errorf("sondes ou un seul client suggérés : %+v", rep.Suggestions)
	}
	if len(rep.Violations) != 3 {
		t.Errorf("les violations restent visibles dans le rapport : %d", len(rep.Violations))
	}
}

func TestOnlyPathAndMethodViolationsAreSuggested(t *testing.T) {
	c, ck := newTest()
	for day := 0; day < 3; day++ {
		violate(c, 12, "unknown_method", "DELETE", "/api/items/{int}", true, false, clients(6))
		violate(c, 12, "invalid_param", "GET", "/api/items/{int}", true, false, clients(6))
		ck.advance(24 * time.Hour)
	}
	rep, _ := c.Report("r1", ModeLearn)
	if len(rep.Suggestions) != 1 || rep.Suggestions[0].Reason != "unknown_method" || rep.Suggestions[0].Method != "DELETE" {
		t.Fatalf("suggestions : %+v", rep.Suggestions)
	}
	if !strings.Contains(strings.Join(rep.Suggestions[0].Cautions, " "), "méthode DELETE") {
		t.Errorf("mise en garde : %v", rep.Suggestions[0].Cautions)
	}
}

func TestForgetViolationsClearsLocalAndPeerEntries(t *testing.T) {
	a, ck := newTest()
	b, _ := newTest()
	for day := 0; day < 2; day++ {
		violate(a, 12, "unknown_path", "GET", "/nouveau/{int}", true, false, clients(6))
		violate(b, 12, "unknown_path", "GET", "/nouveau/{int}", true, false, clients(6))
		violate(a, 6, "unknown_path", "GET", "/autre", false, true, clients(6))
		ck.advance(24 * time.Hour)
	}
	a.ApplyPeer("b", b.Export())
	key := "unknown_path GET /nouveau/{int}"
	if rep, _ := a.Report("r1", ModeLearn); rep.ViolationTotals[0].Count != 24+24+12 || len(rep.Suggestions) != 1 {
		t.Fatalf("avant : %v %+v", rep.ViolationTotals, rep.Suggestions)
	}
	if n := a.ForgetViolations("r1", []string{key, "unknown_path GET /absente"}); n != 1 {
		t.Errorf("%d entrée(s) effacée(s) localement, attendu 1", n)
	}
	rep, _ := a.Report("r1", ModeLearn)
	if len(rep.Suggestions) != 0 || len(rep.Violations) != 1 || rep.Violations[0].Path != "/autre" {
		t.Errorf("après : %+v", rep.Violations)
	}
	if rep.ViolationTotals[0].Count != 12 || rep.BlockedTotals[0].Count != 12 {
		t.Errorf("totaux après oubli : %v refusées %v", rep.ViolationTotals, rep.BlockedTotals)
	}
	// Le profil exporté n'a plus l'entrée non plus : un pair ne la rendra pas.
	if strings.Contains(string(a.Export().Routes["r1"]), "unknown_path GET /nouveau") {
		t.Error("le profil local garde la violation oubliée")
	}
}

func TestAddToSpecKeepsWhatWasThere(t *testing.T) {
	spec := map[string]any{"openapi": "3.1.0", "paths": map[string]any{
		"/api/users/{users_id}": map[string]any{"get": map[string]any{"parameters": []any{
			map[string]any{"name": "users_id", "in": "path", "required": true, "schema": map[string]any{"type": "integer"}}}}},
	}}
	if ok, err := AddToSpec(spec, "DELETE", "/api/users/{int}"); err != nil || !ok {
		t.Fatalf("méthode ajoutée à un chemin connu : %v %v", ok, err)
	}
	paths := spec["paths"].(map[string]any)
	if len(paths) != 1 {
		t.Fatalf("le chemin existant doit recevoir la méthode, pas un doublon : %v", paths)
	}
	if ok, _ := AddToSpec(spec, "DELETE", "/api/users/{int}"); ok {
		t.Error("une méthode déjà présente ne change rien")
	}
	if ok, err := AddToSpec(spec, "GET", "/nouveau/{int}/detail"); err != nil || !ok {
		t.Fatalf("nouveau chemin : %v %v", ok, err)
	}
	if _, ok := paths["/nouveau/{nouveau_id}/detail"]; !ok {
		t.Errorf("chemins : %v", paths)
	}
	// Un autre type au même niveau élargit le paramètre en texte, partout dans le chemin.
	if _, err := AddToSpec(spec, "PUT", "/api/users/{uuid}"); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(paths["/api/users/{users_id}"])
	if strings.Contains(string(b), `"integer"`) || !strings.Contains(string(b), `"put"`) {
		t.Errorf("paramètre non élargi : %s", b)
	}
	for _, bad := range [][2]string{{"PROPFIND", "/x"}, {"GET", "/a/{…}"}} {
		if _, err := AddToSpec(spec, bad[0], bad[1]); err == nil {
			t.Errorf("%v accepté", bad)
		}
	}
}

func TestParseSpec(t *testing.T) {
	if m, err := ParseSpec(`{"openapi":"3.1.0","paths":{}}`); err != nil || m["openapi"] != "3.1.0" {
		t.Errorf("chaîne JSON : %v %v", m, err)
	}
	if _, err := ParseSpec("openapi: 3.0.3\npaths: {}"); err == nil || !strings.Contains(err.Error(), "YAML") {
		t.Errorf("YAML : %v", err)
	}
	if _, err := ParseSpec(42); err == nil {
		t.Error("type inattendu")
	}
}
