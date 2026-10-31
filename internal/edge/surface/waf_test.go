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

const wafCfg = `{"enabled":true,"mode":"detect","anomaly_threshold":5,"exclude_ids":[920350],"behavior_enabled":true}`

// wafTraffic fait déclencher la règle id par n clients ordinaires, perReq fois chacun, chaque jour pendant days jours, sur /api/search.
func wafTraffic(c *Collector, ck *clock, id, clients, perClient, days int, tier string) {
	wafTrafficAt(c, ck, "/api/search", id, clients, perClient, days, tier)
}

func wafTrafficAt(c *Collector, ck *clock, path string, id, clients, perClient, days int, tier string) {
	for d := 0; d < days; d++ {
		for cl := 0; cl < clients; cl++ {
			for k := 0; k < perClient; k++ {
				o := obs("r1", "a.test", req("GET", path+"?q=l%27arbre"), fmt.Sprintf("10.2.%d.%d", id%200, cl+1), 200, "", false)
				o.WAFHits = []WAFHit{{RuleID: id, Category: "sqli", Message: "injection SQL probable", Target: "args"}}
				o.CleanApartFromWAF = true
				if tier == "blocked" {
					o.Status, o.WAFBlocked = 403, true
				}
				c.Observe(o)
			}
		}
		ck.advance(24 * time.Hour)
	}
}

func wafCur() Current { return Current{Host: "a.test", WAF: json.RawMessage(wafCfg)} }

// wafBlockCur : un WAF qui refuse (en detect, adoucir n'aurait pas de sens : rien n'est refusé).
func wafBlockCur() Current {
	return Current{Host: "a.test", WAF: json.RawMessage(`{"enabled":true,"mode":"block","anomaly_threshold":5,"exclude_ids":[920350],"behavior_enabled":true}`)}
}

// wafProposals rend les propositions de réglage du WAF.
func wafProposals(p Proposals) []Proposal {
	var out []Proposal
	for _, it := range p.Items {
		if it.Setting == SettingWAF {
			out = append(out, it)
		}
	}
	return out
}

func wafSkipped(p Proposals) string {
	for _, s := range p.Skipped {
		if s.Setting == SettingWAF {
			return s.Reason
		}
	}
	return ""
}

func ensureLearned(c *Collector) {
	feed(c, 150, func(i int) Observed { return obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true) })
}

type wafValue struct {
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode"`
	AnomalyThreshold int    `json:"anomaly_threshold"`
	ExcludeIDs       []int  `json:"exclude_ids"`
	Behavior         bool   `json:"behavior_enabled"`
	Exclusions       []struct {
		Paths   []string `json:"paths"`
		RuleIDs []int    `json:"rule_ids"`
		Note    string   `json:"note"`
	} `json:"exclusions"`
}

func decodeWAF(t *testing.T, p Proposal) wafValue {
	t.Helper()
	var v wafValue
	if err := json.Unmarshal(p.Value, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustProposals(t *testing.T, c *Collector, cur Current) Proposals {
	t.Helper()
	p, ok := c.Proposals("r1", cur, nil)
	if !ok {
		t.Fatal("pas de propositions")
	}
	return p
}

func TestProposeWAFExclusionIsScopedToThePathsWhereTheRuleFires(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	wafTraffic(c, ck, 942100, 5, 4, 3, "served")
	p := mustProposals(t, c, wafCur())
	list := wafProposals(p)
	if len(list) != 1 {
		t.Fatalf("%d proposition(s) du WAF, attendu 1 : %v", len(list), p.Skipped)
	}
	it := list[0]
	v := decodeWAF(t, it)
	if len(v.Exclusions) != 1 || strings.Join(v.Exclusions[0].Paths, ",") != "/api/search" || fmt.Sprint(v.Exclusions[0].RuleIDs) != "[942100]" {
		t.Errorf("l'exclusion doit être bornée au chemin observé : %s", it.Value)
	}
	if fmt.Sprint(v.ExcludeIDs) != "[920350]" {
		t.Errorf("exclude_ids ne doit pas grossir (l'exclusion ne vaut pas pour tout le proxy) : %v", v.ExcludeIDs)
	}
	if !v.Enabled || v.Mode != "detect" || v.AnomalyThreshold != 5 || !v.Behavior {
		t.Errorf("les autres réglages sont conservés : %s", it.Value)
	}
	joined := strings.Join(it.Evidence, " ")
	if !strings.Contains(joined, "942100 (sqli)") || !strings.Contains(joined, "GET /api/search") || !strings.Contains(joined, "60 requête(s) servies") || !strings.Contains(joined, "limitée à /api/search") {
		t.Errorf("justification : %s", joined)
	}
	cau := strings.Join(it.Cautions, " | ")
	if !strings.Contains(cau, "ne vaut que sous les chemins") || !strings.Contains(cau, "attaque lente") || !strings.Contains(cau, "authentification, filtre d'IP") {
		t.Errorf("mises en garde : %s", cau)
	}
	if !strings.Contains(it.Command, "goproxify proxy option r1 waf '") || it.Measured {
		t.Errorf("commande ou mesure : %+v", it)
	}
}

func TestProposeWAFPathsAreTrimmedToTheirPrefixAndMerged(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	// /api/items/{int} et /api/items/{int}/notes ont le même préfixe /api/items ; /api/users/{int}/bio donne /api/users.
	for d := 0; d < 3; d++ {
		for _, path := range []string{"/api/items/12", "/api/items/12/notes", "/api/users/7/bio"} {
			wafTrafficAt(c, ck, path, 942100, 4, 3, 1, "served")
			ck.advance(-24 * time.Hour)
		}
		ck.advance(24 * time.Hour)
	}
	list := wafProposals(mustProposals(t, c, wafCur()))
	if len(list) != 1 {
		t.Fatalf("propositions : %d", len(list))
	}
	v := decodeWAF(t, list[0])
	if len(v.Exclusions) != 1 || strings.Join(v.Exclusions[0].Paths, ",") != "/api/items,/api/users" {
		t.Errorf("préfixes attendus /api/items et /api/users : %s", list[0].Value)
	}
}

func TestProposeWAFWithoutPathToScopeAdvisesSofteningInsteadOfExcluding(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	wafTrafficAt(c, ck, "/", 942100, 5, 4, 3, "served") // la racine : une exclusion vaudrait pour tout le proxy
	p := mustProposals(t, c, wafBlockCur())
	list := wafProposals(p)
	if len(list) != 1 {
		t.Fatalf("propositions : %d (%s)", len(list), wafSkipped(p))
	}
	it := list[0]
	v := decodeWAF(t, it)
	if len(v.Exclusions) != 0 || fmt.Sprint(v.ExcludeIDs) != "[920350]" {
		t.Fatalf("aucune exclusion ne doit être proposée quand le chemin ne se borne pas : %s", it.Value)
	}
	if v.AnomalyThreshold != 10 || v.Mode != "block" {
		t.Errorf("seuil d'anomalie conseillé : %s", it.Value)
	}
	cau := strings.Join(it.Cautions, " | ")
	if !strings.Contains(cau, "mode detect") || !strings.Contains(cau, "une attaque qui ne déclenche qu'une règle passe") || !strings.Contains(cau, "tout le proxy") {
		t.Errorf("mises en garde : %s", cau)
	}

	// Un identifiant en premier segment ne se borne pas non plus.
	c2, ck2 := newTest()
	ensureLearned(c2)
	wafTrafficAt(c2, ck2, "/12345/edit", 942100, 5, 4, 3, "served")
	if l := wafProposals(mustProposals(t, c2, wafBlockCur())); len(l) != 1 || len(decodeWAF(t, l[0]).Exclusions) != 0 {
		t.Errorf("identifiant en premier segment : %+v", l)
	}

	// Déjà en mode detect, ou à un seuil de 10 : rien de plus à conseiller.
	for _, w := range []string{`{"enabled":true,"mode":"detect"}`, `{"enabled":true,"mode":"block","anomaly_threshold":10}`} {
		cur := wafCur()
		cur.WAF = json.RawMessage(w)
		p = mustProposals(t, c, cur)
		if len(wafProposals(p)) != 0 || !strings.Contains(wafSkipped(p), "déjà en mode detect") {
			t.Errorf("WAF déjà adouci %s : %v %q", w, wafProposals(p), wafSkipped(p))
		}
	}
}

func TestProposeWAFMixedRulesGiveIndependentProposals(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	for d := 0; d < 3; d++ {
		wafTrafficAt(c, ck, "/api/search", 942100, 5, 4, 1, "served")
		ck.advance(-24 * time.Hour)
		wafTrafficAt(c, ck, "/", 941100, 5, 4, 1, "served")
	}
	list := wafProposals(mustProposals(t, c, wafBlockCur()))
	if len(list) != 2 {
		t.Fatalf("une exclusion bornée et un conseil : %d proposition(s)", len(list))
	}
	var scoped, tuning wafValue
	for _, it := range list {
		v := decodeWAF(t, it)
		if len(v.Exclusions) > 0 {
			scoped = v
		} else {
			tuning = v
		}
	}
	if len(scoped.Exclusions) != 1 || scoped.AnomalyThreshold != 5 {
		t.Errorf("l'exclusion ne doit pas porter le seuil du conseil : %+v", scoped)
	}
	if len(tuning.Exclusions) != 0 || tuning.AnomalyThreshold != 10 {
		t.Errorf("le conseil ne doit pas porter l'exclusion : %+v", tuning)
	}
}

func TestProposeWAFNotesWhenThePathsWereNotAllRetained(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	for d := 0; d < 3; d++ {
		for i := 0; i < maxWAFPaths+4; i++ {
			wafTrafficAt(c, ck, fmt.Sprintf("/zone%d/search", i), 942100, 4, 3, 1, "served")
			ck.advance(-24 * time.Hour)
		}
		ck.advance(24 * time.Hour)
	}
	list := wafProposals(mustProposals(t, c, wafCur()))
	if len(list) != 1 {
		t.Fatalf("propositions : %d", len(list))
	}
	if !strings.Contains(strings.Join(list[0].Cautions, " "), "n'a pas retenu tous les chemins") {
		t.Errorf("mise en garde sur les chemins non retenus : %v", list[0].Cautions)
	}
}

func TestProposeWAFSkipsWeakEvidence(t *testing.T) {
	// Un seul client qui recommence : une attaque lente ressemble à cela.
	c, ck := newTest()
	ensureLearned(c)
	wafTraffic(c, ck, 942100, 1, 40, 3, "served")
	// Trop peu de jours.
	wafTraffic(c, ck, 941100, 5, 4, 1, "served")
	// Des clients distincts qui ne reviennent jamais : une attaque distribuée en passe unique.
	for d := 0; d < 3; d++ {
		for cl := 0; cl < 30; cl++ {
			o := obs("r1", "a.test", req("GET", "/api/search?q=x"), fmt.Sprintf("10.9.%d.%d", d, cl+1), 200, "", false)
			o.WAFHits = []WAFHit{{RuleID: 930100, Category: "lfi", Target: "args"}}
			o.CleanApartFromWAF = true
			c.Observe(o)
		}
		ck.advance(24 * time.Hour)
	}
	p := mustProposals(t, c, wafCur())
	if len(wafProposals(p)) != 0 {
		t.Fatalf("proposition sur une preuve trop faible : %s", wafProposals(p)[0].Value)
	}
	if !strings.Contains(wafSkipped(p), "3 règle(s) se sont déclenchées") {
		t.Errorf("raison : %q", wafSkipped(p))
	}
}

func TestProposeWAFBlockedTierNeedsMoreEvidence(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	wafTraffic(c, ck, 942100, 6, 4, 3, "blocked")
	list := wafProposals(mustProposals(t, c, wafCur()))
	if len(list) != 1 {
		t.Fatalf("propositions : %d", len(list))
	}
	it := list[0]
	if !strings.Contains(strings.Join(it.Evidence, " "), "refusées par le WAF") || !strings.Contains(strings.Join(it.Cautions, " "), "refusées par le WAF") {
		t.Errorf("règle refusée : %v %v", it.Evidence, it.Cautions)
	}

	short, ck2 := newTest()
	ensureLearned(short)
	wafTraffic(short, ck2, 942100, 6, 4, 2, "blocked") // deux jours seulement
	if l := wafProposals(mustProposals(t, short, wafCur())); len(l) != 0 {
		t.Error("deux jours de requêtes refusées ne suffisent pas")
	}
}

func TestProposeWAFRespectsExistingSettings(t *testing.T) {
	c, ck := newTest()
	ensureLearned(c)
	for d := 0; d < 3; d++ {
		wafTrafficAt(c, ck, "/api/search", 942100, 5, 4, 1, "served")
		ck.advance(-24 * time.Hour)
		wafTrafficAt(c, ck, "/api/search", 942101, 5, 4, 1, "served")
	}

	cur := wafCur()
	cur.CustomRuleIDs = []int{942100} // règle de l'administrateur : jamais proposée
	list := wafProposals(mustProposals(t, c, cur))
	if len(list) != 1 {
		t.Fatalf("règle personnalisée : %d proposition(s)", len(list))
	}
	if v := decodeWAF(t, list[0]); len(v.Exclusions) != 1 || fmt.Sprint(v.Exclusions[0].RuleIDs) != "[942101]" {
		t.Errorf("seule 942101 est proposée : %s", list[0].Value)
	}

	// Déjà exclues pour tout le proxy.
	cur = wafCur()
	cur.WAF = json.RawMessage(`{"enabled":true,"exclude_ids":[942100,942101]}`)
	if l := wafProposals(mustProposals(t, c, cur)); len(l) != 0 {
		t.Errorf("règles déjà exclues : %s", l[0].Value)
	}

	// Déjà exclues sous ce chemin, ou sous un chemin plus large.
	cur = wafCur()
	cur.WAF = json.RawMessage(`{"enabled":true,"exclusions":[{"paths":["/api/"],"rule_ids":[942100,942101]}]}`)
	if l := wafProposals(mustProposals(t, c, cur)); len(l) != 0 {
		t.Errorf("règles déjà exclues sous /api/ : %s", l[0].Value)
	}
	// Exclues ailleurs seulement : la proposition reste valable, et garde l'exclusion existante.
	cur.WAF = json.RawMessage(`{"enabled":true,"exclusions":[{"paths":["/wp-admin/"],"rule_ids":[942100]}]}`)
	l := wafProposals(mustProposals(t, c, cur))
	if len(l) != 1 || len(decodeWAF(t, l[0]).Exclusions) != 2 {
		t.Errorf("l'exclusion existante est conservée et la nouvelle ajoutée : %v", l)
	}

	for name, cur := range map[string]Current{
		"snippet":   {WAFFromSnippet: true},
		"sans waf":  {},
		"désactivé": {WAF: json.RawMessage(`{"enabled":false}`)},
	} {
		if wafSkipped(mustProposals(t, c, cur)) == "" {
			t.Errorf("%s : aucune raison donnée", name)
		}
	}
}

func TestScopePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"GET /api/search":           "/api/search",
		"POST /api/users/{int}/bio": "/api/users",
		"GET /wp-admin/post.php":    "/wp-admin/post.php",
		"GET /":                     "",
		"GET /{int}/edit":           "",
		"GET /{uuid}":               "",
		"GET /a/{token}/b/{int}":    "/a",
	} {
		got, ok := scopePrefix(in)
		if got != want || ok != (want != "") {
			t.Errorf("scopePrefix(%q) = %q, %v ; attendu %q", in, got, ok, want)
		}
	}
}

func TestWAFRulesInReportAndMergeAcrossPeers(t *testing.T) {
	a, cka := newTest()
	b, ckb := newTest()
	ensureLearned(a)
	wafTraffic(a, cka, 942100, 3, 4, 2, "served")
	wafTraffic(b, ckb, 942100, 3, 4, 2, "served")
	a.ApplyPeer("b", b.Export())
	for i := 0; i < 3; i++ { // un échange répété ne compte pas deux fois
		a.ApplyPeer("b", b.Export())
	}
	rep, _ := a.Report("r1", ModeLearn)
	if len(rep.WAF) != 1 {
		t.Fatalf("règles : %+v", rep.WAF)
	}
	w := rep.WAF[0]
	if w.ID != 942100 || w.Hits != 48 || w.Served != 48 || w.Days != 2 || w.Clients != 3 || w.Category != "sqli" || len(w.Paths) != 1 {
		t.Errorf("règle : %+v", w)
	}
	raw, _ := json.Marshal(a.Snapshot())
	if strings.Contains(string(raw), "10.2.") || strings.Contains(string(raw), "arbre") {
		t.Error("une IP ou une valeur est écrite dans l'état")
	}
}

func TestWAFRulesAreBounded(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < maxWAFRules+20; i++ {
		o := obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", false)
		o.WAFHits = []WAFHit{{RuleID: 900000 + i, Category: "x", Target: "args"}}
		c.Observe(o)
	}
	rep, _ := c.Report("r1", ModeLearn)
	if rep.WAFOverflow != 20 {
		t.Errorf("débordement %d, attendu 20", rep.WAFOverflow)
	}
	c.mu.RLock()
	n := len(c.routes["r1"].p.WAF)
	c.mu.RUnlock()
	if n != maxWAFRules {
		t.Errorf("%d règles retenues, plafond %d", n, maxWAFRules)
	}
}
