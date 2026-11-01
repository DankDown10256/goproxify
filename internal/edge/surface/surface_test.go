// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest() (*Collector, *clock) {
	ck := &clock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	return NewCollector(Options{Now: ck.now}), ck
}

func req(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.ContentLength = -1
	return r
}

func find(t *testing.T, rep Report, path string) TemplateInfo {
	t.Helper()
	for _, ti := range rep.Templates {
		if ti.Path == path {
			return ti
		}
	}
	var all []string
	for _, ti := range rep.Templates {
		all = append(all, ti.Path)
	}
	t.Fatalf("gabarit %q absent, présents : %v", path, all)
	return TemplateInfo{}
}

func TestTemplatesCollapseIdentifiers(t *testing.T) {
	c, _ := newTest()
	paths := []string{
		"/api/users/12", "/api/users/345", "/api/users/6/orders/9",
		"/api/users/0b0c1d2e-3f40-4152-8364-758697a8b9c0", "/api/day/2026-09-30", "/files/" + strings.Repeat("z", 40),
	}
	for _, p := range paths {
		c.Observe(obs("r1", "app.test", req("GET", p), "10.0.0.1", 200, "application/json", true))
	}
	rep, ok := c.Report("r1", ModeLearn)
	if !ok {
		t.Fatal("pas de rapport")
	}
	if got := find(t, rep, "/api/users/{int}").Requests; got != 2 {
		t.Errorf("/api/users/{int} : %d requêtes, attendu 2", got)
	}
	find(t, rep, "/api/users/{int}/orders/{int}")
	find(t, rep, "/api/users/{uuid}")
	find(t, rep, "/api/day/{date}")
	find(t, rep, "/files/{token}")
}

func TestLiteralSegmentsCollapseAboveLimit(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < maxLiteralChildren+10; i++ {
		c.Observe(obs("r1", "blog.test", req("GET", fmt.Sprintf("/posts/article-%d", i)), "10.0.0.1", 200, "text/html", true))
	}
	c.Observe(obs("r1", "blog.test", req("GET", "/about"), "10.0.0.1", 200, "text/html", true))
	rep, _ := c.Report("r1", ModeLearn)
	post := find(t, rep, "/posts/{var}")
	if post.Requests != int64(maxLiteralChildren+10) {
		t.Errorf("{var} a %d requêtes, attendu %d : la fusion a perdu des requêtes", post.Requests, maxLiteralChildren+10)
	}
	find(t, rep, "/about")
	if rep.TemplateCount > 3 {
		t.Errorf("%d gabarits : les articles n'ont pas été regroupés", rep.TemplateCount)
	}
}

func TestOnlyCleanSuccessfulRequestsTeach(t *testing.T) {
	c, _ := newTest()
	c.Observe(obs("r1", "a.test", req("GET", "/ok"), "10.0.0.1", 200, "", true))
	c.Observe(obs("r1", "a.test", req("GET", "/login"), "10.0.0.1", 401, "", true))
	c.Observe(obs("r1", "a.test", req("GET", "/.env"), "10.0.0.2", 404, "", true))
	c.Observe(obs("r1", "a.test", req("GET", "/wp-admin"), "10.0.0.2", 405, "", true))
	c.Observe(obs("r1", "a.test", req("GET", "/etc/passwd"), "10.0.0.3", 200, "", false))
	rep, _ := c.Report("r1", ModeLearn)
	if rep.Requests != 5 || rep.Learned != 2 || rep.Excluded != 1 {
		t.Fatalf("requêtes %d, apprises %d, exclues %d ; attendu 5, 2, 1", rep.Requests, rep.Learned, rep.Excluded)
	}
	find(t, rep, "/ok")
	find(t, rep, "/login")
	for _, ti := range rep.Templates {
		if ti.Path == "/.env" || ti.Path == "/wp-admin" || ti.Path == "/etc/passwd" {
			t.Errorf("le chemin %q ne devait pas entrer dans le profil", ti.Path)
		}
	}
	var failed int64
	for _, f := range rep.Failed {
		failed += f.Count
	}
	if failed != 2 {
		t.Errorf("%d requêtes en échec comptées, attendu 2", failed)
	}
}

func TestQueryParamsKeepNamesNotValues(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < 25; i++ {
		c.Observe(obs("r1", "a.test", req("GET", fmt.Sprintf("/search?q=secret-%d&page=%d&sort=asc", i, i%3)), "10.0.0.1", 200, "", true))
	}
	rep, _ := c.Report("r1", ModeLearn)
	ti := find(t, rep, "/search")
	params := map[string]ParamInfo{}
	for _, p := range ti.Params {
		params[p.Name] = p
	}
	if len(params) != 3 {
		t.Fatalf("paramètres %v", params)
	}
	if !params["sort"].Enum || !params["page"].Enum || params["q"].Enum {
		t.Errorf("énumérations : sort=%v page=%v q=%v, attendu true true false", params["sort"].Enum, params["page"].Enum, params["q"].Enum)
	}
	if params["page"].Kinds[0] != "entier" {
		t.Errorf("types de page : %v", params["page"].Kinds)
	}
	raw, _ := json.Marshal(c.Snapshot())
	if strings.Contains(string(raw), "secret-") {
		t.Error("une valeur de paramètre est écrite dans l'état sauvegardé")
	}
}

func TestStateHasNoIPAndSurvivesRestart(t *testing.T) {
	c, ck := newTest()
	for i := 0; i < 50; i++ {
		c.Observe(obs("r1", "a.test", req("POST", "/api/items/"+fmt.Sprint(i)), fmt.Sprintf("203.0.113.%d", i), 201, "application/json", true))
	}
	ck.advance(time.Hour)
	raw, err := json.Marshal(c.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "203.0.113") {
		t.Fatal("une IP est écrite dans l'état sauvegardé")
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	c2 := NewCollector(Options{Now: ck.now})
	c2.Restore(st)
	a, _ := c.Report("r1", ModeLearn)
	b, ok := c2.Report("r1", ModeLearn)
	if !ok || a.Learned != b.Learned || a.Clients != b.Clients || len(a.Templates) != len(b.Templates) {
		t.Fatalf("avant %+v, après redémarrage %+v", a.Convergence, b.Convergence)
	}
	if b.Clients < 45 || b.Clients > 55 {
		t.Errorf("clients distincts estimés à %d pour 50", b.Clients)
	}
}

func TestPeerMergeIsIdempotent(t *testing.T) {
	a, _ := newTest()
	b, _ := newTest()
	for i := 0; i < 10; i++ {
		a.Observe(obs("r1", "a.test", req("GET", "/api/a"), fmt.Sprintf("10.0.0.%d", i), 200, "", true))
		b.Observe(obs("r1", "a.test", req("GET", "/api/b"), fmt.Sprintf("10.0.1.%d", i), 200, "", true))
		b.Observe(obs("r1", "a.test", req("GET", "/api/a"), fmt.Sprintf("10.0.0.%d", i), 200, "", true))
	}
	for n := 0; n < 3; n++ {
		a.ApplyPeer("b", b.Export())
	}
	rep, _ := a.Report("r1", ModeLearn)
	if rep.Members != 2 || rep.Learned != 30 {
		t.Fatalf("membres %d, requêtes apprises %d ; attendu 2 et 30 (un échange répété ne doit pas compter deux fois)", rep.Members, rep.Learned)
	}
	if got := find(t, rep, "/api/a").Clients; got < 9 || got > 11 {
		t.Errorf("/api/a : %d clients, attendu 10 (mêmes IP chez les deux membres)", got)
	}
	find(t, rep, "/api/b")
	if got := a.Export().Routes["r1"]; strings.Contains(string(got), "/api/b") {
		t.Error("l'export contient le profil d'un pair : il serait renvoyé en écho")
	}
	a.RetainPeers(nil)
	if rep, _ = a.Report("r1", ModeLearn); rep.Members != 1 || rep.Learned != 10 {
		t.Errorf("après le départ du pair : %d membres, %d requêtes", rep.Members, rep.Learned)
	}
}

func TestConvergence(t *testing.T) {
	c, ck := newTest()
	drive := func() {
		for i := 0; i < 400; i++ {
			c.Observe(obs("r1", "a.test", req("GET", "/api/ping"), fmt.Sprintf("10.0.0.%d", i%20), 200, "", true))
		}
	}
	drive()
	rep, _ := c.Report("r1", ModeLearn)
	if rep.Convergence.Converged || len(rep.Convergence.Reasons) == 0 {
		t.Fatalf("un profil de quelques secondes ne doit pas être convergé : %+v", rep.Convergence)
	}
	for day := 0; day < 8; day++ {
		ck.advance(24 * time.Hour)
		drive()
	}
	if rep, _ = c.Report("r1", ModeLearn); !rep.Convergence.Converged {
		t.Fatalf("8 jours, 3 600 requêtes, aucun nouveau gabarit : attendu convergé, raisons %v", rep.Convergence.Reasons)
	}
	c.Observe(obs("r1", "a.test", req("GET", "/api/new"), "10.0.0.1", 200, "", true))
	if rep, _ = c.Report("r1", ModeLearn); rep.Convergence.Converged || rep.Convergence.NewTemplates != 1 {
		t.Errorf("un nouveau gabarit doit rouvrir l'apprentissage : %+v", rep.Convergence)
	}
}

func TestNodeBudgetIsBounded(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < maxNodes*3; i++ {
		c.Observe(obs("r1", "a.test", req("GET", fmt.Sprintf("/a%d/b%d/c%d", i%50, i%47, i%43)), "10.0.0.1", 200, "", true))
	}
	rep, _ := c.Report("r1", ModeLearn)
	if rep.Overflow == 0 || rep.Convergence.Overflow == false || rep.Convergence.Converged {
		t.Errorf("le débordement n'est pas signalé : %+v", rep.Convergence)
	}
	c.mu.RLock()
	nodes := c.routes["r1"].p.Nodes
	c.mu.RUnlock()
	if nodes > maxNodes {
		t.Errorf("%d nœuds, plafond %d", nodes, maxNodes)
	}
}

func TestLowSupportAndBody(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < 100; i++ {
		r := req("POST", "/upload")
		r.ContentLength = int64(100 + i*10)
		r.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
		c.Observe(obs("r1", "a.test", r, "10.0.0.1", 200, "application/json", true))
	}
	rep, _ := c.Report("r1", ModeLearn)
	ti := find(t, rep, "/upload")
	if !ti.LowSupport {
		t.Error("un seul client, un seul jour : le gabarit doit être à faible soutien")
	}
	if len(ti.RequestMedia) != 1 || ti.RequestMedia[0].Name != "application/json" {
		t.Errorf("types de requête : %v", ti.RequestMedia)
	}
	if ti.BodyMax != 1090 || ti.BodyP99 < 1000 || ti.BodyP99 > 1090 {
		t.Errorf("corps : max %d, p99 %d", ti.BodyMax, ti.BodyP99)
	}
}

func TestValidateMode(t *testing.T) {
	for _, m := range []string{"", "off", "learn", "LEARN"} {
		if err := ValidateMode(m); err != nil {
			t.Errorf("%q refusé : %v", m, err)
		}
	}
	for _, m := range []string{"detect", "enforce", "block", "x"} {
		if ValidateMode(m) == nil {
			t.Errorf("%q accepté", m)
		}
	}
}

func TestForgetAndReset(t *testing.T) {
	c, _ := newTest()
	c.Observe(obs("keep", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true))
	c.Observe(obs("gone", "b.test", req("GET", "/"), "10.0.0.1", 200, "", true))
	c.Forget(func(id string) bool { return id == "keep" })
	if _, ok := c.Report("gone", ModeLearn); ok {
		t.Error("le profil d'un proxy supprimé est resté")
	}
	if !c.Reset("keep") || c.Reset("keep") {
		t.Error("Reset doit rendre vrai une fois puis faux")
	}
}

func BenchmarkObserve(b *testing.B) {
	c, _ := newTest()
	r := req("GET", "/api/users/42/orders?page=2&sort=asc")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "Bearer x")
	r.Header.Set("User-Agent", "bench")
	for i := 0; i < 1000; i++ {
		c.Observe(obs("r1", "a.test", r, "10.0.0.1", 200, "application/json", true))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Observe(obs("r1", "a.test", r, "10.0.0.1", 200, "application/json", true))
	}
}

func obs(route, host string, r *http.Request, ip string, status int, respType string, clean bool) Observed {
	return Observed{Route: route, Host: host, Request: r, Path: r.URL.Path, RawQuery: r.URL.RawQuery, IP: ip, Status: status, ResponseType: respType, Clean: clean}
}

func TestConcurrentUse(t *testing.T) {
	c, _ := newTest()
	peer, _ := newTest()
	for i := 0; i < 50; i++ {
		peer.Observe(obs("r1", "a.test", req("GET", fmt.Sprintf("/p/%d", i%7)), fmt.Sprintf("10.9.0.%d", i), 200, "", true))
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	run := func(fn func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
					fn(i)
				}
			}
		}()
	}
	for w := 0; w < 4; w++ {
		w := w
		run(func(i int) {
			c.Observe(obs("r1", "a.test", req("POST", fmt.Sprintf("/api/%d/items?page=%d", i%90, i%5)), fmt.Sprintf("10.%d.0.%d", w, i%250), 200, "application/json", i%9 != 0))
		})
	}
	run(func(int) { c.Report("r1", ModeLearn) })
	run(func(int) { c.Summary("r1", ModeLearn) })
	run(func(int) { _ = c.Export() })
	run(func(int) { _ = c.Snapshot() })
	run(func(int) { c.ApplyPeer("peer", peer.Export()) })
	run(func(i int) {
		if i%50 == 0 {
			c.Reset("r1")
		}
	})
	time.Sleep(300 * time.Millisecond)
	close(done)
	wg.Wait()
}

func TestKnowsWhatTheLegitTrafficUses(t *testing.T) {
	c, _ := newTest()
	for _, p := range []string{"/api/users/12", "/api/users/345", "/.well-known/security.txt"} {
		c.Observe(obs("r1", "app.test", req("GET", p), "10.0.0.1", 200, "application/json", true))
	}
	for path, want := range map[string]bool{
		"/api/users/99":             true, // même gabarit que /api/users/{int}
		"/.well-known/security.txt": true,
		"/api/users":                false, // nœud intermédiaire jamais servi
		"/.git/config":              false,
		"/":                         false,
	} {
		if got := c.Knows("r1", path); got != want {
			t.Errorf("Knows(%q) = %v, attendu %v", path, got, want)
		}
	}
	if c.Knows("autre-route", "/api/users/1") {
		t.Error("une route sans profil ne connaît aucun chemin")
	}
}
