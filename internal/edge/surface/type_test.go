// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// siteTraffic fait visiter days jours un site dont les chemins ne tiennent pas dans le profil (des milliers de pages distinctes).
func siteTraffic(c *Collector, ck *clock, typ string, days int) {
	for d := 0; d < days; d++ {
		for i := 0; i < 400; i++ {
			o := obs("r1", "blog.test", req("GET", fmt.Sprintf("/a%d/b%d/c%d", (i+d)%50, i%47, (i*d+i)%43)), fmt.Sprintf("10.3.%d.%d", i%7, i%200), 200, "text/html", true)
			o.Type = typ
			c.Observe(o)
		}
		ck.advance(24 * time.Hour)
	}
}

// pageTraffic : un blog dont chaque page est un chemin distinct sous la racine (plus de valeurs que le profil n'en garde par niveau).
func pageTraffic(c *Collector, typ string, n int) {
	for i := 0; i < n; i++ {
		o := obs("r1", "blog.test", req("GET", fmt.Sprintf("/page-%d", i%150)), fmt.Sprintf("10.3.0.%d", i%9+1), 200, "text/html", true)
		o.Type = typ
		c.Observe(o)
	}
}

func TestValidateType(t *testing.T) {
	for _, ok := range []string{"", "api", "site", " SITE "} {
		if err := ValidateType(ok); err != nil {
			t.Errorf("%q refusé : %v", ok, err)
		}
	}
	if err := ValidateType("blog"); err == nil || !strings.Contains(err.Error(), "api | site") {
		t.Errorf("type inconnu : %v", err)
	}
}

func TestSiteConvergenceDoesNotDependOnPaths(t *testing.T) {
	site, ck := newTest()
	siteTraffic(site, ck, TypeSite, 8)
	rep, _ := site.Report("r1", ModeLearn)
	if rep.Type != TypeSite || rep.Overflow == 0 {
		t.Fatalf("le trafic doit déborder le profil : type %q, débordement %d", rep.Type, rep.Overflow)
	}
	if !rep.Convergence.Converged || rep.Convergence.Overflow || rep.Convergence.NewTemplates != 0 {
		t.Errorf("un site converge sur l'ancienneté et le volume : %+v", rep.Convergence)
	}

	// Le même trafic, déclaré (ou pris pour) une API, ne converge jamais : les chemins ne cessent pas de changer.
	api, ck2 := newTest()
	siteTraffic(api, ck2, TypeAPI, 8)
	rep, _ = api.Report("r1", ModeLearn)
	if rep.Convergence.Converged || !rep.Convergence.Overflow {
		t.Errorf("une API qui déborde ne converge pas : %+v", rep.Convergence)
	}

	// Un site jeune n'est pas convergé pour autant : l'ancienneté et le volume comptent.
	young, ck3 := newTest()
	siteTraffic(young, ck3, TypeSite, 2)
	if rep, _ = young.Report("r1", ModeLearn); rep.Convergence.Converged || len(rep.Convergence.Reasons) == 0 {
		t.Errorf("deux jours : %+v", rep.Convergence)
	}
}

func TestSiteHasNoPathPolicyNorSuggestions(t *testing.T) {
	c, ck := newTest()
	for day := 0; day < 3; day++ {
		for i := 0; i < 12; i++ {
			o := obs("r1", "blog.test", req("GET", "/nouveau/1"), fmt.Sprintf("10.1.0.%d", i%6+1), 200, "", true)
			o.Type, o.Violation = TypeSite, "unknown_path"
			c.Observe(o)
		}
		ck.advance(24 * time.Hour)
	}
	pageTraffic(c, TypeSite, 150)
	rep, _ := c.Report("r1", ModeLearn)
	if len(rep.Suggestions) != 0 {
		t.Errorf("un site n'a pas de suggestion de chemin : %+v", rep.Suggestions)
	}
	if len(rep.Violations) != 1 {
		t.Errorf("les violations restent visibles : %+v", rep.Violations)
	}
	res, ok := c.OpenAPI("r1", OpenAPIOptions{IncludeLowSupport: true})
	if !ok || res.Config != nil || !strings.Contains(res.Error, "type site") {
		t.Errorf("politique d'un site : %+v", res)
	}
	if sum, _ := c.Summary("r1", ModeLearn); sum.Suggestions != 0 {
		t.Errorf("résumé : %d suggestions", sum.Suggestions)
	}
}

func TestTypeHintSeparatesSitesFromAPIs(t *testing.T) {
	site, _ := newTest()
	pageTraffic(site, "", 300)
	rep, _ := site.Report("r1", ModeLearn)
	if rep.Type != "" || rep.TypeHint != TypeSite || !strings.Contains(rep.TypeHintWhy, "contenu ouvert") {
		t.Errorf("trafic de site : type %q, indice %q (%s)", rep.Type, rep.TypeHint, rep.TypeHintWhy)
	}
	p, _ := site.Proposals("r1", Current{Host: "blog.test"}, nil)
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "surface.type = site") {
		t.Errorf("l'indice doit conseiller de déclarer le type : %v", p.Notes)
	}

	api, _ := newTest()
	for i := 0; i < 200; i++ {
		api.Observe(obs("r1", "api.test", req("GET", fmt.Sprintf("/api/users/%d", i)), fmt.Sprintf("10.0.0.%d", i%9+1), 200, "", true))
	}
	if rep, _ = api.Report("r1", ModeLearn); rep.TypeHint != TypeAPI {
		t.Errorf("trafic d'API : indice %q", rep.TypeHint)
	}
	if p, _ = api.Proposals("r1", Current{}, nil); len(p.Notes) != 0 {
		t.Errorf("une API n'a rien à se faire dire : %v", p.Notes)
	}

	few, _ := newTest()
	few.Observe(obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true))
	if rep, _ = few.Report("r1", ModeLearn); rep.TypeHint != "" {
		t.Errorf("trop peu de requêtes pour deviner : %q", rep.TypeHint)
	}
}

func TestSiteProposalsKeepSizesAndExplainWhatIsLeftOut(t *testing.T) {
	c, ck := newTest()
	for d := 0; d < 3; d++ {
		for i := 0; i < 400; i++ {
			r := req("POST", fmt.Sprintf("/a%d/b%d/c%d", (i+d)%50, i%47, (i*d+i)%43))
			r.ContentLength = int64(200 + i)
			o := obs("r1", "blog.test", r, fmt.Sprintf("10.3.0.%d", i%9+1), 200, "text/html", true)
			o.Type = TypeSite
			c.Observe(o)
		}
		ck.advance(24 * time.Hour)
	}
	p, _ := c.Proposals("r1", Current{Host: "blog.test"}, nil)
	if p.Type != TypeSite || len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "type site") {
		t.Fatalf("notes : %+v", p.Notes)
	}
	// Les corps sont mesurés pour le proxy entier : la proposition voit les requêtes dont le chemin n'a pas été retenu.
	body := item(t, p, SettingMaxBody)
	if string(body.Value) != "1024" && string(body.Value) != "16384" {
		t.Errorf("valeur %s", body.Value)
	}
	if body.Of != 1200 {
		t.Errorf("%d requêtes avec corps mesurées, attendu 1200 (aucune ne doit se perdre avec les chemins)", body.Of)
	}
}

func TestRouteLevelMediaAndBodyMergeAcrossPeers(t *testing.T) {
	a, _ := newTest()
	b, _ := newTest()
	for i := 0; i < 10; i++ {
		r := req("POST", "/x")
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = 300
		o := obs("r1", "a.test", r, "10.0.0.1", 200, "application/json", true)
		o.Type = TypeSite
		a.Observe(o)
		r2 := req("POST", "/y")
		r2.Header.Set("Content-Type", "text/xml")
		r2.ContentLength = 5000
		b.Observe(obs("r1", "a.test", r2, "10.0.0.2", 200, "text/xml", true))
	}
	a.ApplyPeer("b", b.Export())
	rep, _ := a.Report("r1", ModeLearn)
	if len(rep.RequestMedia) != 2 || len(rep.ResponseMedia) != 2 || rep.BodyMax != 5000 || rep.BodyP99 < 4000 {
		t.Errorf("types %v %v, corps max %d p99 %d", rep.RequestMedia, rep.ResponseMedia, rep.BodyMax, rep.BodyP99)
	}
	if rep.Type != TypeSite {
		t.Errorf("le type déclaré se fusionne : %q", rep.Type)
	}
}
