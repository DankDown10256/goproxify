// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// learnAPI apprend un petit service sur trois jours, avec assez de clients pour que chaque chemin soit soutenu.
func learnAPI(t *testing.T) (*Collector, *clock) {
	t.Helper()
	c, ck := newTest()
	for day := 0; day < 3; day++ {
		for i := 0; i < 120; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", i%6, i%200)
			c.Observe(obs("r1", "api.test", req("GET", fmt.Sprintf("/api/users/%d", 100+i)), ip, 200, "application/json", true))
			c.Observe(obs("r1", "api.test", req("GET", fmt.Sprintf("/api/users/%d/orders/%d", i, i*3)), ip, 200, "application/json", true))
			c.Observe(obs("r1", "api.test", req("GET", fmt.Sprintf("/search?q=mot%d&page=%d&actif=true", i, i%9)), ip, 200, "application/json", true))
			c.Observe(obs("r1", "api.test", req("GET", "/health"), ip, 200, "text/plain", true))
			post := req("POST", "/api/items")
			post.Header.Set("Content-Type", "application/json")
			post.ContentLength = 120
			c.Observe(obs("r1", "api.test", post, ip, 201, "application/json", true))
		}
		ck.advance(24 * time.Hour)
	}
	// Un chemin vu par un seul client, un seul jour.
	c.Observe(obs("r1", "api.test", req("GET", "/rare/export"), "10.9.9.9", 200, "", true))
	return c, ck
}

// run passe une requête dans le vrai contrôle openapi, en mode detect, et rend son verdict.
func run(t *testing.T, cfgJSON json.RawMessage, method, target, contentType string) middleware.OpenAPIOutcome {
	t.Helper()
	var cfg router.OpenAPIConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatal(err)
	}
	if errs := middleware.ValidateOpenAPIConfig(&cfg); len(errs) > 0 {
		t.Fatalf("le contrôle openapi refuse la configuration générée : %v", errs)
	}
	h := middleware.OpenAPI("api.test", &cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest(method, target, strings.NewReader(`{"a":1}`))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	ctx, out := middleware.WithOpenAPIOutcome(r.Context())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r.WithContext(ctx))
	if rec.Code != 204 {
		t.Fatalf("en mode detect la requête doit toujours passer, reçu %d", rec.Code)
	}
	return *out
}

func TestGeneratedPolicyAcceptsLearnedTrafficAndFlagsTheRest(t *testing.T) {
	c, _ := learnAPI(t)
	res, ok := c.OpenAPI("r1", OpenAPIOptions{})
	if !ok || res.Error != "" {
		t.Fatalf("génération : %+v", res)
	}
	if res.Paths != 5 || res.Operations != 5 {
		t.Errorf("chemins %d, opérations %d ; attendu 5 et 5 (users, users/orders, search, health, items)", res.Paths, res.Operations)
	}
	var cfg struct {
		Enabled      bool            `json:"enabled"`
		Mode         string          `json:"mode"`
		UnknownPaths string          `json:"unknown_paths"`
		Spec         json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(res.Config, &cfg); err != nil || !cfg.Enabled || cfg.Mode != "detect" || cfg.UnknownPaths != "block" {
		t.Fatalf("configuration %s", res.Config)
	}
	if strings.Contains(string(cfg.Spec), "rare") {
		t.Error("un chemin à faible soutien est entré dans la politique")
	}
	foundRare := false
	for _, e := range res.Excluded {
		if e.Path == "/rare/export" && strings.Contains(e.Reason, "faible soutien") {
			foundRare = true
		}
	}
	if !foundRare {
		t.Errorf("le chemin à confirmer doit être dans excluded : %v", res.Excluded)
	}

	for _, tc := range []struct {
		name, method, target, ct, want string
	}{
		{"id entier", "GET", "/api/users/42", "", ""},
		{"sous-ressource", "GET", "/api/users/7/orders/21", "", ""},
		{"paramètres typés", "GET", "/search?q=chat&page=3&actif=false", "", ""},
		{"corps json", "POST", "/api/items", "application/json; charset=utf-8", ""},
		{"santé", "GET", "/health", "", ""},
		{"chemin inconnu", "GET", "/wp-login.php", "", "unknown_path"},
		{"chemin à faible soutien", "GET", "/rare/export", "", "unknown_path"},
		{"méthode inconnue", "DELETE", "/api/users/42", "", "unknown_method"},
		{"identifiant non entier", "GET", "/api/users/abc", "", "invalid_param"},
		{"page non entière", "GET", "/search?page=beaucoup", "", "invalid_param"},
		{"booléen invalide", "GET", "/search?actif=peut-etre", "", "invalid_param"},
		{"type de contenu inattendu", "POST", "/api/items", "text/xml", "unsupported_media"},
	} {
		if got := run(t, res.Config, tc.method, tc.target, tc.ct); got.Reason != tc.want {
			t.Errorf("%s : %s %s → raison %q, attendu %q", tc.name, tc.method, tc.target, got.Reason, tc.want)
		}
	}

	with, _ := c.OpenAPI("r1", OpenAPIOptions{IncludeLowSupport: true})
	if with.Paths != 6 {
		t.Errorf("avec les chemins à confirmer : %d chemins, attendu 6", with.Paths)
	}
}

func TestOverlappingTemplatesMergeIntoOnePath(t *testing.T) {
	c, ck := newTest()
	for day := 0; day < 3; day++ {
		for i := 0; i < 80; i++ {
			ip := fmt.Sprintf("10.0.%d.1", i%5)
			c.Observe(obs("r1", "a.test", req("GET", fmt.Sprintf("/u/%d", i)), ip, 200, "", true))
			c.Observe(obs("r1", "a.test", req("GET", "/u/moi"), ip, 200, "", true))
		}
		ck.advance(24 * time.Hour)
	}
	res, _ := c.OpenAPI("r1", OpenAPIOptions{})
	if res.Error != "" || res.Paths != 2 {
		t.Fatalf("attendu 2 chemins (/u/{u_id} et /u/moi), obtenu %d (%s)", res.Paths, res.Error)
	}
	if got := run(t, res.Config, "GET", "/u/12", ""); got.Reason != "" {
		t.Errorf("/u/12 : %q", got.Reason)
	}
	if got := run(t, res.Config, "GET", "/u/moi", ""); got.Reason != "" {
		t.Errorf("/u/moi : %q", got.Reason)
	}

	// Un niveau qui mêle entier et texte ne doit pas typer le paramètre en entier : sinon /u/abc serait refusé à tort.
	mix, _ := newTest()
	for day := 0; day < 3; day++ {
		for i := 0; i < 80; i++ {
			ip := fmt.Sprintf("10.0.%d.1", i%5)
			mix.Observe(obs("r1", "a.test", req("GET", fmt.Sprintf("/v/%d", i)), ip, 200, "", true))
			mix.Observe(obs("r1", "a.test", req("GET", fmt.Sprintf("/v/%016x", uint64(i)*7919+0xabcdef0123456789)), ip, 200, "", true)) // {hex}
		}
	}
	res, _ = mix.OpenAPI("r1", OpenAPIOptions{IncludeLowSupport: true})
	if res.Error != "" || res.Paths != 1 {
		t.Fatalf("entier et empreinte au même niveau : %d chemins (%s)", res.Paths, res.Error)
	}
	if got := run(t, res.Config, "GET", "/v/abc", ""); got.Reason != "" {
		t.Errorf("le paramètre mêlant plusieurs classes doit être un texte : %q", got.Reason)
	}
}

func TestOpenAPIRefusedWhenProfileTooYoungOrSparse(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < 50; i++ {
		c.Observe(obs("r1", "a.test", req("GET", "/x"), "10.0.0.1", 200, "", true))
	}
	if res, _ := c.OpenAPI("r1", OpenAPIOptions{}); res.Error == "" || res.Config != nil {
		t.Errorf("sous 100 requêtes : %+v", res)
	}
	for i := 0; i < 200; i++ {
		c.Observe(obs("r1", "a.test", req("GET", "/x"), "10.0.0.1", 200, "", true))
	}
	res, _ := c.OpenAPI("r1", OpenAPIOptions{})
	if res.Error == "" || !strings.Contains(res.Error, "soutenu") {
		t.Errorf("un seul client et un seul jour : %+v", res)
	}
	if res, _ := c.OpenAPI("r1", OpenAPIOptions{IncludeLowSupport: true}); res.Error != "" || res.Paths != 1 {
		t.Errorf("avec les chemins à confirmer : %+v", res)
	}
	if _, ok := c.OpenAPI("absent", OpenAPIOptions{}); ok {
		t.Error("proxy sans profil")
	}
}

func TestOpenAPICautionsAndReadiness(t *testing.T) {
	c, _ := learnAPI(t)
	res, _ := c.OpenAPI("r1", OpenAPIOptions{Replaces: true})
	if res.Ready {
		t.Error("trois jours et 1 800 requêtes : le profil n'est pas encore convergé")
	}
	joined := strings.Join(res.Cautions, " | ")
	for _, want := range []string{"mode detect", "pas encore fiable", "remplacerait", "corps"} {
		if !strings.Contains(joined, want) {
			t.Errorf("mise en garde %q absente : %s", want, joined)
		}
	}
}

func TestViolationsAreCountedWithoutIdentifiers(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < 20; i++ {
		o := obs("r1", "a.test", req("GET", fmt.Sprintf("/nouveau/%d/detail", 1000+i)), fmt.Sprintf("10.0.0.%d", i%6), 200, "", true)
		o.Violation = "unknown_path"
		c.Observe(o)
	}
	o := obs("r1", "a.test", req("GET", "/.env"), "192.0.2.5", 404, "", false)
	o.Violation = "unknown_path"
	c.Observe(o)
	rep, _ := c.Report("r1", ModeLearn)
	if len(rep.ViolationTotals) != 1 || rep.ViolationTotals[0].Count != 21 {
		t.Fatalf("totaux : %v", rep.ViolationTotals)
	}
	byPath := map[string]ViolationInfo{}
	for _, v := range rep.Violations {
		byPath[v.Path] = v
	}
	nv := byPath["/nouveau/{int}/detail"]
	if nv.Count != 20 || nv.Legit != 20 || nv.Clients < 5 || !nv.LikelyLegit {
		t.Errorf("chemin légitime manquant à la politique : %+v", nv)
	}
	if env := byPath["/.env"]; env.Count != 1 || env.Legit != 0 || env.LikelyLegit {
		t.Errorf("sonde d'un scanner : %+v", env)
	}
	raw, _ := json.Marshal(c.Snapshot())
	if strings.Contains(string(raw), "1007") || strings.Contains(string(raw), "10.0.0.") {
		t.Error("un identifiant ou une IP est écrit dans l'état")
	}
}

func TestViolationMergeAndBounds(t *testing.T) {
	a, _ := newTest()
	b, _ := newTest()
	for i := 0; i < maxViolations+30; i++ {
		o := obs("r1", "a.test", req("GET", fmt.Sprintf("/p%d", i)), "10.0.0.1", 404, "", false)
		o.Violation = "unknown_path"
		a.Observe(o)
	}
	o := obs("r1", "a.test", req("GET", "/p1"), "10.0.0.2", 404, "", false)
	o.Violation = "unknown_path"
	b.Observe(o)
	a.ApplyPeer("b", b.Export())
	rep, _ := a.Report("r1", ModeLearn)
	if rep.ViolationsOverflow != 30 || rep.ViolationTotals[0].Count != int64(maxViolations+30)+1 {
		t.Errorf("débordement %d, total %d", rep.ViolationsOverflow, rep.ViolationTotals[0].Count)
	}
	a.mu.RLock()
	n := len(a.routes["r1"].p.Violations)
	a.mu.RUnlock()
	if n > maxViolations {
		t.Errorf("%d violations distinctes, plafond %d", n, maxViolations)
	}
}

func TestViolationReasonsMatchTheControl(t *testing.T) {
	if strings.Join(ViolationReasons, ",") != strings.Join(middleware.OpenAPIReasons, ",") {
		t.Errorf("les raisons de la surface %v et celles du contrôle openapi %v doivent rester les mêmes", ViolationReasons, middleware.OpenAPIReasons)
	}
}

func TestBlockedViolationsAreCountedApart(t *testing.T) {
	c, _ := newTest()
	for i := 0; i < 6; i++ {
		o := obs("r1", "a.test", req("GET", "/interdit"), fmt.Sprintf("10.0.0.%d", i), 404, "", true)
		o.Violation, o.Blocked = "unknown_path", i < 4
		c.Observe(o)
	}
	rep, _ := c.Report("r1", ModeLearn)
	if len(rep.BlockedTotals) != 1 || rep.BlockedTotals[0].Count != 4 || rep.ViolationTotals[0].Count != 6 {
		t.Fatalf("refusées %v sur %v", rep.BlockedTotals, rep.ViolationTotals)
	}
	if len(rep.Violations) != 1 || rep.Violations[0].Blocked != 4 || rep.Violations[0].Count != 6 {
		t.Errorf("violation : %+v", rep.Violations)
	}
}

func TestAcceptedSuggestionsMakeTheControlAcceptTheRequests(t *testing.T) {
	c, _ := learnAPI(t)
	res, _ := c.OpenAPI("r1", OpenAPIOptions{})
	var cfg map[string]any
	if err := json.Unmarshal(res.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	spec, err := ParseSpec(cfg["spec"])
	if err != nil {
		t.Fatal(err)
	}
	before := run(t, res.Config, "GET", "/nouveau/5", "")
	beforeMethod := run(t, res.Config, "DELETE", "/api/users/42", "")
	if before.Reason != "unknown_path" || beforeMethod.Reason != "unknown_method" {
		t.Fatalf("avant : %q %q", before.Reason, beforeMethod.Reason)
	}
	for _, add := range [][2]string{{"GET", "/nouveau/{int}"}, {"DELETE", "/api/users/{int}"}, {"GET", "/nouveau/{int}/detail"}} {
		if ok, err := AddToSpec(spec, add[0], add[1]); err != nil || !ok {
			t.Fatalf("ajout de %v : %v %v", add, ok, err)
		}
	}
	cfg["spec"] = spec
	raw, _ := json.Marshal(cfg)
	for _, tc := range []struct{ method, target, want string }{
		{"GET", "/nouveau/5", ""},
		{"GET", "/nouveau/5/detail", ""},
		{"DELETE", "/api/users/42", ""},
		{"GET", "/nouveau/abc", "invalid_param"},
		{"GET", "/api/users/42", ""},               // l'existant reste valable
		{"GET", "/search?page=2", ""},              // idem
		{"PUT", "/api/users/42", "unknown_method"}, // ce qui n'a pas été accepté reste hors politique
		{"GET", "/wp-login.php", "unknown_path"},
	} {
		if got := run(t, raw, tc.method, tc.target, ""); got.Reason != tc.want {
			t.Errorf("%s %s → %q, attendu %q", tc.method, tc.target, got.Reason, tc.want)
		}
	}
}
