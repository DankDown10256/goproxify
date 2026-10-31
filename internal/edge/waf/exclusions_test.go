// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func code(t *testing.T, cfg *router.WAFConfig, path, payload string) int {
	t.Helper()
	e := NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := e.Middleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path+"?q="+url.QueryEscape(payload), nil))
	return rec.Code
}

func TestMatchPathIsOnSegmentBoundaries(t *testing.T) {
	for _, tc := range []struct {
		path, prefix string
		want         bool
	}{
		{"/wp-admin/post.php", "/wp-admin/", true},
		{"/wp-admin", "/wp-admin/", true},
		{"/wp-adminx/post.php", "/wp-admin/", false},
		{"/api/search", "/api/search", true},
		{"/api/search/x", "/api/search", true},
		{"/api/searchx", "/api/search", false},
		{"/other", "/api/search", false},
		{"/anything", "/", false}, // « / » est refusé par la validation : jamais un chemin d'exclusion
		{"/x", "", false},
		{"x", "x", false},
	} {
		if got := MatchPath(tc.path, tc.prefix); got != tc.want {
			t.Errorf("MatchPath(%q, %q) = %v, attendu %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

// Une charge arrêtée partout est laissée passer sous le chemin de l'exclusion, et seulement là.
func TestPathExclusionOnlyAppliesUnderItsPaths(t *testing.T) {
	ids, _ := PlatformIDs("wordpress")
	var payload string
	for _, p := range payloads {
		if code(t, &router.WAFConfig{Enabled: true, Mode: "block"}, "/", p) == http.StatusForbidden &&
			code(t, &router.WAFConfig{Enabled: true, Mode: "block", ExcludeIDs: ids}, "/", p) == http.StatusNoContent {
			payload = p
			break
		}
	}
	if payload == "" {
		t.Fatal("aucune charge n'est arrêtée seulement par les règles de WordPress : le test ne prouve rien")
	}
	scoped := &router.WAFConfig{Enabled: true, Mode: "block", Exclusions: []router.WAFExclusion{{Paths: []string{"/wp-admin/", "/wp-json/"}, Platform: "wordpress"}}}
	for path, want := range map[string]int{
		"/wp-admin/post.php":   http.StatusNoContent, // sous le chemin : exclue
		"/wp-json/wp/v2/posts": http.StatusNoContent,
		"/":                    http.StatusForbidden, // partout ailleurs : la règle reste active
		"/search":              http.StatusForbidden,
		"/wp-adminx/x":         http.StatusForbidden,
		"/blog/2026/article":   http.StatusForbidden,
	} {
		if got := code(t, scoped, path, payload); got != want {
			t.Errorf("%s : %d, attendu %d", path, got, want)
		}
	}

	// Avec des règles nommées une à une, le même effet que la plateforme.
	byIDs := &router.WAFConfig{Enabled: true, Mode: "block", Exclusions: []router.WAFExclusion{{Paths: []string{"/admin/"}, RuleIDs: ids}}}
	if code(t, byIDs, "/admin/x", payload) != http.StatusNoContent || code(t, byIDs, "/", payload) != http.StatusForbidden {
		t.Error("rule_ids : exclue sous /admin/ seulement")
	}

	// Une exclusion sur tout le proxy et une par chemin s'ajoutent.
	both := &router.WAFConfig{Enabled: true, Mode: "block", ExcludeIDs: ids[:1], Exclusions: scoped.Exclusions}
	if code(t, both, "/wp-admin/x", payload) != http.StatusNoContent {
		t.Error("l'union des exclusions")
	}
}

func TestInvalidPathExclusionsAreIgnoredByTheEngine(t *testing.T) {
	// Sans chemin elle vaudrait pour tout le proxy : le moteur l'ignore (la validation la refuse à l'enregistrement).
	ids, _ := PlatformIDs("wordpress")
	var payload string
	for _, p := range payloads {
		if code(t, &router.WAFConfig{Enabled: true, Mode: "block"}, "/", p) == http.StatusForbidden &&
			code(t, &router.WAFConfig{Enabled: true, Mode: "block", ExcludeIDs: ids}, "/", p) == http.StatusNoContent {
			payload = p
			break
		}
	}
	cfg := &router.WAFConfig{Enabled: true, Mode: "block", Exclusions: []router.WAFExclusion{{RuleIDs: ids}, {Paths: []string{"/x/"}}}}
	if got := code(t, cfg, "/x/y", payload); got != http.StatusForbidden {
		t.Errorf("exclusion sans chemin ou sans règle : %d", got)
	}
}

func TestValidateConfig(t *testing.T) {
	if errs := ValidateConfig(nil); len(errs) != 0 {
		t.Errorf("sans WAF : %v", errs)
	}
	ok := &router.WAFConfig{Exclusions: []router.WAFExclusion{{Paths: []string{"/wp-admin/"}, Platform: "wordpress"}, {Paths: []string{"/a"}, RuleIDs: []int{942100}}}}
	if errs := ValidateConfig(ok); len(errs) != 0 {
		t.Errorf("configuration valide : %v", errs)
	}
	bad := &router.WAFConfig{Exclusions: []router.WAFExclusion{
		{RuleIDs: []int{1}},                            // sans chemin
		{Paths: []string{"admin/"}, RuleIDs: []int{1}}, // sans /
		{Paths: []string{"/"}, RuleIDs: []int{1}},      // tout le proxy
		{Paths: []string{"/x/"}, Platform: "wordprss"}, // plateforme inconnue
		{Paths: []string{"/x/"}},                       // sans règle
		{Paths: []string{"/x/"}, RuleIDs: []int{-3}},   // identifiant invalide
	}}
	errs := strings.Join(ValidateConfig(bad), "\n")
	for _, want := range []string{"au moins un chemin", `doit commencer par /`, "couvre tout le proxy", `plateforme "wordprss" inconnue`, "rule_ids ou platform est requis", "identifiant de règle -3"} {
		if !strings.Contains(errs, want) {
			t.Errorf("erreur %q absente :\n%s", want, errs)
		}
	}
}
