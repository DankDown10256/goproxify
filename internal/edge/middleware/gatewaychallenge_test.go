// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func navReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.RemoteAddr = "203.0.113.7:4000"
	return r
}

func TestGatewayChallengeApplies(t *testing.T) {
	g := NewGatewayChallenge(GatewayChallengeConfig{ExemptPaths: []string{"/api/"}})
	withHeader := func(r *http.Request, k, v string) *http.Request { r.Header.Set(k, v); return r }
	noAccept := func() *http.Request {
		r := navReq("GET", "/page")
		r.Header.Del("Accept")
		return r
	}
	botRoute := func(b router.BotConfig) *router.Route { b.Enabled = true; return &router.Route{Bot: &b} }

	for name, tc := range map[string]struct {
		r     *http.Request
		route *router.Route
		want  bool
	}{
		"navigation GET":            {navReq("GET", "/page"), nil, true},
		"HEAD":                      {navReq("HEAD", "/page"), nil, true},
		"navigation sans Accept":    {withHeader(noAccept(), "Sec-Fetch-Mode", "navigate"), nil, true},
		"POST":                      {navReq("POST", "/page"), nil, false},
		"client d'API (Accept */*)": {withHeader(navReq("GET", "/page"), "Accept", "*/*"), nil, false},
		"JSON":                      {withHeader(navReq("GET", "/page"), "Accept", "application/json"), nil, false},
		"WebSocket":                 {withHeader(navReq("GET", "/ws"), "Upgrade", "websocket"), nil, false},
		"validation ACME":           {navReq("GET", "/.well-known/acme-challenge/x"), nil, false},
		"chemin exempté":            {navReq("GET", "/api/v1/users"), nil, false},
		"URL de vérification":       {navReq("GET", GatewayChallengePath), nil, false},
		"exemption de la route":     {navReq("GET", "/hooks/x"), botRoute(router.BotConfig{ChallengeExemptPaths: []string{"/hooks/"}}), false},
		"route qui défie déjà":      {navReq("GET", "/page"), botRoute(router.BotConfig{Mode: "challenge"}), false},
		"route avec bot sans défi":  {navReq("GET", "/page"), botRoute(router.BotConfig{Mode: "block"}), true},
	} {
		if got := g.Applies(tc.r, tc.route); got != tc.want {
			t.Errorf("%s : Applies = %v, attendu %v", name, got, tc.want)
		}
	}
}

func TestGatewayChallengeSolveThenProof(t *testing.T) {
	g := NewGatewayChallenge(GatewayChallengeConfig{Difficulty: 8, Secret: "secret-de-test"})

	page := httptest.NewRecorder()
	g.Serve(page, navReq("GET", "/app?x=1"))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Checking your browser") {
		t.Fatalf("page de défi attendue : %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), `"`+GatewayChallengePath+`"`) {
		t.Fatalf("la page doit poster sur l'URL de vérification de la passerelle, pas sur celle d'une route : %s", page.Body.String())
	}
	token := tokenRe.FindStringSubmatch(page.Body.String())[1]

	body, _ := json.Marshal(map[string]string{"c": token, "n": solve(token, 8)})
	post := httptest.NewRequest("POST", GatewayChallengePath, strings.NewReader(string(body)))
	post.Header.Set("User-Agent", "Mozilla/5.0")
	post.RemoteAddr = "203.0.113.7:4000"
	if !g.IsVerify(post) {
		t.Fatal("un POST sur l'URL de vérification est une solution")
	}
	ok := httptest.NewRecorder()
	if !g.Verify(ok, post) || ok.Code != http.StatusNoContent {
		t.Fatalf("solution valide refusée : %d", ok.Code)
	}
	cookies := ok.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "_gpx_ephor" || !cookies[0].HttpOnly {
		t.Fatalf("cookie de preuve attendu (HttpOnly, nom propre à la passerelle) : %v", cookies)
	}

	req := navReq("GET", "/app")
	req.AddCookie(cookies[0])
	req.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	if !g.HasProof(req) {
		t.Fatal("la preuve doit être reconnue")
	}
	g.StripProof(req)
	if got := req.Header.Get("Cookie"); got != "sid=abc" {
		t.Fatalf("le cookie de preuve ne doit pas atteindre le backend, reçu %q", got)
	}

	other := navReq("GET", "/app")
	other.RemoteAddr = "203.0.113.99:4000"
	other.AddCookie(cookies[0])
	if g.HasProof(other) {
		t.Fatal("une preuve copiée sur une autre IP ne vaut rien")
	}
}

func TestGatewayChallengeRejectsAWrongNonce(t *testing.T) {
	g := NewGatewayChallenge(GatewayChallengeConfig{Difficulty: 16, Secret: "s"})
	page := httptest.NewRecorder()
	g.Serve(page, navReq("GET", "/"))
	token := tokenRe.FindStringSubmatch(page.Body.String())[1]
	body, _ := json.Marshal(map[string]string{"c": token, "n": "0"})
	post := httptest.NewRequest("POST", GatewayChallengePath, strings.NewReader(string(body)))
	post.RemoteAddr = "203.0.113.7:4000"
	post.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	if g.Verify(rec, post) || rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("un nonce faux ne doit pas donner de preuve : %d", rec.Code)
	}
}

// Le défi de la passerelle et celui d'une route ne se partagent ni cookie ni URL : une preuve de l'un ne vaut pas pour l'autre.
func TestGatewayChallengeIsIndependentOfTheRouteChallenge(t *testing.T) {
	gw := NewGatewayChallenge(GatewayChallengeConfig{Difficulty: 8, Secret: "commun"})
	route := newBotChallenge(&router.BotConfig{ChallengeDifficulty: 8}, "commun")

	req := navReq("GET", "/")
	rec := httptest.NewRecorder()
	route.handleVerify(rec, func() *http.Request {
		page := httptest.NewRecorder()
		route.serve(page, navReq("GET", "/"))
		token := tokenRe.FindStringSubmatch(page.Body.String())[1]
		b, _ := json.Marshal(map[string]string{"c": token, "n": solve(token, 8)})
		p := httptest.NewRequest("POST", botChallengePath, strings.NewReader(string(b)))
		p.RemoteAddr = "203.0.113.7:4000"
		p.Header.Set("User-Agent", "Mozilla/5.0")
		return p
	}())
	routeCookie := rec.Result().Cookies()[0]
	req.AddCookie(routeCookie)
	if routeCookie.Name == "_gpx_ephor" || gw.HasProof(req) {
		t.Fatalf("la preuve d'une route (cookie %s) ne doit pas valoir pour la passerelle", routeCookie.Name)
	}
}
