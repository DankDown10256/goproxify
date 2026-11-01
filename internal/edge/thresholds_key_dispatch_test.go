// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// loginSite : une route dont la connexion refuse tout (401) ; Ephor protège les comptes visés par cinq échecs en dix minutes.
type loginSite struct {
	s      *Server
	hits   atomic.Int32
	bodies atomic.Value // dernier corps reçu par le backend
}

func newLoginSite(t *testing.T, mode string) *loginSite {
	t.Helper()
	site := &loginSite{}
	site.bodies.Store("")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		site.bodies.Store(string(b))
		if r.Method == http.MethodPost && r.URL.Path == "/login" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "app", Host: "app.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}}
	s := newEphorGateway(t, t.TempDir(), route)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	cfg := threat.Config{
		Enabled:   true,
		Mode:      "block",
		IPScore:   threat.IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: threat.Duration{Duration: time.Hour}},
		Challenge: threat.ChallengeConfig{Mode: threat.ChallengeDetect, Threshold: 2, Difficulty: 8, Secret: "secret-de-test"},
		Whitelist: threat.Whitelist{IPs: []string{"198.51.100.250"}},
		Thresholds: threat.ThresholdsConfig{
			Logins: []threat.LoginRoute{{Path: "/login", Field: "email"}},
			Rules: []threat.ThresholdRule{{
				Name: "stuffing", Mode: mode, By: threat.ThresholdByAccount, Status: []string{"401"}, Paths: []string{"/login"},
				Count: 5, Window: threat.Duration{Duration: 10 * time.Minute},
			}},
		},
	}
	s.threatEngine.UpdateConfig(cfg)
	s.applyChallenge(cfg)
	site.s = s
	return site
}

func (l *loginSite) login(ip, account string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://app.example.test/login", strings.NewReader(`{"email":"`+account+`","password":"secret"}`))
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	l.s.dispatch(rec, req)
	return rec
}

func TestStuffingProtectsTheTargetedAccountAndNothingElse(t *testing.T) {
	site := newLoginSite(t, threat.ThresholdBlock)
	for i := 0; i < 5; i++ {
		if rec := site.login(fmt.Sprintf("203.0.113.%d", 10+i), "victime@example.fr"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("avant la protection la connexion atteint le backend : %d", rec.Code)
		}
	}
	if got := site.bodies.Load().(string); !strings.Contains(got, `"password":"secret"`) {
		t.Fatalf("le backend doit recevoir le corps entier de la connexion : %q", got)
	}

	// Les tentatives suivantes sur ce compte, depuis des IP sans historique, partagent trois essais par minute.
	var passed, limited int
	for i := 0; i < 12; i++ {
		switch site.login(fmt.Sprintf("203.0.113.%d", 100+i), "victime@example.fr").Code {
		case http.StatusUnauthorized:
			passed++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if passed != 3 || limited != 9 {
		t.Fatalf("trois tentatives par minute sur le compte visé : %d passées, %d limitées", passed, limited)
	}

	// Un autre compte, depuis une IP quelconque, n'est pas touché.
	if rec := site.login("203.0.113.200", "autre@example.fr"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("un autre compte reste servi : %d", rec.Code)
	}
	// La liste blanche d'Ephor n'est jamais limitée.
	if rec := site.login("198.51.100.250", "victime@example.fr"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("la liste blanche passe : %d", rec.Code)
	}
}

func TestStuffingInDetectModeLimitsNothing(t *testing.T) {
	site := newLoginSite(t, threat.ThresholdDetect)
	for i := 0; i < 20; i++ {
		if rec := site.login(fmt.Sprintf("203.0.113.%d", 10+i), "victime@example.fr"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("detect ne limite rien : %d", rec.Code)
		}
	}
}

func TestProtectedOperatorChallengesNavigationsAndLimitsTheRest(t *testing.T) {
	site := newLoginSite(t, threat.ThresholdBlock)
	cfg := threat.Config{
		Enabled:   true,
		Mode:      "block",
		IPScore:   threat.IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: threat.Duration{Duration: time.Hour}},
		Challenge: threat.ChallengeConfig{Mode: threat.ChallengeDetect, Difficulty: 8, Secret: "secret-de-test"},
		Thresholds: threat.ThresholdsConfig{Rules: []threat.ThresholdRule{{
			Name: "asn-fail", Mode: threat.ThresholdBlock, By: threat.ThresholdByASN, Status: []string{"401"}, Count: 3,
			Window: threat.Duration{Duration: time.Minute}, Limit: 2,
		}}},
	}
	site.s.threatEngine.UpdateConfig(cfg)
	site.s.applyChallenge(cfg)
	store := behavior.NewReplayStore(0)
	store.SetASNLookup(func(ip string) uint32 {
		if strings.HasPrefix(ip, "203.0.113.") {
			return 64500
		}
		return 0
	})
	site.s.threatEngine.SetBehaviorStore(store)

	for i := 0; i < 3; i++ {
		site.login(fmt.Sprintf("203.0.113.%d", 10+i), fmt.Sprintf("u%d@example.fr", i))
	}

	nav := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://app.example.test/page", nil)
		req.RemoteAddr = ip + ":40000"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", html)
		rec := httptest.NewRecorder()
		site.s.dispatch(rec, req)
		return rec
	}
	before := site.hits.Load()
	if page := nav("203.0.113.50"); !strings.Contains(page.Body.String(), "Checking your browser") || site.hits.Load() != before {
		t.Fatalf("une navigation depuis l'opérateur protégé reçoit le défi : %d %q", page.Code, page.Body.String())
	}
	if rec := nav("192.0.2.50"); rec.Code != http.StatusOK {
		t.Fatalf("un autre opérateur n'est pas touché : %d", rec.Code)
	}

	limited := 0
	for i := 0; i < 6; i++ {
		if site.login(fmt.Sprintf("203.0.113.%d", 60+i), fmt.Sprintf("v%d@example.fr", i)).Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 4 {
		t.Fatalf("deux tentatives par minute pour l'opérateur protégé : %d limitées sur 6", limited)
	}
}
