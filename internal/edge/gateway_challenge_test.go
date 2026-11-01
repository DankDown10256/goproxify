// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/sha256"
	"encoding/json"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

var challengeTokenRe = regexp.MustCompile(`var gpxToken="([^"]+)"`)

func solvePoW(token string, difficulty int) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(n)))
		zeros := 0
		for _, b := range sum {
			if b == 0 {
				zeros += 8
				continue
			}
			zeros += bits.LeadingZeros8(b)
			break
		}
		if zeros >= difficulty {
			return strconv.Itoa(n)
		}
	}
}

func challengeCounter(t *testing.T, result string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "gpx_threat_challenge_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "result" && lp.GetValue() == result {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

type challengeSite struct {
	s       *Server
	hits    atomic.Int32
	cookies atomic.Value // dernier en-tête Cookie reçu par le backend
}

// newChallengeSite : une passerelle avec une route, Ephor à score cumulé (ban à 10, défi à 2) et un chemin de liste qui pèse 2.
func newChallengeSite(t *testing.T, mode string, bot *router.BotConfig) *challengeSite {
	t.Helper()
	site := &challengeSite{}
	site.cookies.Store("")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site.hits.Add(1)
		site.cookies.Store(r.Header.Get("Cookie"))
	}))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "app", Host: "app.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}, Bot: bot}
	s := newEphorGateway(t, t.TempDir(), route)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	cfg := threat.Config{
		Enabled:     true,
		Mode:        "block",
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		IPScore:     threat.IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: threat.Duration{Duration: time.Hour}},
		Challenge:   threat.ChallengeConfig{Mode: mode, Threshold: 2, Difficulty: 8, ExemptPaths: []string{"/api/"}, Secret: "secret-de-test"},
	}
	s.threatEngine.UpdateConfig(cfg)
	s.applyChallenge(cfg)
	site.s = s
	return site
}

func (c *challengeSite) do(ip, method, path, accept string, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://app.example.test"+path, strings.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.s.dispatch(rec, req)
	return rec
}

const html = "text/html,application/xhtml+xml"

// raise donne à l'IP une note de 4 : nettement au-dessus du défi (2, le score décroît en continu), sous le ban (10).
func (c *challengeSite) raise(ip string) {
	c.do(ip, "GET", "/wp-login.php", html, "")
	c.do(ip, "GET", "/wp-login.php", html, "")
}

func TestGraduatedChallengeFullPath(t *testing.T) {
	site := newChallengeSite(t, threat.ChallengeBlock, nil)
	const ip = "203.0.113.40"

	if rec := site.do("203.0.113.41", "GET", "/page", html, ""); rec.Code != http.StatusOK || site.hits.Load() != 1 {
		t.Fatalf("une IP sans note passe au backend : %d, %d appels", rec.Code, site.hits.Load())
	}

	site.raise(ip)
	servedBefore, solvedBefore := challengeCounter(t, "served"), challengeCounter(t, "solved")
	page := site.do(ip, "GET", "/page", html, "")
	if !strings.Contains(page.Body.String(), "Checking your browser") || site.hits.Load() != 1 {
		t.Fatalf("une IP au-dessus du seuil reçoit la page de défi sans toucher le backend : %d %q", page.Code, page.Body.String())
	}
	if challengeCounter(t, "served") != servedBefore+1 {
		t.Fatal("la page servie doit être comptée")
	}

	// Ce qui ne peut pas porter un défi reste sur la voie du ban.
	for name, tc := range map[string]struct{ method, path, accept string }{
		"client d'API":    {"GET", "/data", "application/json"},
		"POST":            {"POST", "/form", html},
		"chemin exempté":  {"GET", "/api/v1/users", html},
		"validation ACME": {"GET", "/.well-known/acme-challenge/x", html},
	} {
		before := site.hits.Load()
		if rec := site.do(ip, tc.method, tc.path, tc.accept, ""); rec.Code != http.StatusOK || site.hits.Load() != before+1 {
			t.Errorf("%s : doit atteindre le backend (%d)", name, rec.Code)
		}
	}

	token := challengeTokenRe.FindStringSubmatch(page.Body.String())[1]
	payload, _ := json.Marshal(map[string]string{"c": token, "n": solvePoW(token, 8)})
	solved := site.do(ip, "POST", middleware.GatewayChallengePath, "", string(payload))
	if solved.Code != http.StatusNoContent || len(solved.Result().Cookies()) != 1 {
		t.Fatalf("solution valide refusée : %d", solved.Code)
	}
	if challengeCounter(t, "solved") != solvedBefore+1 {
		t.Fatal("la solution doit être comptée")
	}

	before := site.hits.Load()
	proof := solved.Result().Cookies()[0]
	if rec := site.do(ip, "GET", "/page", html, "", proof, &http.Cookie{Name: "sid", Value: "abc"}); rec.Code != http.StatusOK || site.hits.Load() != before+1 {
		t.Fatalf("avec la preuve, la requête atteint le backend : %d", rec.Code)
	}
	if got := site.cookies.Load().(string); got != "sid=abc" {
		t.Fatalf("le cookie de preuve ne doit pas atteindre le backend, reçu %q", got)
	}
}

func TestGraduatedChallengeFailedSolutionIsRefusedAndCounted(t *testing.T) {
	site := newChallengeSite(t, threat.ChallengeBlock, nil)
	const ip = "203.0.113.42"
	site.raise(ip)
	page := site.do(ip, "GET", "/page", html, "")
	token := challengeTokenRe.FindStringSubmatch(page.Body.String())[1]
	failedBefore := challengeCounter(t, "failed")

	payload, _ := json.Marshal(map[string]string{"c": token, "n": "x"})
	rec := site.do(ip, "POST", middleware.GatewayChallengePath, "", string(payload))
	if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("une solution fausse ne donne pas de preuve : %d", rec.Code)
	}
	if challengeCounter(t, "failed") != failedBefore+1 {
		t.Fatal("l'échec doit être compté")
	}
}

func TestGraduatedChallengeDetectModeServesNothing(t *testing.T) {
	site := newChallengeSite(t, threat.ChallengeDetect, nil)
	const ip = "203.0.113.43"
	site.raise(ip)
	shadowBefore := challengeCounter(t, "shadow")

	before := site.hits.Load()
	rec := site.do(ip, "GET", "/page", html, "")
	if strings.Contains(rec.Body.String(), "Checking your browser") || site.hits.Load() != before+1 {
		t.Fatalf("en detect, la requête atteint le backend sans défi : %d", rec.Code)
	}
	if challengeCounter(t, "shadow") != shadowBefore+1 {
		t.Fatal("le défi qui aurait été imposé doit être compté")
	}
}

func TestGraduatedChallengeOffLeavesNoVerifyEndpoint(t *testing.T) {
	site := newChallengeSite(t, "", nil)
	if site.s.gwChallenge.Load() != nil {
		t.Fatal("défi off : aucun défi monté")
	}
	site.raise("203.0.113.44")
	before := site.hits.Load()
	site.do("203.0.113.44", "POST", middleware.GatewayChallengePath, "", "{}")
	if site.hits.Load() != before+1 {
		t.Fatal("défi off : l'URL de vérification est une requête ordinaire, transmise au backend")
	}
}

func TestGraduatedChallengeDoesNotChallengeTwiceOnARouteThatAlreadyDoes(t *testing.T) {
	site := newChallengeSite(t, threat.ChallengeBlock, &router.BotConfig{Enabled: true, Mode: "challenge", ChallengeSecret: "route", ChallengeDifficulty: 8})
	const ip = "203.0.113.45"
	site.raise(ip)
	rec := site.do(ip, "GET", "/page", html, "")
	if !strings.Contains(rec.Body.String(), `gpxVerify="/.gpx/challenge"`) {
		t.Fatalf("c'est le défi de la route qui répond, pas celui de la passerelle : %q", rec.Body.String())
	}
}

func TestGraduatedChallengeIsDroppedWhenEphorIsDisabled(t *testing.T) {
	site := newChallengeSite(t, threat.ChallengeBlock, nil)
	cfg := threat.Config{Enabled: false, Challenge: threat.ChallengeConfig{Mode: threat.ChallengeBlock}}
	site.s.threatEngine.UpdateConfig(cfg)
	site.s.applyChallenge(cfg)
	if site.s.gwChallenge.Load() != nil {
		t.Fatal("Ephor coupé : le défi doit l'être aussi")
	}
}

// Un 403 servi par un ban ne compte pas pour un Seuil : la requête est refusée avant le routage, donc avant toute observation.
func TestBannedClientRequestsDoNotCountForAThreshold(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "app", Host: "app.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}}
	s := newEphorGateway(t, t.TempDir(), route)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	s.threatEngine.UpdateConfig(threat.Config{Enabled: true, Mode: "block", Thresholds: threat.ThresholdsConfig{Mode: threat.ThresholdBlock}})
	const banned, other = "203.0.113.40", "203.0.113.41"
	s.banStore.Replace([]*router.RuntimeBan{{ID: "manuel", IP: banned, Source: "admin"}})

	login := func(ip string) int {
		req := httptest.NewRequest(http.MethodPost, "http://app.example.test/login", nil)
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		s.dispatch(rec, req)
		return rec.Code
	}
	for i := 0; i < 15; i++ {
		if code := login(banned); code != http.StatusForbidden {
			t.Fatalf("l'IP bannie est refusée : %d", code)
		}
	}
	if n := len(s.threatEngine.SnapshotState().Thresholds); n != 0 {
		t.Fatalf("les refus du ban ne comptent pas : %d compteur(s)", n)
	}
	if code := login(other); code != http.StatusUnauthorized {
		t.Fatalf("une IP non bannie atteint le backend : %d", code)
	}
	if n := len(s.threatEngine.SnapshotState().Thresholds); n == 0 {
		t.Fatal("l'échec d'une IP non bannie compte")
	}
}
