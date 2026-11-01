// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// challengeEngine : score cumulé (ban à 6, défi à 3) et un chemin de liste qui pèse 2.
func challengeEngine(t *testing.T, mode string, extra ...func(*Config)) *Engine {
	t.Helper()
	cfg := Config{
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 6, HalfLife: Duration{time.Hour}},
		Challenge:   ChallengeConfig{Mode: mode, Threshold: 3},
	}
	for _, f := range extra {
		f(&cfg)
	}
	e, _, _ := explainEngine(t, cfg)
	return e
}

func touch(e *Engine, ip, path string) {
	e.Check(httptest.NewRequest("GET", path, nil), ip)
}

func due(e *Engine, ip string) bool {
	return e.ChallengeDue(httptest.NewRequest("GET", "/page", nil), ip)
}

func TestChallengeDueOnceTheNoteReachesTheThreshold(t *testing.T) {
	e := challengeEngine(t, ChallengeBlock)
	const ip = "198.51.100.1"
	if due(e, ip) {
		t.Fatal("une IP sans note ne reçoit pas de défi")
	}
	touch(e, ip, "/wp-admin/a") // 2 points
	if due(e, ip) {
		t.Fatal("2 points, seuil à 3 : pas encore de défi")
	}
	touch(e, ip, "/wp-admin/b") // 4 points : au-dessus du défi, sous le ban (6)
	if !due(e, ip) {
		t.Fatal("4 points, seuil à 3 : l'IP doit recevoir le défi")
	}
	if due(e, "198.51.100.2") {
		t.Fatal("le défi ne vise que l'IP dont la note a monté")
	}
}

func TestChallengeDetectOnlyCounts(t *testing.T) {
	e := challengeEngine(t, ChallengeDetect)
	const ip = "198.51.100.1"
	touch(e, ip, "/wp-admin/a")
	touch(e, ip, "/wp-admin/b")
	before := testutil.ToFloat64(threatChallengeTotal.WithLabelValues("shadow"))
	if due(e, ip) {
		t.Fatal("en detect le défi n'est jamais imposé")
	}
	if got := testutil.ToFloat64(threatChallengeTotal.WithLabelValues("shadow")); got != before+1 {
		t.Fatalf("défi fantôme compté %v fois, attendu %v", got, before+1)
	}
}

func TestChallengeOffNeverDue(t *testing.T) {
	e := challengeEngine(t, "")
	touch(e, "198.51.100.1", "/wp-admin/a")
	touch(e, "198.51.100.1", "/wp-admin/b")
	if due(e, "198.51.100.1") {
		t.Fatal("défi off par défaut")
	}
}

func TestChallengeSkipsWhitelistedClients(t *testing.T) {
	e := challengeEngine(t, ChallengeBlock, func(c *Config) {
		c.Whitelist = Whitelist{IPs: []string{"198.51.100.1"}, UAs: []string{"supervision"}, Paths: []string{"/health"}}
	})
	touch(e, "198.51.100.1", "/wp-admin/a")
	touch(e, "198.51.100.1", "/wp-admin/b")
	touch(e, "198.51.100.3", "/wp-admin/a")
	touch(e, "198.51.100.3", "/wp-admin/b")
	if due(e, "198.51.100.1") {
		t.Fatal("une IP en liste blanche n'est jamais défiée")
	}
	r := httptest.NewRequest("GET", "/page", nil)
	r.Header.Set("User-Agent", "supervision/1.0")
	if e.ChallengeDue(r, "198.51.100.3") {
		t.Fatal("un User-Agent en liste blanche n'est jamais défié")
	}
	if e.ChallengeDue(httptest.NewRequest("GET", "/health", nil), "198.51.100.3") {
		t.Fatal("un chemin en liste blanche n'est jamais défié")
	}
}

func TestChallengeDefaultThresholdIsHalfTheBanThreshold(t *testing.T) {
	e := challengeEngine(t, ChallengeBlock, func(c *Config) { c.Challenge.Threshold = 0 })
	if got := e.Challenge().Threshold; got != 3 {
		t.Fatalf("seuil par défaut %v, attendu la moitié du seuil de ban (3)", got)
	}
}

func TestChallengeCountsSignalsInBlockModeAndShadowsTheOthers(t *testing.T) {
	cfg := func(c *Config) {
		c.Challenge.Threshold = 3
		c.Behavior = BehaviorConfig{Signals: map[string]string{behavior.SignalPathScanning: BehaviorBlock}}
	}
	e, now, _, _ := noteEngine(t, BehaviorConfig{Signals: map[string]string{behavior.SignalPathScanning: BehaviorBlock}})
	c := e.cfg
	cfg(&c)
	c.Challenge.Mode = ChallengeBlock
	e.UpdateConfig(c)
	scan(e, now, "198.51.100.9", 200) // 3 points de balayage de chemins, sous le ban (6)
	if !due(e, "198.51.100.9") {
		t.Fatal("la note de comportement doit compter pour le défi")
	}
}

func TestValidateChallenge(t *testing.T) {
	ok := Config{IPScore: IPScoreConfig{Enabled: true, BanThreshold: 6}, Challenge: ChallengeConfig{Mode: ChallengeBlock, Threshold: 3, Difficulty: 12, TTL: Duration{time.Hour}, ExemptPaths: []string{"/api/"}}}
	if err := ok.ValidateChallenge(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	for what, mut := range map[string]func(*Config){
		"mode inconnu":           func(c *Config) { c.Challenge.Mode = "bloque" },
		"score cumulé absent":    func(c *Config) { c.IPScore.Enabled = false },
		"seuil au-dessus du ban": func(c *Config) { c.Challenge.Threshold = 6 },
		"seuil négatif":          func(c *Config) { c.Challenge.Threshold = -1 },
		"difficulté trop haute":  func(c *Config) { c.Challenge.Difficulty = 30 },
		"durée trop courte":      func(c *Config) { c.Challenge.TTL = Duration{time.Second} },
		"chemin sans barre":      func(c *Config) { c.Challenge.ExemptPaths = []string{"api"} },
	} {
		c := ok
		mut(&c)
		if err := c.ValidateChallenge(); err == nil {
			t.Errorf("%s : la configuration devait être refusée", what)
		} else if !strings.Contains(err.Error(), "challenge") {
			t.Errorf("%s : erreur sans le nom du réglage : %v", what, err)
		}
	}
	off := Config{Challenge: ChallengeConfig{Mode: ChallengeOff}}
	if err := off.ValidateChallenge(); err != nil {
		t.Fatalf("défi off sans score cumulé : %v", err)
	}
}
