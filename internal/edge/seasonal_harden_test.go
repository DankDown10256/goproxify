// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/threat"
)

// attackedSite : une route qui a appris 5 req/s, puis reçoit un flot de 500 req/s depuis 4 000 adresses sur un seul chemin.
func attackedSite(t *testing.T, seasonalMode string) (*challengeSite, time.Time) {
	t.Helper()
	site := newChallengeSite(t, threat.ChallengeDetect, nil)
	cfg := threat.Config{
		Enabled:   true,
		Mode:      "block",
		IPScore:   threat.IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: threat.Duration{Duration: time.Hour}},
		Challenge: threat.ChallengeConfig{Mode: threat.ChallengeDetect, Threshold: 2, Difficulty: 8, Secret: "secret-de-test"},
		Whitelist: threat.Whitelist{IPs: []string{"198.51.100.7"}},
		Seasonal:  threat.SeasonalConfig{Mode: seasonalMode, MinHours: 0.1},
	}
	site.s.threatEngine.UpdateConfig(cfg)
	site.s.applyChallenge(cfg)

	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	for tick := 0; tick < 40; tick++ {
		for i := 0; i < 50; i++ {
			site.do(fmt.Sprintf("192.0.2.%d", i%30+1), "GET", fmt.Sprintf("/p%d", i%20), "application/json", "")
		}
		at = at.Add(10 * time.Second)
		site.s.threatEngine.SeasonalTick(at)
	}
	return site, flood(site, at, 3, 10)
}

// flood joue ticks tranches de 5 000 requêtes depuis des adresses toutes différentes, sur un seul chemin.
func flood(site *challengeSite, at time.Time, ticks, firstOctet int) time.Time {
	for tick := 0; tick < ticks; tick++ {
		for i := 0; i < 5000; i++ {
			site.do(fmt.Sprintf("%d.%d.%d.%d", firstOctet, tick, (i/250)%250, i%250+1), "GET", "/flood", "application/json", "")
		}
		at = at.Add(10 * time.Second)
		site.s.threatEngine.SeasonalTick(at)
	}
	return at
}

func TestProbableAttackHardensAnAttackedRouteInBlockMode(t *testing.T) {
	site, _ := attackedSite(t, threat.SeasonalBlock)
	if active := site.s.threatEngine.SeasonalActive(); len(active) != 1 || active[0].Level != "probable" || !active[0].Hardened {
		t.Fatalf("prérequis : la route doit être en attaque probable et durcie : %+v", active)
	}

	// Une IP sans historique qui navigue reçoit le défi, sans toucher le backend.
	before := site.hits.Load()
	page := site.do("203.0.113.77", "GET", "/accueil", html, "")
	if !strings.Contains(page.Body.String(), "Checking your browser") || site.hits.Load() != before {
		t.Fatalf("une navigation sans historique doit recevoir le défi : %d %q", page.Code, page.Body.String())
	}

	// La liste blanche d'Ephor passe comme d'ordinaire.
	if rec := site.do("198.51.100.7", "GET", "/accueil", html, ""); rec.Code != http.StatusOK || site.hits.Load() != before+1 {
		t.Fatalf("une IP en liste blanche n'est pas durcie : %d", rec.Code)
	}

	// Un client d'API ne peut pas porter un défi : il partage le plafond des IP sans historique, que le flot a déjà vidé.
	shed := 0
	for i := 0; i < 200; i++ {
		if site.do(fmt.Sprintf("203.0.113.%d", 100+i%100), "GET", "/data", "application/json", "").Code == http.StatusServiceUnavailable {
			shed++
		}
	}
	if shed < 150 {
		t.Fatalf("le plafond doit refuser les clients d'API sans historique : %d refusés sur 200", shed)
	}
}

func TestDetectModeNeverHardens(t *testing.T) {
	site, _ := attackedSite(t, threat.SeasonalDetect)
	if active := site.s.threatEngine.SeasonalActive(); len(active) != 1 || active[0].Hardened {
		t.Fatalf("en detect la route est signalée, jamais durcie : %+v", active)
	}
	before := site.hits.Load()
	for i := 0; i < 100; i++ {
		if rec := site.do(fmt.Sprintf("203.0.113.%d", 100+i%100), "GET", "/data", "application/json", ""); rec.Code != http.StatusOK {
			t.Fatalf("detect ne refuse rien : %d", rec.Code)
		}
	}
	if site.hits.Load() != before+100 {
		t.Fatal("tout doit atteindre le backend")
	}
	if page := site.do("203.0.113.77", "GET", "/accueil", html, ""); strings.Contains(page.Body.String(), "Checking your browser") {
		t.Fatal("aucun défi en detect")
	}
}

func TestHardenedRouteIsNotReleasedWhileTheFloodIsStillShed(t *testing.T) {
	site, at := attackedSite(t, threat.SeasonalBlock)
	flood(site, at, 3, 11)
	if active := site.s.threatEngine.SeasonalActive(); len(active) != 1 || !active[0].Hardened {
		t.Fatalf("le volume écarté par le plafond doit rester compté : l'alerte ne se croit pas finie et la route reste durcie : %+v", active)
	}
}
