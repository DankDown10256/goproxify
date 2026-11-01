// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"testing"
	"time"
)

// seasonalHistory : une route calme (5 req/s depuis 30 adresses) pendant 50 minutes, puis deux minutes de flot (300 req/s depuis des
// adresses toutes différentes, sur un seul chemin). Tout tient dans le même créneau horaire.
func seasonalHistory() []SimEvent {
	start := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	var ev []SimEvent
	for tick := 0; tick < 300; tick++ {
		for i := 0; i < 50; i++ {
			ev = append(ev, SimEvent{Time: start.Add(time.Duration(tick)*10*time.Second + time.Duration(i)*100*time.Millisecond),
				IP: fmt.Sprintf("192.0.2.%d", i%30+1), Path: fmt.Sprintf("/p%d", i%20), Status: 200, Route: "app.example.fr"})
		}
	}
	flood := start.Add(50 * time.Minute)
	for tick := 0; tick < 12; tick++ {
		for i := 0; i < 3000; i++ {
			ev = append(ev, SimEvent{Time: flood.Add(time.Duration(tick)*10*time.Second + time.Duration(i)*3*time.Millisecond),
				IP: fmt.Sprintf("10.%d.%d.%d", tick, (i/250)%250, i%250+1), Path: "/flood", Status: 200, Route: "app.example.fr"})
		}
	}
	return ev
}

func TestSimulateReplaysTheSeasonalReference(t *testing.T) {
	cfg := Config{Seasonal: SeasonalConfig{Mode: SeasonalDetect, MinHours: 0.1}}
	rep := Simulate(cfg, seasonalHistory())
	s := rep.Seasonal
	if s == nil || s.Mode != SeasonalDetect || len(s.Routes) != 1 {
		t.Fatalf("la simulation doit rendre la part saisonnière : %+v", s)
	}
	r := s.Routes[0]
	if r.Route != "app.example.fr" || !r.Warm || r.Probables < 1 || r.AlertSeconds <= 0 {
		t.Fatalf("le flot doit être vu comme une attaque probable sur une route jugeable : %+v", r)
	}
	if r.HardenedRequests != 0 {
		t.Fatalf("en detect rien n'est durci : %+v", r)
	}
	if len(s.Events) == 0 || s.Events[0].Kind != "start" {
		t.Fatalf("les événements de la simulation : %+v", s.Events)
	}
}

func TestSimulateMeasuresWhatHardeningWouldHaveTouched(t *testing.T) {
	cfg := Config{Seasonal: SeasonalConfig{Mode: SeasonalBlock, MinHours: 0.1}}
	r := Simulate(cfg, seasonalHistory()).Seasonal.Routes[0]
	if r.HardenedRequests == 0 || r.HardenedServed == 0 || r.HardenedServed > r.HardenedRequests {
		t.Fatalf("en block la simulation compte les requêtes qu'un profil durci aurait touchées : %+v", r)
	}
}

func TestSimulateWithoutSeasonalReportsNothingAboutIt(t *testing.T) {
	if rep := Simulate(Config{}, seasonalHistory()); rep.Seasonal != nil {
		t.Fatalf("référence coupée : pas de rapport saisonnier : %+v", rep.Seasonal)
	}
}

func TestSimulateTooShortAWindowStaysCold(t *testing.T) {
	cfg := Config{Seasonal: SeasonalConfig{Mode: SeasonalDetect}} // deux heures d'historique exigées
	r := Simulate(cfg, seasonalHistory()).Seasonal.Routes[0]
	if r.Warm || r.Warnings != 0 || r.Probables != 0 {
		t.Fatalf("une fenêtre trop courte ne juge rien : %+v", r)
	}
}
