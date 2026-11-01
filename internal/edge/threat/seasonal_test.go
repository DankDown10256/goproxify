// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/seasonal"
)

func seasonalEngine(mode string) *Engine {
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	e.UpdateConfig(Config{Enabled: true, Seasonal: SeasonalConfig{Mode: mode, MinHours: 0.1}})
	return e
}

func feedSeasonal(e *Engine, route string, rps, ticks int, at *time.Time) {
	for t := 0; t < ticks; t++ {
		for i := 0; i < rps*seasonal.BucketSeconds; i++ {
			r := httptest.NewRequest("GET", fmt.Sprintf("/p%d", i%20), nil)
			e.Observe(r, fmt.Sprintf("203.0.113.%d", i%200), route, 200)
		}
		*at = at.Add(seasonal.BucketSeconds * time.Second)
		e.seasonal.Tick(*at)
	}
}

func TestSeasonalOffRecordsNothing(t *testing.T) {
	e := seasonalEngine("")
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	feedSeasonal(e, "a.example", 5, 3, &at)
	if len(e.SeasonalStatus()) != 0 {
		t.Fatalf("mode off : aucune route suivie, %+v", e.SeasonalStatus())
	}
}

func TestSeasonalDetectsASpikeThroughObserve(t *testing.T) {
	e := seasonalEngine(SeasonalDetect)
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	feedSeasonal(e, "a.example", 5, 40, &at)
	feedSeasonal(e, "a.example", 500, 1, &at)
	ev := e.SeasonalEvents()
	if len(ev) == 0 || ev[0].Kind != "start" || ev[0].Route != "a.example" {
		t.Fatalf("un pic doit ouvrir une alerte : %+v", ev)
	}
	if len(e.SeasonalActive()) != 1 {
		t.Fatalf("l'alerte doit être active : %+v", e.SeasonalActive())
	}
}

func TestSeasonalReferenceSurvivesARestart(t *testing.T) {
	e := seasonalEngine(SeasonalDetect)
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	feedSeasonal(e, "a.example", 5, 40, &at)
	st := e.SnapshotState()
	if len(st.Seasonal) != 1 {
		t.Fatalf("la référence doit être dans l'état persisté : %+v", st.Seasonal)
	}

	e2 := seasonalEngine(SeasonalDetect)
	e2.RestoreState(st)
	feedSeasonal(e2, "a.example", 500, 1, &at)
	if len(e2.SeasonalEvents()) == 0 {
		t.Fatal("après un redémarrage, la référence relue doit servir sans nouvel apprentissage")
	}
}

func TestSeasonalUnknownHostFeedsTheEntryProfile(t *testing.T) {
	e := seasonalEngine(SeasonalDetect)
	for i := 0; i < 20; i++ {
		e.NoteUnknownHost("203.0.113.9", "x.invalid")
	}
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	e.seasonal.Tick(at.Add(seasonal.BucketSeconds * time.Second))
	found := false
	for _, s := range e.SeasonalStatus() {
		found = found || s.Route == seasonal.Entry
	}
	if !found {
		t.Fatalf("un hôte inconnu doit alimenter le profil d'entrée : %+v", e.SeasonalStatus())
	}
}

func TestValidateSeasonal(t *testing.T) {
	ok := []SeasonalConfig{{}, {Mode: "detect"}, {Mode: "DETECT", FloorRPS: 50, FastFactor: 5, SlowSigmas: 3, MinHours: 1}}
	for _, s := range ok {
		if err := (Config{Seasonal: s}).ValidateSeasonal(); err != nil {
			t.Errorf("%+v refusé : %v", s, err)
		}
	}
	blockOK := Config{Seasonal: SeasonalConfig{Mode: "block", CapFactor: 5}, Challenge: ChallengeConfig{Mode: "detect"}, IPScore: IPScoreConfig{Enabled: true}}
	if err := blockOK.ValidateSeasonal(); err != nil {
		t.Errorf("block avec un défi actif refusé : %v", err)
	}
	if err := (Config{Seasonal: SeasonalConfig{Mode: "block"}}).ValidateSeasonal(); err == nil {
		t.Error("block sans défi actif doit être refusé : le profil durci sert le défi")
	}
	bad := map[string]SeasonalConfig{
		"seasonal.cap_factor":  {CapFactor: 0.5},
		"seasonal.mode":        {Mode: "bloc"},
		"seasonal.floor_rps":   {FloorRPS: -1},
		"seasonal.fast_factor": {FastFactor: 1},
		"seasonal.slow_sigmas": {SlowSigmas: 0.5},
		"seasonal.min_hours":   {MinHours: 500},
	}
	for want, s := range bad {
		err := (Config{Seasonal: s}).ValidateSeasonal()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v : erreur attendue sur %s, reçu %v", s, want, err)
		}
	}
}

func TestSeasonalNotifiesOnChangeThenEveryMinuteAndAtTheEnd(t *testing.T) {
	e := seasonalEngine(SeasonalDetect)
	var sent [][]seasonal.Event
	e.SetSeasonalNotify(func(active []seasonal.Event) { sent = append(sent, active) })
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	step := func(rps, ticks int) {
		feedSeasonal(e, "a.example", rps, ticks, &at)
	}
	step(5, 40)
	e.notifySeasonal()
	if len(sent) != 0 {
		t.Fatalf("rien à dire sans alerte : %+v", sent)
	}
	step(500, 1)
	e.notifySeasonal()
	if len(sent) != 1 || len(sent[0]) != 1 || sent[0][0].Route != "a.example" {
		t.Fatalf("le début d'une alerte doit être annoncé aussitôt : %+v", sent)
	}
	e.notifySeasonal()
	if len(sent) != 1 {
		t.Fatalf("pas de répétition avant une minute : %d messages", len(sent))
	}
}

func TestSeasonalTellsTheAdminWhenAlertsEnd(t *testing.T) {
	e := seasonalEngine(SeasonalDetect)
	var sent [][]seasonal.Event
	e.SetSeasonalNotify(func(active []seasonal.Event) { sent = append(sent, active) })
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	feedSeasonal(e, "a.example", 5, 40, &at)
	feedSeasonal(e, "a.example", 500, 1, &at)
	e.notifySeasonal()
	feedSeasonal(e, "a.example", 5, 12, &at)
	e.notifySeasonal()
	if len(sent) != 2 || len(sent[1]) != 0 {
		t.Fatalf("la fin des alertes doit être annoncée par une liste vide : %+v", sent)
	}
}
