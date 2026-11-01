// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// noteEngine : un moteur avec score cumulé et un magasin comportemental sur la même horloge.
func noteEngine(t *testing.T, bc BehaviorConfig) (*Engine, *time.Time, *behavior.Store, *[]explained) {
	t.Helper()
	e, now, bans := explainEngine(t, Config{
		CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}},
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 6, HalfLife: Duration{time.Hour}},
		Behavior:    bc,
	})
	st := behavior.NewStore(time.Minute)
	st.SetClock(func() time.Time { return *now })
	e.SetBehaviorStore(st)
	return e, now, st, bans
}

// scan fait balayer vingt chemins valides ou introuvables par l'IP : high_4xx_rate (4) et path_scanning (3) sans aucun
// signal de liste.
func scan(e *Engine, now *time.Time, ip string, status int) {
	for i := 0; i < 20; i++ {
		*now = now.Add(700 * time.Millisecond)
		r := httptest.NewRequest("GET", fmt.Sprintf("/page-%d", i), nil)
		e.Check(r, ip)
		e.Observe(r, ip, "app.test", status)
	}
}

func TestBehaviorSignalsStartInDetectAndNeverBan(t *testing.T) {
	e, now, _, bans := noteEngine(t, BehaviorConfig{})
	scan(e, now, "198.51.100.1", 404)
	e.Check(httptest.NewRequest("GET", "/ok", nil), "198.51.100.1")
	if len(*bans) != 0 {
		t.Fatalf("un signal neuf naît en detect, il ne bannit pas : %+v", *bans)
	}
}

func TestBehaviorSignalInBlockModeCountsInTheCommonNote(t *testing.T) {
	e, now, _, bans := noteEngine(t, BehaviorConfig{Signals: map[string]string{
		behavior.SignalHigh4xxRate: BehaviorBlock, behavior.SignalPathScanning: BehaviorBlock,
	}})
	scan(e, now, "198.51.100.1", 404)
	if len(*bans) != 1 || (*bans)[0].reason != "threat: score cumulé" {
		t.Fatalf("un seul ban, sur la note commune : %+v", *bans)
	}
	got := map[string]float64{}
	for _, s := range (*bans)[0].signals {
		got[s.Name] = s.Points
	}
	if got[behavior.SignalHigh4xxRate] != 4 || got[behavior.SignalPathScanning] != 3 {
		t.Fatalf("le ban doit expliquer chaque signal de comportement avec ses points : %+v", (*bans)[0].signals)
	}
}

func TestBehaviorAddsToTheListSignalsInOneNote(t *testing.T) {
	e, now, _, bans := noteEngine(t, BehaviorConfig{Signals: map[string]string{behavior.SignalPathScanning: BehaviorBlock}})
	// 3 points de balayage de chemins (path_scanning), puis deux passages sur un chemin de liste (2 + 2 = 4) : 7 ≥ 6.
	scan(e, now, "198.51.100.1", 200)
	if len(*bans) != 0 {
		t.Fatalf("3 points seulement : %+v", *bans)
	}
	e.Check(httptest.NewRequest("GET", "/wp-admin/a", nil), "198.51.100.1")
	e.Check(httptest.NewRequest("GET", "/wp-admin/b", nil), "198.51.100.1")
	if len(*bans) != 1 {
		t.Fatalf("score de liste + comportement : %+v", *bans)
	}
	names := map[string]bool{}
	for _, s := range (*bans)[0].signals {
		names[s.Name] = true
	}
	if !names["custom_path"] || !names[behavior.SignalPathScanning] {
		t.Fatalf("une seule note, tous les signaux dans l'explication : %+v", (*bans)[0].signals)
	}
}

func TestOffSignalIsIgnored(t *testing.T) {
	e, now, _, bans := noteEngine(t, BehaviorConfig{Mode: BehaviorBlock, Signals: map[string]string{
		behavior.SignalHigh4xxRate: BehaviorOff, behavior.SignalPathScanning: BehaviorOff,
	}})
	scan(e, now, "198.51.100.1", 404)
	e.Check(httptest.NewRequest("GET", "/ok", nil), "198.51.100.1")
	if len(*bans) != 0 {
		t.Fatalf("des signaux en off ne comptent pas : %+v", *bans)
	}
}

func TestDetectModeNeverBansEvenWhenTheNoteCrossesTheThreshold(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var bans []explained
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(ip, reason string, _ time.Time, signals []router.BanSignal) {
		bans = append(bans, explained{ip, reason, signals})
	})
	e.counters.now = func() time.Time { return now }
	e.UpdateConfig(Config{
		Enabled: true, Mode: "detect",
		IPScore:  IPScoreConfig{Enabled: true, BanThreshold: 6, HalfLife: Duration{time.Hour}},
		Behavior: BehaviorConfig{Mode: BehaviorBlock},
	})
	st := behavior.NewStore(time.Minute)
	st.SetClock(func() time.Time { return now })
	e.SetBehaviorStore(st)
	scan(e, &now, "198.51.100.1", 404)
	e.Check(httptest.NewRequest("GET", "/ok", nil), "198.51.100.1")
	if len(bans) != 0 {
		t.Fatalf("en mode detect, la note est calculée mais ne bannit pas : %+v", bans)
	}
}

func TestColdReferenceNeverCountsWhateverItsMode(t *testing.T) {
	e, now, st, bans := noteEngine(t, BehaviorConfig{Signals: map[string]string{behavior.SignalRateDeviation: BehaviorBlock}})
	e.cfg.IPScore.BanThreshold = 3
	// Douze minutes de trafic normal sur la route, puis une IP à 60 requêtes par minute : l'écart est vu, mais la référence
	// (douze minutes, route observée depuis moins de 24 h) n'est pas fiable.
	for m := 0; m < 12; m++ {
		for i := 1; i <= 15; i++ {
			for r := 0; r < 4; r++ {
				st.Record(fmt.Sprintf("10.0.%d.%d", i, m), behavior.Event{At: now.Add(time.Duration(i*397+r*4793) % time.Minute), Status: 200, Method: "GET", Path: fmt.Sprintf("/api/%d", (i+r)%5), UA: "ua", Route: "api.test"})
			}
		}
		*now = now.Add(time.Minute)
	}
	for i := 0; i < 60; i++ {
		st.Record("198.51.100.1", behavior.Event{At: now.Add(time.Duration(i) * 900 * time.Millisecond), Status: 200, Method: "GET", Path: fmt.Sprintf("/api/%d", (i*7)%5), UA: "ua", Route: "api.test"})
	}
	*now = now.Add(55 * time.Second)
	sig := st.Signals("198.51.100.1")
	var dev behavior.Signal
	for _, s := range sig {
		if s.Name == behavior.SignalRateDeviation {
			dev = s
		}
	}
	if !dev.Cold {
		t.Fatalf("contrôle : le signal doit être froid : %+v", sig)
	}
	e.Check(httptest.NewRequest("GET", "/ok", nil), "198.51.100.1")
	if len(*bans) != 0 {
		t.Fatalf("un signal froid ne compte jamais, même en block : %+v", *bans)
	}
}

func TestTrustBonusRaisesTheBanThreshold(t *testing.T) {
	cfg := BehaviorConfig{Signals: map[string]string{behavior.SignalPathScanning: BehaviorBlock}}
	e, now, st, bans := noteEngine(t, cfg)
	// Une longue histoire propre : 500 requêtes, donc +5 au seuil de 6.
	for i := 0; i < 500; i++ {
		*now = now.Add(2 * time.Second)
		st.Record("198.51.100.1", behavior.Event{At: *now, Status: 200, Method: "GET", Path: "/", UA: "browser"})
	}
	if st.TrustBonus("198.51.100.1") < 5 {
		t.Fatalf("bonus = %d", st.TrustBonus("198.51.100.1"))
	}
	scan(e, now, "198.51.100.1", 200)
	e.Check(httptest.NewRequest("GET", "/wp-admin/a", nil), "198.51.100.1")
	e.Check(httptest.NewRequest("GET", "/wp-admin/b", nil), "198.51.100.1")
	if len(*bans) != 0 {
		t.Fatalf("7 points contre un seuil relevé à 11 : %+v", *bans)
	}

	// Sans bonus, le même comportement banni.
	cfg.NoTrust = true
	e2, now2, st2, bans2 := noteEngine(t, cfg)
	for i := 0; i < 500; i++ {
		*now2 = now2.Add(2 * time.Second)
		st2.Record("198.51.100.1", behavior.Event{At: *now2, Status: 200, Method: "GET", Path: "/", UA: "browser"})
	}
	scan(e2, now2, "198.51.100.1", 200)
	e2.Check(httptest.NewRequest("GET", "/wp-admin/a", nil), "198.51.100.1")
	e2.Check(httptest.NewRequest("GET", "/wp-admin/b", nil), "198.51.100.1")
	if len(*bans2) != 1 {
		t.Fatalf("no_trust coupe le bonus : %+v", *bans2)
	}
}

func TestObserveFeedsTheStoreOnceAndSkipsWhatTheWAFAlreadyRecorded(t *testing.T) {
	e, now, st, _ := noteEngine(t, BehaviorConfig{})
	r := httptest.NewRequest("GET", "/a", nil)
	e.Observe(r, "198.51.100.1", "app.test", 200)
	if st.Len() != 1 {
		t.Fatalf("profils : %d", st.Len())
	}

	ctx, obs := behavior.WithObservation(httptest.NewRequest("GET", "/b", nil).Context())
	r2 := httptest.NewRequest("GET", "/b", nil).WithContext(ctx)
	obs.MarkRecorded()
	e.Observe(r2, "198.51.100.2", "app.test", 200)
	if st.Len() != 1 {
		t.Fatalf("le WAF avait déjà versé la requête, Ephor ne doit pas la compter une seconde fois (profils : %d)", st.Len())
	}
	_ = now
}

func TestObserveCarriesTheWAFScoreToTheStore(t *testing.T) {
	e, now, st, _ := noteEngine(t, BehaviorConfig{})
	for i := 0; i < 3; i++ {
		*now = now.Add(time.Second)
		ctx, obs := behavior.WithObservation(httptest.NewRequest("GET", "/", nil).Context())
		obs.NoteWAFScore(5) // le WAF a déclenché des règles sur ces requêtes, sans les enregistrer lui-même
		e.Observe(httptest.NewRequest("GET", "/?q=x", nil).WithContext(ctx), "198.51.100.1", "app.test", 403)
	}
	if score, sig := st.Score("198.51.100.1"); score == 0 {
		t.Fatalf("3 × 5 points WAF cumulés (waf_score_accumulation) : %+v", sig)
	}
}

func TestBehaviorOffFeedsNothing(t *testing.T) {
	e, _, st, _ := noteEngine(t, BehaviorConfig{Mode: BehaviorOff})
	e.Observe(httptest.NewRequest("GET", "/a", nil), "198.51.100.1", "app.test", 200)
	if st.Len() != 0 {
		t.Fatal("behavior.mode=off : Ephor ne verse plus rien")
	}
}

func TestExternalDecisionsEnterTheNote(t *testing.T) {
	e, now, st, _ := noteEngine(t, BehaviorConfig{})
	e.NoteDecision("198.51.100.1", behavior.SignalCrowdSec, 5, now.Add(time.Hour))
	if sig := st.Signals("198.51.100.1"); len(sig) != 1 || sig[0].Name != behavior.SignalCrowdSec {
		t.Fatalf("%+v", sig)
	}
}

func TestForgetIPClearsCountersAndBehavior(t *testing.T) {
	e, now, st, _ := noteEngine(t, BehaviorConfig{})
	for i := 0; i < 200; i++ {
		*now = now.Add(time.Second)
		st.Record("198.51.100.1", behavior.Event{At: *now, Status: 200, Method: "GET", Path: "/", UA: "browser"})
	}
	e.counters.addScore("198.51.100.1", time.Hour)
	e.ForgetIP("198.51.100.1")
	if st.TrustBonus("198.51.100.1") != 0 || st.Len() != 0 || e.counters.size() != 0 {
		t.Fatal("effacement RGPD : plus rien ne doit rester de l'IP")
	}
}
