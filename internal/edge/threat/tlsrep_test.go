// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

const (
	toolJA4    = "t13d1010h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	browserJA4 = "t13d1516h2_8daaf6152771_02713d6af862"
)

func repEngine(t *testing.T, mut ...func(*Config)) *Engine {
	t.Helper()
	cfg := Config{TLSReputation: TLSReputationConfig{Enabled: true}}
	for _, m := range mut {
		m(&cfg)
	}
	e, _, _ := explainEngine(t, cfg)
	e.SetBehaviorStore(behavior.NewReplayStore(0))
	return e
}

// repHit rejoue une requête servie : empreinte, IP, statut, et si le WAF a marqué la requête.
func repHit(e *Engine, ja4, ip string, status int, waf bool) {
	r := httptest.NewRequest("GET", "/x", nil)
	ctx, obs := behavior.WithObservation(tlsfp.WithContext(context.Background(), &tlsfp.Fingerprint{JA4: ja4}))
	if waf {
		obs.NoteWAFScore(5)
	}
	e.Observe(r.WithContext(ctx), ip, "app.test", status)
}

func ipOf(i int) string { return fmt.Sprintf("10.%d.%d.%d", i/65025, (i/255)%255, i%255+1) }

func TestASharedAttackToolFingerprintIsProposedWithItsProof(t *testing.T) {
	e := repEngine(t)
	for i := 0; i < 400; i++ {
		repHit(e, toolJA4, ipOf(i%60), 403, i%3 == 0) // 60 IP, tout en erreur, un tiers marqué par le WAF
	}
	rep := e.TLSReputation()
	if !rep.Enabled || len(rep.Proposals) != 1 {
		t.Fatalf("une proposition attendue : %+v", rep)
	}
	p := rep.Proposals[0]
	if p.JA4 != toolJA4 || p.IPs < 55 || p.IPs > 65 || p.Requests != 400 || p.BadShare != 1 || p.WAFShare < 0.3 || p.WAFShare > 0.37 || p.ErrShare != 1 {
		t.Fatalf("les preuves doivent suivre : %+v", p)
	}
}

func TestBrowserStacksAreNeverProposed(t *testing.T) {
	e := repEngine(t)
	for i := 0; i < 2000; i++ {
		repHit(e, browserJA4, ipOf(i%300), 403, true)
	}
	rep := e.TLSReputation()
	if len(rep.Proposals) != 0 || rep.Browsers != 1 {
		t.Fatalf("une pile de navigateur connue n'est jamais proposée, même si ses requêtes sont toutes mauvaises : %+v", rep)
	}
}

func TestNothingIsProposedBelowTheThresholds(t *testing.T) {
	cases := map[string]func(e *Engine){
		"peu d'IP (un seul client très actif)": func(e *Engine) {
			for i := 0; i < 500; i++ {
				repHit(e, toolJA4, ipOf(i%3), 403, true)
			}
		},
		"peu de requêtes": func(e *Engine) {
			for i := 0; i < 50; i++ {
				repHit(e, toolJA4, ipOf(i), 403, true)
			}
		},
		"requêtes surtout bonnes": func(e *Engine) {
			for i := 0; i < 500; i++ {
				repHit(e, toolJA4, ipOf(i%80), 200, i%10 == 0)
			}
		},
		"application cassée : des erreurs, jamais le WAF": func(e *Engine) {
			for i := 0; i < 500; i++ {
				repHit(e, toolJA4, ipOf(i%80), 404, false)
			}
		},
	}
	for name, run := range cases {
		e := repEngine(t)
		run(e)
		if rep := e.TLSReputation(); len(rep.Proposals) != 0 {
			t.Errorf("%s : aucune proposition attendue, %+v", name, rep.Proposals)
		}
	}
}

func TestAlreadyListedFingerprintsAreNotProposedAgain(t *testing.T) {
	e := repEngine(t, func(c *Config) { c.CustomLists.TLSFingerprints = []string{"T13D1010H2_AAAAAAAAAAAA_BBBBBBBBBBBB"} })
	for i := 0; i < 400; i++ {
		repHit(e, toolJA4, ipOf(i%60), 403, true)
	}
	if rep := e.TLSReputation(); len(rep.Proposals) != 0 {
		t.Fatalf("déjà dans la liste personnalisée : %+v", rep.Proposals)
	}
}

func TestReputationIsOffByDefaultAndNeverBlocks(t *testing.T) {
	e, _, _ := explainEngine(t, Config{})
	for i := 0; i < 400; i++ {
		repHit(e, toolJA4, ipOf(i%60), 403, true)
	}
	if rep := e.TLSReputation(); rep.Enabled || rep.Tracked != 0 {
		t.Fatalf("désactivée : rien n'est suivi : %+v", rep)
	}
	e2 := repEngine(t)
	for i := 0; i < 400; i++ {
		r := httptest.NewRequest("GET", "/x", nil)
		ctx, _ := behavior.WithObservation(tlsfp.WithContext(context.Background(), &tlsfp.Fingerprint{JA4: toolJA4}))
		if blocked, _ := e2.Check(r.WithContext(ctx), ipOf(i%60)); blocked {
			t.Fatal("la réputation ne bloque jamais : elle propose")
		}
		e2.Observe(r.WithContext(ctx), ipOf(i%60), "app.test", 403)
	}
}

func TestReputationCountersSurviveARestartAndStayBounded(t *testing.T) {
	e := repEngine(t)
	for i := 0; i < 400; i++ {
		repHit(e, toolJA4, ipOf(i%60), 403, true)
	}
	st := e.SnapshotState()
	if len(st.TLSReputation) != 1 {
		t.Fatalf("la réputation est conservée avec l'état : %+v", st.TLSReputation)
	}
	e2 := repEngine(t)
	e2.RestoreState(st)
	if rep := e2.TLSReputation(); len(rep.Proposals) != 1 || rep.Proposals[0].IPs < 55 {
		t.Fatalf("après un redémarrage la proposition subsiste : %+v", rep)
	}

	b := repEngine(t)
	for i := 0; i < tlsRepShards*tlsRepShardCap*2; i++ {
		repHit(b, fmt.Sprintf("t13d%04dh2_x_y", i), "203.0.113.1", 200, false)
	}
	if rep := b.TLSReputation(); rep.Tracked > tlsRepShards*tlsRepShardCap {
		t.Fatalf("le suivi doit rester borné : %d empreintes", rep.Tracked)
	}
}

func TestValidateTLSReputation(t *testing.T) {
	if err := (Config{TLSReputation: TLSReputationConfig{Enabled: true, MinIPs: 30, MinRequests: 500, MinBadShare: 0.8}}).ValidateTLSReputation(); err != nil {
		t.Fatalf("réglage valide refusé : %v", err)
	}
	bad := map[string]TLSReputationConfig{
		"une seule IP":    {MinIPs: 1},
		"IP négatives":    {MinIPs: -3},
		"requêtes":        {MinRequests: -1},
		"part trop basse": {MinBadShare: 0.1},
		"part > 1":        {MinBadShare: 1.5},
	}
	for name, c := range bad {
		if (Config{TLSReputation: c}).ValidateTLSReputation() == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
}
