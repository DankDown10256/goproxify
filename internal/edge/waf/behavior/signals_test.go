// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClockStore(window time.Duration) (*Store, *clock) {
	c := &clock{t: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)}
	s := newStore(window)
	s.SetClock(c.now)
	return s, c
}

func find(signals []Signal, name string) (Signal, bool) {
	for _, s := range signals {
		if s.Name == name {
			return s, true
		}
	}
	return Signal{}, false
}

const (
	chromeUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	chromeJA4  = "t13d1516h2_8daaf6152771_02713d6af862"
	pythonJA4  = "t13d1812h1_a09f3c656075_14788d8d241b"
	firefoxUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
	iosChrome  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.153 Mobile/15E148 Safari/604.1"
	scriptNote = "les signaux nés avec l'ADR 0011 ne comptent pas dans le score du WAF"
)

func TestUATLSMismatchNeedsAKnownFamilyAndAMismatchingFingerprint(t *testing.T) {
	cases := []struct {
		name, ua, ja4 string
		want          bool
	}{
		{"Chrome annoncé, suites d'un client Python", chromeUA, pythonJA4, true},
		{"Chrome annoncé, vraies suites de Chrome", chromeUA, chromeJA4, false},
		{"Firefox : famille absente de la table, jamais évalué", firefoxUA, pythonJA4, false},
		{"Chrome sur iOS (pile Apple) : jamais évalué", iosChrome, pythonJA4, false},
		{"HTTP clair ou QUIC : pas d'empreinte exploitable", chromeUA, "q13d0310h3_55b375c5d22e_cd85d2d88918", false},
		{"pas d'empreinte", chromeUA, "", false},
	}
	for _, c := range cases {
		s, clk := newClockStore(time.Minute)
		var sig []Signal
		for i := 0; i < 4; i++ {
			_, sig = s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: c.ua, TLS: c.ja4})
		}
		got, ok := find(sig, SignalUATLSMismatch)
		if ok != c.want {
			t.Errorf("%s : signal=%v, attendu %v", c.name, ok, c.want)
		}
		if ok && !got.Detect {
			t.Errorf("%s : un signal neuf naît en detect", c.name)
		}
	}
}

func TestTLSTableCanBeExtendedByTheAdministrator(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetTLSFamilies(map[string][]string{"chromium": {"A09F3C656075"}}) // ce client-là est de confiance
	var sig []Signal
	for i := 0; i < 4; i++ {
		_, sig = s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: chromeUA, TLS: pythonJA4})
	}
	if _, ok := find(sig, SignalUATLSMismatch); ok {
		t.Fatal("une empreinte ajoutée à la famille ne doit plus être un décalage")
	}
}

func TestNewSignalsDoNotCountInTheWAFScore(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	var score int
	var sig []Signal
	for i := 0; i < 4; i++ {
		score, sig = s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: chromeUA, TLS: pythonJA4})
	}
	if _, ok := find(sig, SignalUATLSMismatch); !ok || score != 0 {
		t.Fatalf("%s : score=%d signaux=%+v", scriptNote, score, sig)
	}
}

func TestNoAssets(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	var sig []Signal
	for i := 0; i < minPagesNoAssets; i++ {
		clk.t = clk.t.Add(600 * time.Millisecond * time.Duration(1+i%2)) // intervalles irréguliers
		_, sig = s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: fmt.Sprintf("/p%d", i%7), UA: "bot", Page: true})
	}
	if _, ok := find(sig, SignalNoAssets); !ok {
		t.Fatalf("25 pages sans aucune image, feuille de style ni script : %+v", sig)
	}

	s2, clk2 := newClockStore(time.Minute)
	for i := 0; i < minPagesNoAssets; i++ {
		clk2.t = clk2.t.Add(time.Second)
		s2.Record("203.0.113.6", Event{At: clk2.t, Status: 200, Method: "GET", Path: fmt.Sprintf("/p%d", i), UA: "browser", Page: true})
		if i == 3 {
			s2.Record("203.0.113.6", Event{At: clk2.t, Status: 200, Method: "GET", Path: "/app.js", UA: "browser", Asset: true})
		}
	}
	if _, ok := find(s2.Signals("203.0.113.6"), SignalNoAssets); ok {
		t.Fatal("un script chargé suffit : c'est un navigateur")
	}
}

func TestRegularInterval(t *testing.T) {
	run := func(step func(i int) time.Duration) []Signal {
		s, clk := newClockStore(2 * time.Minute)
		var sig []Signal
		for i := 0; i < 20; i++ {
			clk.t = clk.t.Add(step(i))
			_, sig = s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: fmt.Sprintf("/p%d", i%3), UA: "poller"})
		}
		return sig
	}
	if _, ok := find(run(func(int) time.Duration { return 2 * time.Second }), SignalRegularInterval); !ok {
		t.Error("une requête toutes les 2 s, exactement, est un script")
	}
	jitter := []time.Duration{900, 3100, 1500, 4200, 700, 2600}
	if _, ok := find(run(func(i int) time.Duration { return jitter[i%len(jitter)] * time.Millisecond }), SignalRegularInterval); ok {
		t.Error("un rythme irrégulier est celui d'une personne")
	}
	if _, ok := find(run(func(int) time.Duration { return 20 * time.Millisecond }), SignalRegularInterval); ok {
		t.Error("plus rapide que 100 ms, c'est une rafale, pas une cadence")
	}
}

func TestScanBreadth(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	var sig []Signal
	for i := 0; i < 20; i++ {
		clk.t = clk.t.Add(time.Duration(300+37*i) * time.Millisecond)
		status := 404
		if i%4 == 0 {
			status = 200
		}
		_, sig = s.Record("203.0.113.5", Event{At: clk.t, Status: status, Method: "GET", Path: fmt.Sprintf("/probe-%d", i), UA: "scanner"})
	}
	if got, ok := find(sig, SignalScanBreadth); !ok || !got.Detect {
		t.Fatalf("15 chemins distincts en erreur sur 20 requêtes : %+v", sig)
	}

	// Une même page introuvable demandée cent fois n'est pas un balayage.
	s2, clk2 := newClockStore(time.Minute)
	for i := 0; i < 20; i++ {
		clk2.t = clk2.t.Add(time.Duration(300+37*i) * time.Millisecond)
		s2.Record("203.0.113.6", Event{At: clk2.t, Status: 404, Method: "GET", Path: "/favicon.ico", UA: "browser"})
	}
	if _, ok := find(s2.Signals("203.0.113.6"), SignalScanBreadth); ok {
		t.Fatal("un seul chemin répété ne fait pas un balayage")
	}
}

func TestASNAggregateCatchesTheSlowDistributedAttack(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.SetASNLookup(func(ip string) uint32 {
		if len(ip) > 7 && ip[:7] == "198.51." {
			return 64500
		}
		return 0
	})
	// Dix adresses du même ASN, chacune dans son /24, échouent quatre fois en quelques minutes : chaque adresse reste très en
	// dessous de tous les seuils individuels, et aucun /24 ne voit de scan distribué.
	for round := 0; round < 4; round++ {
		for i := 1; i <= 10; i++ {
			clk.t = clk.t.Add(2 * time.Second)
			s.Record(fmt.Sprintf("198.51.%d.7", i), Event{At: clk.t, Status: 404, Method: "GET", Path: fmt.Sprintf("/x%d", round), UA: "ua"})
		}
	}
	sig := s.Signals("198.51.3.7")
	if got, ok := find(sig, SignalASNAggregate); !ok || !got.Detect {
		t.Fatalf("dix IP d'un même ASN, 40 requêtes dont 100 %% en erreur : %+v", sig)
	}
	if score, _ := s.Score("198.51.3.7"); score != 0 {
		t.Fatalf("%s : score=%d", scriptNote, score)
	}

	// Sans base ASN, ou pour un ASN dont le trafic va bien, rien.
	s2, clk2 := newClockStore(time.Minute)
	s2.SetASNLookup(func(string) uint32 { return 64501 })
	for round := 0; round < 4; round++ {
		for i := 1; i <= 10; i++ {
			clk2.t = clk2.t.Add(2 * time.Second)
			s2.Record(fmt.Sprintf("192.0.2.%d", i), Event{At: clk2.t, Status: 200, Method: "GET", Path: "/", UA: "ua"})
		}
	}
	if _, ok := find(s2.Signals("192.0.2.3"), SignalASNAggregate); ok {
		t.Fatal("un ASN dont le trafic réussit n'est pas une attaque")
	}
}

func TestSubnetStillCatchesADistributedScan(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	for i := 1; i <= 12; i++ {
		clk.t = clk.t.Add(time.Second)
		s.Record(fmt.Sprintf("203.0.113.%d", i), Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: "ua"})
	}
	if score, sig := s.Score("203.0.113.1"); score != 8 {
		t.Fatalf("douze IP du même /24 : score=%d signaux=%+v", score, sig)
	}
}

func TestHAMergeIsAMaximumAndIdempotent(t *testing.T) {
	a, clkA := newClockStore(time.Minute)
	b, clkB := newClockStore(time.Minute)
	for i := 0; i < 20; i++ {
		clkA.t = clkA.t.Add(time.Second)
		a.Record("203.0.113.5", Event{At: clkA.t, Status: 404, Method: "GET", Path: fmt.Sprintf("/scan/%d", i), UA: "bot"})
	}
	clkB.t = clkA.t
	payload := a.BuildHAPayload()
	own, _ := a.Score("203.0.113.5")
	if own == 0 {
		t.Fatal("la passerelle A doit avoir une note")
	}

	b.ApplyHAPayload(payload)
	b.ApplyHAPayload(payload) // rejouer ne change rien
	got, sig := b.Score("203.0.113.5")
	if got != own {
		t.Fatalf("note de B = %d, celle de A = %d (maximum, pas somme)", got, own)
	}
	if _, ok := find(sig, SignalHAPeer); !ok {
		t.Fatalf("la note d'un pair doit s'expliquer par le signal ha_peer : %+v", sig)
	}

	// B renvoie sa propre note : elle ne contient pas celle qu'il a reçue.
	back := b.BuildHAPayload()
	if e, ok := back.Entries["203.0.113.5"]; ok && e.Score != 0 {
		t.Fatalf("B ne doit pas réexporter la note reçue de A : %+v", e)
	}

	// Si B a déjà une note égale ou plus haute, rien ne s'ajoute.
	c, clkC := newClockStore(time.Minute)
	clkC.t = clkA.t
	for i := 0; i < 20; i++ {
		clkC.t = clkC.t.Add(time.Millisecond)
		c.Record("203.0.113.5", Event{At: clkC.t, Status: 404, Method: "GET", Path: fmt.Sprintf("/c/%d", i), UA: "bot"})
	}
	before, _ := c.Score("203.0.113.5")
	c.ApplyHAPayload(payload)
	if after, _ := c.Score("203.0.113.5"); after != before {
		t.Fatalf("note de C = %d après fusion, %d avant : le maximum ne doit rien ajouter", after, before)
	}
}

func TestPeerNoteExpiresWithTheEntry(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.ApplyHAPayload(HAPayload{Entries: map[string]HAEntry{"203.0.113.5": {Score: 7, ExpiresAt: clk.t.Add(30 * time.Second)}}})
	if score, _ := s.Score("203.0.113.5"); score != 7 {
		t.Fatalf("note = %d", score)
	}
	clk.t = clk.t.Add(time.Minute)
	if score, _ := s.Score("203.0.113.5"); score != 0 {
		t.Fatalf("note = %d après expiration", score)
	}
}

func TestExternalDecisionsAreDetectOnly(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	s.AddSignal("203.0.113.5", SignalCrowdSec, 5, clk.t.Add(time.Hour))
	score, sig := s.Score("203.0.113.5")
	if got, ok := find(sig, SignalCrowdSec); !ok || !got.Detect || score != 0 {
		t.Fatalf("une décision de CrowdSec est une entrée de la note d'Ephor, pas du WAF : score=%d %+v", score, sig)
	}
}

func TestMemoryIsBounded(t *testing.T) {
	s, clk := newClockStore(time.Hour)
	for i := 0; i < maxEventsPerProfile*3; i++ {
		clk.t = clk.t.Add(time.Millisecond)
		s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: fmt.Sprintf("/%d", i), UA: "ua"})
	}
	s.mu.RLock()
	p := s.profiles["203.0.113.5"]
	s.mu.RUnlock()
	if len(p.events) > maxEventsPerProfile {
		t.Fatalf("%d événements gardés, plafond %d", len(p.events), maxEventsPerProfile)
	}

	small := newStore(time.Hour)
	small.SetClock(clk.now)
	for i := 0; i < maxProfiles+50; i++ {
		small.Record(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: "ua"})
	}
	if n := small.Len(); n > maxProfiles {
		t.Fatalf("%d profils, plafond %d", n, maxProfiles)
	}
}

func TestTrustBonusGrowsWithACleanHistoryAndIsLostOnASignal(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	const ip = "203.0.113.5"
	for day := 0; day < 4; day++ {
		for i := 0; i < 60; i++ {
			clk.t = clk.t.Add(time.Minute)
			s.Record(ip, Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: "browser"})
		}
		clk.t = clk.t.Add(23 * time.Hour)
	}
	// 240 requêtes propres → 2 points, 3 jours d'histoire → 3 points
	if got := s.TrustBonus(ip); got != 5 {
		t.Fatalf("bonus = %d, attendu 5 (2 + 3)", got)
	}

	// Un 404 balayant 20 chemins coupe la confiance de moitié et repart l'historique.
	for i := 0; i < 20; i++ {
		clk.t = clk.t.Add(500 * time.Millisecond)
		s.Record(ip, Event{At: clk.t, Status: 404, Method: "GET", Path: fmt.Sprintf("/scan/%d", i), UA: "browser"})
	}
	if got := s.TrustBonus(ip); got >= 5 {
		t.Fatalf("bonus = %d après un balayage, la confiance doit baisser", got)
	}

	s.Forget(ip)
	if got := s.TrustBonus(ip); got != 0 {
		t.Fatalf("bonus = %d après effacement", got)
	}
}

func TestTrustIsForgottenAfterTheRetention(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	for i := 0; i < 200; i++ {
		clk.t = clk.t.Add(time.Second)
		s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: "browser"})
	}
	if s.TrustBonus("203.0.113.5") == 0 {
		t.Fatal("la confiance doit exister")
	}
	clk.t = clk.t.Add(trustRetention + time.Hour)
	s.gc()
	if got := s.TrustBonus("203.0.113.5"); got != 0 {
		t.Fatalf("bonus = %d après la rétention (vie privée)", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	s, clk := newClockStore(time.Minute)
	for i := 0; i < 200; i++ {
		clk.t = clk.t.Add(time.Second)
		s.Record("203.0.113.5", Event{At: clk.t, Status: 200, Method: "GET", Path: "/", UA: "browser", Route: "app.test"})
	}
	for i := 0; i < 20; i++ {
		clk.t = clk.t.Add(100 * time.Millisecond)
		s.Record("203.0.113.9", Event{At: clk.t, Status: 404, Method: "GET", Path: fmt.Sprintf("/s/%d", i), UA: "bot"})
	}
	st := s.ExportState()

	s2, clk2 := newClockStore(time.Minute)
	clk2.t = clk.t.Add(5 * time.Second)
	s2.ImportState(st)
	if got := s2.TrustBonus("203.0.113.5"); got == 0 {
		t.Fatal("l'historique propre doit survivre à un redémarrage")
	}
	if score, sig := s2.Score("203.0.113.9"); score == 0 {
		t.Fatalf("la note en cours doit survivre : %+v", sig)
	} else if _, ok := find(sig, SignalRestored); !ok {
		t.Fatalf("la note relue du disque s'explique par le signal restored : %+v", sig)
	}

	// Une copie ancienne se périme d'elle-même.
	s3, clk3 := newClockStore(time.Minute)
	clk3.t = clk.t.Add(trustRetention + time.Hour)
	s3.ImportState(st)
	if s3.TrustBonus("203.0.113.5") != 0 {
		t.Fatal("un historique plus vieux que la rétention ne revient pas")
	}
	if score, _ := s3.Score("203.0.113.9"); score != 0 {
		t.Fatal("une note expirée ne revient pas")
	}
}

func TestEventFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app.css", nil)
	req.Header.Set("Accept", "text/css,*/*")
	if ev := EventFromRequest(req, 200, 0, "app.test"); !ev.Asset || ev.Page {
		t.Errorf("une feuille de style est un asset : %+v", ev)
	}
	req = httptest.NewRequest(http.MethodGet, "/produits", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if ev := EventFromRequest(req, 200, 0, "app.test"); ev.Asset || !ev.Page {
		t.Errorf("une navigation est une page : %+v", ev)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("Accept", "application/json")
	if ev := EventFromRequest(req, 200, 0, "app.test"); ev.Asset || ev.Page {
		t.Errorf("un appel d'API n'est ni l'un ni l'autre : %+v", ev)
	}
	req = httptest.NewRequest(http.MethodGet, "/img", nil)
	req.Header.Set("Sec-Fetch-Dest", "image")
	if ev := EventFromRequest(req, 200, 0, ""); !ev.Asset {
		t.Errorf("Sec-Fetch-Dest: image : %+v", ev)
	}
}

func TestObservationIsSharedAlongTheRequest(t *testing.T) {
	ctx, obs := WithObservation(httptest.NewRequest("GET", "/", nil).Context())
	ObservationFrom(ctx).NoteWAFScore(7)
	ObservationFrom(ctx).MarkRecorded()
	if obs.WAFScore() != 7 || !obs.Recorded() {
		t.Fatalf("%+v", obs)
	}
	var none *Observation
	none.NoteWAFScore(3) // sans observation (tests, appels hors passerelle) : sans effet
	none.MarkRecorded()
	if none.WAFScore() != 0 || none.Recorded() {
		t.Fatal("une observation absente ne retient rien")
	}
}

func BenchmarkRecordCleanTraffic(b *testing.B) {
	s := newStore(time.Minute)
	ev := Event{Status: 200, Method: "GET", Path: "/index.html", UA: chromeUA, TLS: chromeJA4, Page: true, Route: "app.test"}
	ips := make([]string, 1024)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.0.%d.%d", i>>8, i&255)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.At = time.Now()
		s.Record(ips[i&1023], ev)
	}
}

func BenchmarkScoreCached(b *testing.B) {
	s := newStore(time.Minute)
	for i := 0; i < 50; i++ {
		s.Record("10.0.0.1", Event{At: time.Now(), Status: 200, Method: "GET", Path: fmt.Sprintf("/%d", i), UA: "ua"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Signals("10.0.0.1")
	}
}

// Le magasin est partagé par toutes les requêtes de la passerelle, le WAF, Ephor, la synchronisation HA et la persistance :
// sous le détecteur de courses (WSL), rien ne doit se chevaucher.
func TestConcurrentUse(t *testing.T) {
	s := newStore(time.Minute)
	s.SetASNLookup(func(ip string) uint32 { return 64500 })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 600; i++ {
				ip := fmt.Sprintf("10.%d.%d.1", g, i%40)
				s.Record(ip, Event{Status: 200 + 204*(i%2), Method: "GET", Path: fmt.Sprintf("/p%d", i%30), UA: "ua", Route: "api.test", Page: i%3 == 0})
				s.Signals(ip)
				s.TrustBonus(ip)
				if i%97 == 0 {
					s.DeleteProfile(ip)
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.ApplyHAPayload(s.BuildHAPayload())
				s.Profiles()
				s.References()
				st := s.ExportState()
				s.ImportState(st)
				s.AddSignal("10.0.0.9", SignalCrowdSec, 5, time.Now().Add(time.Minute))
				s.gc()
			}
		}
	}()
	// Les écrivains terminés, on arrête le lecteur.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	<-done
}
