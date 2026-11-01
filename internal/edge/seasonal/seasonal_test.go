// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package seasonal

import (
	"fmt"
	"hash/maphash"
	"math"
	"sync"
	"testing"
	"time"
)

type rig struct {
	t      *testing.T
	tr     *Tracker
	now    time.Time
	events []Event
}

// newRig démarre un lundi à 10 h UTC, avec des créneaux crus après 30 tranches.
func newRig(t *testing.T) *rig {
	r := &rig{t: t, now: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}
	r.tr = New(func() time.Time { return r.now }, func(e Event) { r.events = append(r.events, e) })
	r.tr.SetParams(Params{MinSamples: 30})
	return r
}

// tick joue une tranche de dix secondes : rps requêtes par seconde réparties sur ips adresses et sur paths chemins, dont errPct % d'erreurs.
func (r *rig) tick(route string, rps float64, ips, paths, errPct int) {
	n := int(rps * BucketSeconds)
	for i := 0; i < n; i++ {
		status := 200
		if i%100 < errPct {
			status = 404
		}
		r.tr.Record(route, fmt.Sprintf("203.0.%d.%d", (i%ips)/250, (i%ips)%250), status, fmt.Sprintf("/p%d", i%paths))
	}
	r.now = r.now.Add(BucketSeconds * time.Second)
	r.tr.Tick(r.now)
}

func (r *rig) learn(route string, ticks int, rps float64, ips int) {
	for i := 0; i < ticks; i++ {
		r.tick(route, rps, ips, 20, 2)
	}
}

func (r *rig) last(kind string) *Event {
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Kind == kind {
			return &r.events[i]
		}
	}
	return nil
}

func TestColdReferenceNeverAlerts(t *testing.T) {
	r := newRig(t)
	r.tick("a.example", 5000, 3000, 20, 0)
	r.tick("a.example", 5000, 3000, 20, 0)
	if len(r.events) != 0 {
		t.Fatalf("un créneau sans historique ne doit jamais alerter : %+v", r.events)
	}
	if st := r.tr.Status(); len(st) != 1 || st[0].Warm {
		t.Fatalf("la route doit être signalée froide : %+v", st)
	}
}

func TestFastSpikeFromOneIPIsAWarning(t *testing.T) {
	r := newRig(t)
	r.learn("a.example", 40, 5, 30)
	r.tick("a.example", 500, 1, 20, 2)
	e := r.last("start")
	if e == nil || e.Level != "warning" || e.Route != "a.example" {
		t.Fatalf("un pic de volume sans écart de nature est un avertissement : %+v", r.events)
	}
	if len(e.Natures) != 0 {
		t.Fatalf("aucune nature attendue : %+v", e)
	}
}

func TestVolumeWithNatureIsProbable(t *testing.T) {
	r := newRig(t)
	r.learn("a.example", 40, 5, 30)
	for i := 0; i < 3; i++ {
		r.tick("a.example", 500, 4000, 1, 60)
	}
	var probable *Event
	for i := range r.events {
		if r.events[i].Level == "probable" {
			probable = &r.events[i]
		}
	}
	if probable == nil {
		t.Fatalf("volume + IP nouvelles + erreurs + un seul chemin doit être probable : %+v", r.events)
	}
	want := map[string]bool{"distinct_ips": true, "errors": true, "one_path": true}
	for _, n := range probable.Natures {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Fatalf("natures manquantes %v dans %+v", want, probable)
	}
}

func TestSlowRiseIsSeenByTheSlowWindow(t *testing.T) {
	r := newRig(t)
	r.learn("a.example", 40, 5, 30)
	// 8 fois la moyenne : sous le multiple rapide (10), mais au-dessus du plancher et de la bande lente.
	for i := 0; i < 8; i++ {
		r.tick("a.example", 40, 30, 20, 2)
	}
	if r.last("start") == nil {
		t.Fatalf("la fenêtre lente doit voir une montée plus modeste : %+v", r.events)
	}
}

func TestFloorProtectsQuietSites(t *testing.T) {
	r := newRig(t)
	r.learn("quiet.example", 40, 0.1, 3)
	for i := 0; i < 8; i++ {
		r.tick("quiet.example", 3, 3, 3, 0)
	}
	if len(r.events) != 0 {
		t.Fatalf("30 fois la moyenne mais sous le plancher absolu : %+v", r.events)
	}
}

func TestAlertEndsAfterCalmAndLearningIsFrozenMeanwhile(t *testing.T) {
	r := newRig(t)
	r.learn("a.example", 40, 5, 30)
	s168, _ := slotsOf(r.now)
	mean0 := r.tr.route("a.example").ref.slots[s168].stats[0][mReq].Mean
	for i := 0; i < 3; i++ {
		r.tick("a.example", 800, 5000, 1, 0)
	}
	if got := r.tr.route("a.example").ref.slots[s168].stats[0][mReq].Mean; got != mean0 {
		t.Fatalf("la référence ne doit pas apprendre pendant l'alerte : %v -> %v", mean0, got)
	}
	r.learn("a.example", 12, 5, 30)
	end := r.last("end")
	if end == nil || end.Peak < 500 || end.Duration <= 0 {
		t.Fatalf("l'alerte doit se terminer après des ticks calmes, avec son pic et sa durée : %+v", r.events)
	}
	if len(r.tr.Active()) != 0 {
		t.Fatalf("plus aucune alerte active : %+v", r.tr.Active())
	}
}

func TestDriftIsCapped(t *testing.T) {
	r := newRig(t)
	r.learn("a.example", 40, 5, 30)
	s168, _ := slotsOf(r.now)
	r.tick("a.example", 19, 30, 20, 2) // sous le plancher : pas d'alerte, donc appris
	m := r.tr.route("a.example").ref.slots[s168].stats[0][mReq].Mean
	if float64(m) > 5.7 {
		t.Fatalf("une seule mesure ne doit pas tirer la moyenne si haut (plafond de dérive) : %v", m)
	}
}

func TestFallbackSlotServesWhenFineSlotIsCold(t *testing.T) {
	var tab refTable
	p := Params{MinSamples: 10}.withDefaults()
	s168, s48 := slotsOf(time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	for i := 0; i < 12; i++ {
		tab.fb[s48].stats[0][mReq].add(5, 1440, 10, 0.1)
	}
	if tab.pick(s168, s48, p.MinSamples) != &tab.fb[s48] {
		t.Fatal("le créneau grossier doit servir tant que le fin est froid")
	}
	for i := 0; i < 12; i++ {
		tab.slots[s168].stats[0][mReq].add(5, 1440, 10, 0.1)
	}
	if tab.pick(s168, s48, p.MinSamples) != &tab.slots[s168] {
		t.Fatal("le créneau fin doit prendre le relais dès qu'il a assez d'échantillons")
	}
	if tab.pick((s168+1)%slotCount, (s48+1)%fallbackCount, p.MinSamples) != nil {
		t.Fatal("un autre créneau, jamais vu, reste froid")
	}
}

func TestSlotsOf(t *testing.T) {
	cases := []struct {
		t         time.Time
		s168, s48 int
	}{
		{time.Date(2026, 11, 2, 0, 30, 0, 0, time.UTC), 0, 0},                // lundi 0 h
		{time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), 10, 10},              // lundi 10 h
		{time.Date(2026, 11, 7, 23, 59, 0, 0, time.UTC), 5*24 + 23, 24 + 23}, // samedi 23 h
		{time.Date(2026, 11, 8, 1, 0, 0, 0, time.UTC), 6*24 + 1, 24 + 1},     // dimanche 1 h
	}
	for _, c := range cases {
		a, b := slotsOf(c.t)
		if a != c.s168 || b != c.s48 {
			t.Errorf("%v : %d,%d ; attendu %d,%d", c.t, a, b, c.s168, c.s48)
		}
	}
}

func TestExportImportKeepsWhatWasLearned(t *testing.T) {
	r := newRig(t)
	r.learn("a.example", 40, 5, 30)
	st := r.tr.Export()
	if len(st) != 1 || len(st["a.example"].Data) == 0 {
		t.Fatalf("export : %+v", st)
	}
	if len(st["a.example"].Data) > 4096 {
		t.Fatalf("une route récente doit tenir en quelques centaines d'octets, pas %d", len(st["a.example"].Data))
	}

	r2 := newRig(t)
	r2.tr.Import(st)
	r2.tick("a.example", 500, 1, 1, 0)
	if r2.last("start") == nil {
		t.Fatalf("après un redémarrage, la référence relue doit servir tout de suite : %+v", r2.events)
	}

	r3 := newRig(t)
	r3.learn("a.example", 40, 5, 30)
	mean := r3.tr.route("a.example").ref.slots[0].stats
	r3.tr.Import(map[string]RefState{"a.example": {At: r3.now, Data: []byte{9, 9}}})
	r3.tr.Import(st)
	if r3.tr.route("a.example").ref.slots[0].stats != mean {
		t.Fatal("une route déjà apprise depuis le démarrage ne doit pas être écrasée")
	}

	stale := map[string]RefState{"old.example": {At: r.now.Add(-60 * 24 * time.Hour), Data: st["a.example"].Data}}
	r4 := newRig(t)
	r4.tr.Import(stale)
	if len(r4.tr.Export()) != 0 {
		t.Fatal("une copie trop ancienne est ignorée")
	}
}

func TestDistinctIPEstimate(t *testing.T) {
	r := newRig(t)
	for _, want := range []int{10, 300, 3000} {
		b := &bucket{}
		tr := r.tr
		for i := 0; i < want; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
			bit := hashIP(tr, ip)
			b.ips[bit/32].Or(1 << (bit % 32))
		}
		got := observe([]*bucket{b}, 10).ips
		if math.Abs(got-float64(want))/float64(want) > 0.1 {
			t.Errorf("%d IP distinctes estimées à %.0f", want, got)
		}
	}
}

func hashIP(t *Tracker, ip string) uint64 { return maphash.String(t.seed, ip) % ipBits }

func TestRoutesAreBounded(t *testing.T) {
	r := newRig(t)
	for i := 0; i < maxRoutes+50; i++ {
		r.tr.Record(fmt.Sprintf("h%d.example", i), "203.0.113.1", 200, "/")
	}
	r.tr.Record(Entry, "203.0.113.1", 404, "")
	n := len(*r.tr.routes.Load())
	if n > maxRoutes+2 {
		t.Fatalf("le suivi doit rester borné : %d routes", n)
	}
	if _, ok := (*r.tr.routes.Load())[Others]; !ok {
		t.Fatal("les routes au-delà du plafond vont dans « (autres) »")
	}
	if _, ok := (*r.tr.routes.Load())[Entry]; !ok {
		t.Fatal("le profil d'entrée existe toujours")
	}
}

func TestIdleRoutesAreForgotten(t *testing.T) {
	r := newRig(t)
	r.learn("gone.example", 3, 5, 30)
	r.now = r.now.Add(idleForget + time.Hour)
	r.tr.Tick(r.now)
	if _, ok := (*r.tr.routes.Load())["gone.example"]; ok {
		t.Fatal("une route sans requête depuis un mois est oubliée")
	}
}

func TestConcurrentRecordAndTick(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				r.tr.Record(fmt.Sprintf("h%d.example", g%3), fmt.Sprintf("10.0.0.%d", i%200), 200+(i%3)*100, "/x")
			}
		}(g)
	}
	for i := 0; i < 20; i++ {
		r.tr.Tick(r.now.Add(time.Duration(i) * BucketSeconds * time.Second))
	}
	wg.Wait()
	_ = r.tr.Status()
	_ = r.tr.Events()
}

func BenchmarkRecord(b *testing.B) {
	tr := New(nil, nil)
	ips := make([]string, 1024)
	for i := range ips {
		ips[i] = fmt.Sprintf("203.0.%d.%d", i/250, i%250)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			tr.Record("app.example.fr", ips[i&1023], 200, "/api/items")
			i++
		}
	})
}

func BenchmarkTick(b *testing.B) {
	r := &rig{now: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}
	r.tr = New(func() time.Time { return r.now }, nil)
	for i := 0; i < maxRoutes; i++ {
		r.tr.Record(fmt.Sprintf("h%d.example", i), "203.0.113.1", 200, "/")
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.tr.Record("h1.example", "203.0.113.1", 200, "/")
		r.now = r.now.Add(10 * time.Second)
		r.tr.Tick(r.now)
	}
}

func TestProbableAlertHardensTheRouteOnlyWhenAsked(t *testing.T) {
	for _, harden := range []bool{false, true} {
		r := newRig(t)
		r.tr.SetParams(Params{MinSamples: 30, Harden: harden})
		r.learn("a.example", 40, 5, 30)
		for i := 0; i < 3; i++ {
			r.tick("a.example", 500, 4000, 1, 60)
		}
		h := r.tr.Hardened("a.example")
		if harden != (h != nil) {
			t.Fatalf("harden=%v : profil durci = %v", harden, h)
		}
		if harden {
			if want := 15.0 * 4; h.Rate < 20 || h.Rate > want {
				t.Fatalf("le plafond suit la moyenne apprise (≈ 3 × 5, plancher 20) : %v", h.Rate)
			}
			if e := r.last("start"); e == nil || !e.Hardened {
				t.Fatalf("l'événement doit dire que la route est durcie : %+v", r.events)
			}
			if st := r.tr.Status(); !st[0].Hardened {
				t.Fatalf("l'état doit le dire aussi : %+v", st)
			}
		}
	}
}

func TestWarningNeverHardens(t *testing.T) {
	r := newRig(t)
	r.tr.SetParams(Params{MinSamples: 30, Harden: true})
	r.learn("a.example", 40, 5, 30)
	r.tick("a.example", 500, 1, 20, 2)
	if r.tr.Hardened("a.example") != nil {
		t.Fatal("un écart de volume seul ne durcit pas la route")
	}
}

func TestHardeningEndsWithTheAlert(t *testing.T) {
	r := newRig(t)
	r.tr.SetParams(Params{MinSamples: 30, Harden: true})
	r.learn("a.example", 40, 5, 30)
	for i := 0; i < 3; i++ {
		r.tick("a.example", 500, 4000, 1, 60)
	}
	if r.tr.Hardened("a.example") == nil {
		t.Fatal("prérequis : route durcie")
	}
	r.learn("a.example", 12, 5, 30)
	if r.tr.Hardened("a.example") != nil || r.last("end") == nil {
		t.Fatalf("le profil durci doit tomber avec l'alerte : %+v", r.events)
	}
}

func TestHardBucketCapsAndRefills(t *testing.T) {
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	h := newHard(10, now)
	allowed := 0
	for i := 0; i < 100; i++ {
		if h.Allow(now) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("la rafale vaut deux secondes de débit : %d admises", allowed)
	}
	if h.Allow(now) {
		t.Fatal("plafond atteint")
	}
	now = now.Add(time.Second)
	n := 0
	for h.Allow(now) {
		n++
	}
	if n != 10 {
		t.Fatalf("une seconde rend 10 jetons : %d", n)
	}
}
