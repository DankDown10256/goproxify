// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package seasonal apprend le comportement agrégé du trafic de chaque route, créneau par créneau (jour de la semaine × heure, UTC), et
// signale quand il s'écarte de ce qu'il est d'habitude (ADR 0020, étape 3). Elle complète la référence par IP de l'ADR 0011 : l'une dit
// qu'une IP s'écarte, l'autre que le trafic s'écarte.
//
// Aucun état par IP : une requête incrémente quelques compteurs atomiques et pose un bit dans une table de 1 Ko (comptage approché
// des IP distinctes). Un tick toutes les dix secondes clôt la tranche, la compare à la référence puis l'y verse.
package seasonal

import (
	"hash/maphash"
	"math"
	"math/bits"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Entry est le profil du trafic qu'aucune route ne retient : hôtes inconnus, poignées de main TLS refusées.
	Entry = "(entrée)"
	// Others regroupe les routes au-delà du plafond de suivi.
	Others = "(autres)"

	// BucketSeconds est le pas de la fenêtre rapide.
	BucketSeconds = 10
	// SlowBuckets est le nombre de tranches de la fenêtre lente (une minute).
	SlowBuckets = 6

	maxRoutes   = 128
	pathBuckets = 32
	ipBits      = 8192
	ipWords     = ipBits / 32
	maxEvents   = 64
	// idleForget : une route sans requête depuis ce délai est oubliée avec sa référence.
	idleForget = 30 * 24 * time.Hour
)

// Niveaux d'une alerte.
const (
	LevelNone     = 0
	LevelWarning  = 1 // un écart de volume seul : une newsletter ou une promotion peuvent le causer
	LevelProbable = 2 // un écart de volume accompagné d'un écart de nature
)

// LevelName donne le nom d'un niveau.
func LevelName(l int) string {
	switch l {
	case LevelWarning:
		return "warning"
	case LevelProbable:
		return "probable"
	}
	return "none"
}

// Params règle la détection. Les valeurs à zéro prennent leur défaut ; ce sont des points de départ à calibrer sur des logs réels.
type Params struct {
	// FloorRPS : débit (req/s) sous lequel aucun écart de volume ne compte, quelle que soit la référence (défaut 20).
	FloorRPS float64
	// FastFactor : multiple de la moyenne du créneau qui déclenche la fenêtre rapide (défaut 10).
	FastFactor float64
	// SlowSigmas : nombre d'écarts-types au-dessus de la moyenne pour la fenêtre lente (défaut 4).
	SlowSigmas float64
	// MinSamples : tranches de dix secondes qu'un créneau doit avoir vues avant d'être cru (défaut 720, soit deux heures).
	MinSamples int
	// ExitTicks : ticks calmes consécutifs qui mettent fin à une alerte (défaut 6, soit une minute).
	ExitTicks int
	// Harden : pendant une attaque probable, la route est durcie (voir Hard). Sans cela l'alerte ne fait que signaler.
	Harden bool
	// CapFactor : multiple de la moyenne du créneau qui plafonne les IP sans historique pendant une alerte durcie (défaut 3).
	CapFactor float64
}

func (p Params) withDefaults() Params {
	if p.FloorRPS <= 0 {
		p.FloorRPS = 20
	}
	if p.FastFactor <= 0 {
		p.FastFactor = 10
	}
	if p.SlowSigmas <= 0 {
		p.SlowSigmas = 4
	}
	if p.MinSamples <= 0 {
		p.MinSamples = 720
	}
	if p.ExitTicks <= 0 {
		p.ExitTicks = SlowBuckets
	}
	if p.CapFactor <= 0 {
		p.CapFactor = 3
	}
	return p
}

// Event est un changement d'état d'une alerte.
type Event struct {
	Route string    `json:"route"`
	Kind  string    `json:"kind"`  // start | escalate | end
	Level string    `json:"level"` // warning | probable
	At    time.Time `json:"at"`
	// RPS : le débit qui a causé l'événement ; Expected : la moyenne apprise du créneau.
	RPS      float64 `json:"rps"`
	Expected float64 `json:"expected"`
	// Natures : les écarts de nature constatés (distinct_ips, errors, one_path).
	Natures []string `json:"natures,omitempty"`
	// Duration et Peak : à la fin seulement.
	Duration time.Duration `json:"duration,omitempty"`
	Peak     float64       `json:"peak,omitempty"`
	// Hardened : la route est durcie (défi et plafond pour les IP sans historique) tant que l'alerte dure.
	Hardened bool `json:"hardened,omitempty"`
}

// RouteStatus est l'état courant d'une route, pour l'affichage (courbe réelle contre bande attendue).
type RouteStatus struct {
	Route string `json:"route"`
	// Warm : le créneau courant a assez d'observations pour être cru. Sinon la détection reste froide.
	Warm    bool   `json:"warm"`
	Level   string `json:"level"`
	Samples uint32 `json:"samples"`
	// RPS : débit de la dernière minute ; Expected et Upper : la moyenne et la borne haute du créneau pour la même fenêtre.
	RPS      float64   `json:"rps"`
	Expected float64   `json:"expected"`
	Upper    float64   `json:"upper"`
	IPs      float64   `json:"ips"`
	Since    time.Time `json:"since,omitempty"`
	Hardened bool      `json:"hardened,omitempty"`
}

type bucket struct {
	req, e4, e5 atomic.Uint32
	paths       [pathBuckets]atomic.Uint32
	ips         [ipWords]atomic.Uint32
}

// idle est la tranche partagée d'une route sans requête : jamais écrite.
var idle = &bucket{}

type routeState struct {
	name string
	cur  atomic.Pointer[bucket]
	hard atomic.Pointer[Hard]

	// Le reste n'est touché que sous Tracker.mu.
	hist     [SlowBuckets]*bucket
	histN    int
	ticks    int
	ref      refTable
	alert    alertState
	lastSeen time.Time
	last     RouteStatus
}

type alertState struct {
	level    int
	since    time.Time
	calm     int
	peak     float64
	natures  map[string]bool
	expected float64
}

// Tracker suit le trafic de toutes les routes d'une passerelle.
type Tracker struct {
	seed   maphash.Seed
	now    func() time.Time
	onEvt  func(Event)
	params atomic.Pointer[Params]

	routes   atomic.Pointer[map[string]*routeState]
	createMu sync.Mutex

	mu     sync.Mutex
	events []Event
}

// New crée un suivi. now est l'horloge (injectable) ; onEvent reçoit chaque changement d'état d'une alerte, hors verrou.
func New(now func() time.Time, onEvent func(Event)) *Tracker {
	if now == nil {
		now = time.Now
	}
	t := &Tracker{seed: maphash.MakeSeed(), now: now, onEvt: onEvent}
	m := map[string]*routeState{}
	t.routes.Store(&m)
	p := Params{}.withDefaults()
	t.params.Store(&p)
	return t
}

// SetParams remplace les réglages à chaud.
func (t *Tracker) SetParams(p Params) {
	p = p.withDefaults()
	t.params.Store(&p)
}

func (t *Tracker) route(name string) *routeState {
	if rs, ok := (*t.routes.Load())[name]; ok {
		return rs
	}
	t.createMu.Lock()
	defer t.createMu.Unlock()
	old := *t.routes.Load()
	if rs, ok := old[name]; ok {
		return rs
	}
	if len(old) >= maxRoutes && name != Entry {
		name = Others
		if rs, ok := old[name]; ok {
			return rs
		}
	}
	rs := &routeState{name: name}
	rs.cur.Store(idle)
	next := make(map[string]*routeState, len(old)+1)
	for k, v := range old {
		next[k] = v
	}
	next[name] = rs
	t.routes.Store(&next)
	return rs
}

// Record compte une requête servie. route est l'hôte de la route (ou Entry), path le chemin sans la query.
func (t *Tracker) Record(route, ip string, status int, path string) {
	rs := t.route(route)
	b := rs.cur.Load()
	if b == idle {
		nb := &bucket{}
		if rs.cur.CompareAndSwap(idle, nb) {
			b = nb
		} else {
			b = rs.cur.Load()
		}
	}
	b.req.Add(1)
	switch {
	case status >= 500:
		b.e5.Add(1)
	case status >= 400:
		b.e4.Add(1)
	}
	b.paths[maphash.String(t.seed, path)%pathBuckets].Add(1)
	bit := maphash.String(t.seed, ip) % ipBits
	b.ips[bit/32].Or(1 << (bit % 32))
}

type obs struct {
	reqs     float64
	rps      float64
	ips      float64
	errShare float64
	topShare float64
}

func observe(bs []*bucket, seconds float64) obs {
	var o obs
	var reqs, errs uint32
	var paths [pathBuckets]uint32
	var words [ipWords]uint32
	for _, b := range bs {
		reqs += b.req.Load()
		errs += b.e4.Load() + b.e5.Load()
		for i := range paths {
			paths[i] += b.paths[i].Load()
		}
		if b == idle {
			continue
		}
		for i := range words {
			words[i] |= b.ips[i].Load()
		}
	}
	o.reqs = float64(reqs)
	o.rps = o.reqs / seconds
	set := 0
	for _, w := range words {
		set += bits.OnesCount32(w)
	}
	switch {
	case set == 0:
	case set >= ipBits:
		o.ips = ipBits * math.Log(ipBits)
	default:
		o.ips = -ipBits * math.Log(1-float64(set)/ipBits)
	}
	if reqs > 0 {
		o.errShare = float64(errs) / o.reqs
		var top uint32
		for _, p := range paths {
			if p > top {
				top = p
			}
		}
		o.topShare = float64(top) / o.reqs
	}
	return o
}

// Tick clôt la tranche de dix secondes de chaque route, la compare à la référence du créneau puis la lui verse.
func (t *Tracker) Tick(now time.Time) {
	p := *t.params.Load()
	var emit []Event
	t.mu.Lock()
	for name, rs := range *t.routes.Load() {
		if rs.step(now, p, &emit) {
			t.forget(name)
		}
	}
	t.events = append(t.events, emit...)
	if len(t.events) > maxEvents {
		t.events = append([]Event(nil), t.events[len(t.events)-maxEvents:]...)
	}
	t.mu.Unlock()
	if t.onEvt != nil {
		for _, e := range emit {
			t.onEvt(e)
		}
	}
}

func (t *Tracker) forget(name string) {
	t.createMu.Lock()
	defer t.createMu.Unlock()
	old := *t.routes.Load()
	next := make(map[string]*routeState, len(old))
	for k, v := range old {
		if k != name {
			next[k] = v
		}
	}
	t.routes.Store(&next)
}

// step traite un tick pour une route. Vrai quand la route est oubliée.
func (rs *routeState) step(now time.Time, p Params, emit *[]Event) bool {
	b := rs.cur.Load()
	if b != idle {
		rs.cur.Store(idle)
	}
	if b.req.Load() > 0 {
		rs.lastSeen = now
	} else if !rs.lastSeen.IsZero() && now.Sub(rs.lastSeen) > idleForget && rs.alert.level == LevelNone {
		return true
	}
	copy(rs.hist[:], rs.hist[1:])
	rs.hist[SlowBuckets-1] = b
	if rs.histN < SlowBuckets {
		rs.histN++
	}
	rs.ticks++

	fast := observe(rs.hist[SlowBuckets-1:], BucketSeconds)
	var slow obs
	haveSlow := rs.histN == SlowBuckets
	if haveSlow {
		slow = observe(rs.hist[:], BucketSeconds*SlowBuckets)
	}

	s168, s48 := slotsOf(now)
	ref := rs.ref.pick(s168, s48, p.MinSamples)
	rs.last = RouteStatus{Route: rs.name, Warm: ref != nil, Level: LevelName(rs.alert.level), Since: rs.alert.since, RPS: fast.rps, IPs: fast.ips, Hardened: rs.hard.Load() != nil}
	if ref != nil {
		rs.last.Samples = ref.stats[0][mReq].N
		rs.detect(now, p, ref, fast, slow, haveSlow, emit)
	} else if rs.alert.level != LevelNone {
		rs.endAlert(now, emit)
	}

	if rs.alert.level == LevelNone {
		rs.ref.learn(s168, s48, 0, fast, p)
		if haveSlow && rs.ticks%SlowBuckets == 0 {
			rs.ref.learn(s168, s48, 1, slow, p)
		}
	}
	return false
}

func (rs *routeState) detect(now time.Time, p Params, ref *slotRef, fast, slow obs, haveSlow bool, emit *[]Event) {
	m0 := ref.stats[0][mReq]
	volume := fast.rps > math.Max(p.FastFactor*float64(m0.Mean), p.FloorRPS)
	var natures []string
	rps, expected := fast.rps, float64(m0.Mean)
	if haveSlow && ref.warm(1, p.MinSamples/SlowBuckets) {
		s := ref.stats[1]
		limit := math.Max(math.Max(float64(s[mReq].Mean)+p.SlowSigmas*s[mReq].sd(), p.FloorRPS), 2*float64(s[mReq].Mean))
		rs.last.RPS, rs.last.Expected, rs.last.Upper, rs.last.IPs = slow.rps, float64(s[mReq].Mean), limit, slow.ips
		if slow.rps > limit {
			volume = true
			if slow.rps > rps {
				rps, expected = slow.rps, float64(s[mReq].Mean)
			}
		}
		if slow.reqs >= minNatureRequests {
			if slow.ips > math.Max(math.Max(float64(s[mIPs].Mean)+p.SlowSigmas*s[mIPs].sd(), 3*float64(s[mIPs].Mean)), minNatureIPs) {
				natures = append(natures, "distinct_ips")
			}
			if slow.errShare >= 0.2 && slow.errShare > float64(s[mErr].Mean)+math.Max(p.SlowSigmas*s[mErr].sd(), 0.15) {
				natures = append(natures, "errors")
			}
			if slow.topShare >= 0.5 && slow.topShare > float64(s[mTop].Mean)+math.Max(p.SlowSigmas*s[mTop].sd(), 0.25) {
				natures = append(natures, "one_path")
			}
		}
	} else {
		rs.last.RPS, rs.last.Expected, rs.last.Upper = fast.rps, float64(m0.Mean), math.Max(p.FastFactor*float64(m0.Mean), p.FloorRPS)
	}

	a := &rs.alert
	if !volume {
		if a.level == LevelNone {
			return
		}
		a.calm++
		if a.calm >= p.ExitTicks {
			rs.endAlert(now, emit)
		}
		return
	}
	a.calm = 0
	level := LevelWarning
	if len(natures) > 0 {
		level = LevelProbable
	}
	if rps > a.peak {
		a.peak = rps
	}
	kind := ""
	switch {
	case a.level == LevelNone:
		kind = "start"
		a.since, a.natures, a.peak, a.expected = now, map[string]bool{}, rps, expected
	case level > a.level:
		kind = "escalate"
	}
	for _, n := range natures {
		a.natures[n] = true
	}
	if p.Harden && level == LevelProbable && rs.hard.Load() == nil {
		rs.hard.Store(newHard(math.Max(p.CapFactor*a.expected, p.FloorRPS), now))
		if kind == "" {
			kind = "escalate"
		}
	}
	if kind != "" {
		a.level = level
		*emit = append(*emit, Event{Route: rs.name, Kind: kind, Level: LevelName(level), At: now, RPS: rps, Expected: expected, Natures: sortedKeys(a.natures), Hardened: rs.hard.Load() != nil})
	}
	rs.last.Level, rs.last.Since, rs.last.Hardened = LevelName(a.level), a.since, rs.hard.Load() != nil
}

func (rs *routeState) endAlert(now time.Time, emit *[]Event) {
	a := rs.alert
	*emit = append(*emit, Event{Route: rs.name, Kind: "end", Level: LevelName(a.level), At: now, Expected: a.expected,
		Natures: sortedKeys(a.natures), Duration: now.Sub(a.since), Peak: a.peak, Hardened: rs.hard.Load() != nil})
	rs.hard.Store(nil)
	rs.alert = alertState{}
	rs.last.Level = LevelName(LevelNone)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const (
	minNatureRequests = 100
	minNatureIPs      = 20
)

// Status décrit l'état de chaque route suivie, les plus actives d'abord.
func (t *Tracker) Status() []RouteStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]RouteStatus, 0, len(*t.routes.Load()))
	for _, rs := range *t.routes.Load() {
		st := rs.last
		st.Route = rs.name
		if st.Level == "" {
			st.Level = LevelName(LevelNone)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level > out[j].Level
		}
		if out[i].RPS != out[j].RPS {
			return out[i].RPS > out[j].RPS
		}
		return out[i].Route < out[j].Route
	})
	return out
}

// Events retourne les derniers changements d'état, du plus récent au plus ancien.
func (t *Tracker) Events() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Event, len(t.events))
	for i, e := range t.events {
		out[len(t.events)-1-i] = e
	}
	return out
}

// Active retourne les alertes en cours.
func (t *Tracker) Active() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Event
	for _, rs := range *t.routes.Load() {
		if a := rs.alert; a.level != LevelNone {
			out = append(out, Event{Route: rs.name, Kind: "active", Level: LevelName(a.level), At: a.since, RPS: a.peak, Expected: a.expected, Natures: sortedKeys(a.natures), Hardened: rs.hard.Load() != nil})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })
	return out
}
