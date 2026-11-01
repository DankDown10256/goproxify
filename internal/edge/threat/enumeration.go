// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"hash/maphash"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Modes du signal « énumération ».
const (
	EnumerationOff    = "off"    // aucun signal (défaut)
	EnumerationDetect = "detect" // compté et journalisé, sans effet sur la note
	EnumerationBlock  = "block"  // verse des points à la note commune de l'IP
)

const (
	defaultEnumFloor     = 30
	defaultEnumWindow    = 10 * time.Minute
	defaultEnumPoints    = 4.0
	maxEnumPoints        = 10.0
	enumBits             = 1024
	enumWords            = enumBits / 64
	enumShards           = 16
	enumShardCap         = 256
	enumNormCap          = 512
	enumNormMinSamples   = 20
	enumNormSigmas       = 6.0
	enumNormMaxMeanRatio = 4.0
)

// EnumerationConfig règle la détection d'énumération (ADR 0020, étape 4.b) : une IP qui parcourt de nombreuses valeurs distinctes d'un
// même gabarit de chemin (`/api/users/{int}`), le premier risque des API, que les règles du WAF ne voient pas.
//
// Par IP, route et gabarit, un compteur approché de valeurs distinctes (une table de 1 024 bits : aucune valeur n'est conservée, ce qui
// respecte l'ADR 0016). Le signal ne vaut que sur un gabarit que le profil de surface de la route connaît, et seulement si ce profil a
// convergé. Le seuil est le plus grand de `floor` et de ce que les autres clients font d'ordinaire sur ce gabarit. Il naît en `detect`.
type EnumerationConfig struct {
	// Mode : off (défaut) | detect | block.
	Mode string `json:"mode,omitempty"`
	// Floor : valeurs distinctes sur un gabarit, dans la fenêtre, sous lesquelles rien ne compte (défaut 30).
	Floor int `json:"floor,omitempty"`
	// Window : fenêtre de comptage (défaut 10 minutes, 1 minute à 24 h).
	Window Duration `json:"window,omitempty"`
	// Points : points versés à la note commune en `block` (défaut 4, au plus 10). Le seuil de ban par défaut est 10.
	Points float64 `json:"points,omitempty"`
}

func (c EnumerationConfig) mode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case EnumerationDetect:
		return EnumerationDetect
	case EnumerationBlock:
		return EnumerationBlock
	}
	return EnumerationOff
}

// Active : la détection est en `detect` ou en `block`.
func (c EnumerationConfig) Active() bool { return c.mode() != EnumerationOff }

func (c EnumerationConfig) floor() int {
	if c.Floor <= 0 {
		return defaultEnumFloor
	}
	return c.Floor
}

func (c EnumerationConfig) window() time.Duration {
	if c.Window.Duration <= 0 {
		return defaultEnumWindow
	}
	return c.Window.Duration
}

func (c EnumerationConfig) points() float64 {
	if c.Points <= 0 {
		return defaultEnumPoints
	}
	return c.Points
}

// ValidateEnumeration refuse un réglage qui ne pourrait jamais servir.
func (c Config) ValidateEnumeration() error {
	en := c.Enumeration
	switch strings.ToLower(strings.TrimSpace(en.Mode)) {
	case "", EnumerationOff, EnumerationDetect, EnumerationBlock:
	default:
		return fmt.Errorf("enumeration.mode : %q invalide (attendu : off | detect | block)", en.Mode)
	}
	if en.Floor < 0 || en.Floor > 100000 {
		return fmt.Errorf("enumeration.floor : %d hors de 1 – 100000", en.Floor)
	}
	if w := en.Window.Duration; w < 0 || (w != 0 && (w < time.Minute || w > 24*time.Hour)) {
		return fmt.Errorf("enumeration.window : %s hors de 1 minute – 24 heures", w)
	}
	if en.Points < 0 || en.Points > maxEnumPoints {
		return fmt.Errorf("enumeration.points : %v hors de 0 – %v", en.Points, maxEnumPoints)
	}
	if en.mode() == EnumerationBlock && !c.IPScore.Enabled {
		return fmt.Errorf("enumeration.mode block : demande ip_score.enabled (le signal verse des points à la note commune)")
	}
	return nil
}

// EnumShapeFunc décompose un chemin en gabarit et valeurs d'identifiant (surface.EnumShape).
type EnumShapeFunc func(path string) (shape, values string, ok bool)

// EnumKnownFunc dit si l'hôte a un profil de surface convergé qui connaît ce chemin. Appelée au seul moment d'un dépassement : elle
// peut coûter (clonage du profil).
type EnumKnownFunc func(host, path string) bool

// SetEnumerationHooks branche la lecture des gabarits et le profil de surface. Sans eux, le signal ne se déclenche jamais.
func (e *Engine) SetEnumerationHooks(shape EnumShapeFunc, known EnumKnownFunc) {
	e.mu.Lock()
	e.enumShape, e.enumKnown = shape, known
	e.mu.Unlock()
}

// ── Compteurs ────────────────────────────────────────────────────────────────

type enumEntry struct {
	start time.Time
	bits  [enumWords]uint64
	reqs  int
	fired bool
	last  time.Time
}

// distinct estime le nombre de valeurs distinctes (comptage linéaire sur 1 024 bits).
func (en *enumEntry) distinct() float64 {
	set := 0
	for _, w := range en.bits {
		for ; w != 0; w &= w - 1 {
			set++
		}
	}
	switch {
	case set == 0:
		return 0
	case set >= enumBits:
		return enumBits * math.Log(enumBits)
	}
	return -enumBits * math.Log(1-float64(set)/enumBits)
}

type enumNorm struct {
	mean, vari float64
	n          uint32
}

func (n *enumNorm) add(x float64) {
	n.n++
	alpha := 1 / float64(minU32(n.n, 200))
	d := x - n.mean
	n.mean += alpha * d
	n.vari = (1 - alpha) * (n.vari + alpha*d*d)
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// threshold est le nombre de valeurs distinctes à partir duquel une IP s'écarte des autres sur ce gabarit : le plus grand du plancher et
// de la norme apprise (moyenne plus six écarts-types, au moins quatre fois la moyenne).
func (n *enumNorm) threshold(floor int) float64 {
	t := float64(floor)
	if n != nil && n.n >= enumNormMinSamples {
		if v := math.Max(n.mean+enumNormSigmas*math.Sqrt(n.vari), enumNormMaxMeanRatio*n.mean); v > t {
			t = v
		}
	}
	return t
}

type enumShard struct {
	mu sync.Mutex
	m  map[string]*enumEntry
}

type enumTracker struct {
	seed   maphash.Seed
	now    func() time.Time
	shards [enumShards]enumShard
	nmu    sync.Mutex
	norms  map[string]*enumNorm
}

func newEnumTracker(now func() time.Time) *enumTracker {
	t := &enumTracker{seed: maphash.MakeSeed(), now: now, norms: map[string]*enumNorm{}}
	for i := range t.shards {
		t.shards[i].m = map[string]*enumEntry{}
	}
	return t
}

func (t *enumTracker) shard(key string) *enumShard {
	return &t.shards[maphash.String(t.seed, key)%enumShards]
}

func (t *enumTracker) learn(normKey string, x float64) {
	t.nmu.Lock()
	defer t.nmu.Unlock()
	n := t.norms[normKey]
	if n == nil {
		if len(t.norms) >= enumNormCap {
			return
		}
		n = &enumNorm{}
		t.norms[normKey] = n
	}
	n.add(x)
}

func (t *enumTracker) norm(normKey string) *enumNorm {
	t.nmu.Lock()
	defer t.nmu.Unlock()
	if n := t.norms[normKey]; n != nil {
		c := *n
		return &c
	}
	return nil
}

// normKeyOf retire l'IP d'une clé « ip|hôte|gabarit ».
func normKeyOf(key string) string {
	if i := strings.IndexByte(key, '|'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// closeEntry verse une fenêtre échue à la norme de son gabarit : ce que les clients font d'ordinaire. La mesure est plafonnée (deux
// fois le plancher tant que la norme n'est pas établie, ensuite deux fois sa moyenne) : une IP qui énumère ne peut tirer la norme que
// d'un pas borné, jamais d'un coup.
func (t *enumTracker) closeEntry(key string, en *enumEntry, floor int) {
	if en.reqs == 0 {
		return
	}
	nk := normKeyOf(key)
	limit := 2 * float64(floor)
	if n := t.norm(nk); n != nil && n.n >= enumNormMinSamples {
		limit = math.Max(2*n.mean, float64(floor))
	}
	t.learn(nk, math.Min(en.distinct(), limit))
}

// record compte une valeur et rend le nombre estimé de valeurs distinctes de la fenêtre, avec le seuil de la norme et si le signal
// vient de franchir son seuil pour la première fois dans cette fenêtre.
func (t *enumTracker) record(key, value string, window time.Duration, floor int) (est float64, crossed bool) {
	now := t.now()
	sh := t.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	en := sh.m[key]
	if en != nil && now.Sub(en.start) >= window {
		t.closeEntry(key, en, floor)
		en = nil
	}
	if en == nil {
		if len(sh.m) >= enumShardCap {
			evictEnum(sh.m)
		}
		en = &enumEntry{start: now}
		sh.m[key] = en
	}
	bit := maphash.String(t.seed, value) % enumBits
	en.bits[bit/64] |= 1 << (bit % 64)
	en.reqs++
	en.last = now
	est = en.distinct()
	if !en.fired && est >= t.norm(normKeyOf(key)).threshold(floor) {
		en.fired = true
		return est, true
	}
	return est, false
}

func evictEnum(m map[string]*enumEntry) {
	var victim string
	var oldest time.Time
	n := 0
	for k, en := range m {
		if victim == "" || en.last.Before(oldest) {
			victim, oldest = k, en.last
		}
		if n++; n >= 16 {
			break
		}
	}
	delete(m, victim)
}

// sweep clôt les fenêtres échues, y compris celles de clients qui ne reviennent pas : sans cela leur comportement n'entrerait jamais
// dans la norme.
func (t *enumTracker) sweep(window time.Duration, floor int) {
	now := t.now()
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for k, en := range sh.m {
			if now.Sub(en.start) >= window {
				t.closeEntry(k, en, floor)
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

func (t *enumTracker) forget(ip string) {
	prefix := counterKey(ip) + "|"
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for k := range sh.m {
			if strings.HasPrefix(k, prefix) {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

// EnumNormState : la norme apprise d'un gabarit, telle qu'elle est conservée sur disque. Aucune IP, aucune valeur.
type EnumNormState struct {
	Mean float64 `json:"mean"`
	Var  float64 `json:"var"`
	N    uint32  `json:"n"`
}

func (t *enumTracker) snapshot() map[string]EnumNormState {
	t.nmu.Lock()
	defer t.nmu.Unlock()
	out := make(map[string]EnumNormState, len(t.norms))
	for k, n := range t.norms {
		out[k] = EnumNormState{Mean: n.mean, Var: n.vari, N: n.n}
	}
	return out
}

func (t *enumTracker) restore(in map[string]EnumNormState) {
	t.nmu.Lock()
	defer t.nmu.Unlock()
	for k, s := range in {
		if _, ok := t.norms[k]; ok || len(t.norms) >= enumNormCap || s.N == 0 || s.Mean < 0 || s.Var < 0 || math.IsNaN(s.Mean) || math.IsNaN(s.Var) {
			continue
		}
		t.norms[k] = &enumNorm{mean: s.Mean, vari: s.Var, n: s.N}
	}
}

// ── Évaluation ───────────────────────────────────────────────────────────────

// observeEnumeration compte la valeur d'identifiant d'une requête servie et, au dépassement de la norme du gabarit, déclenche le signal.
func (e *Engine) observeEnumeration(path, ip, route string, cfg Config) {
	ec := cfg.Enumeration
	e.mu.RLock()
	shape, known := e.enumShape, e.enumKnown
	e.mu.RUnlock()
	if shape == nil {
		return
	}
	tpl, values, ok := shape(path)
	if !ok {
		return
	}
	key := counterKey(ip) + "|" + strings.ToLower(route) + "|" + tpl
	est, crossed := e.enum.record(key, values, ec.window(), ec.floor())
	if !crossed {
		return
	}
	if known == nil || !known(route, path) {
		// Un gabarit que le profil ne connaît pas, ou un profil qui n'a pas convergé : on ne sait pas encore ce qui est normal.
		e.inc(threatEnumerationTotal, "unproven")
		return
	}
	value := fmt.Sprintf("%.0f valeurs distinctes sur %s", est, tpl)
	if ec.mode() == EnumerationDetect {
		e.inc(threatEnumerationTotal, "shadow")
		if ok, _ := e.sigLog.Allow("enumeration|" + ip); ok {
			e.log.Info("ephor: énumération détectée (mode detect)", "ip", ip, "gabarit", tpl, "valeurs", int(est), "route", route)
		}
		return
	}
	e.inc(threatEnumerationTotal, "hit")
	if cfg.IPScore.Enabled && e.banFn != nil {
		e.scoreBan(ip, "enumeration", []router.BanSignal{{Name: "enumeration", Points: ec.points(), Value: clipValue(value)}}, cfg)
	}
}

// sweepEnumeration clôt les fenêtres échues tant que la détection est active.
func (e *Engine) sweepEnumeration() {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if cfg.Enabled && cfg.Enumeration.Active() {
		e.enum.sweep(cfg.Enumeration.window(), cfg.Enumeration.floor())
	}
}
