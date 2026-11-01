// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/bantarget"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/seasonal"
)

// Modes du signal « hôte inconnu ».
const (
	UnknownHostOff    = "off"    // aucun signal (défaut)
	UnknownHostDetect = "detect" // compté et journalisé, sans effet sur la note
	UnknownHostBlock  = "block"  // verse des points modérés à la note commune de l'IP
)

const (
	defaultUnknownHostPoints = 1.0
	maxUnknownHostPoints     = 5.0
	maxUnknownProbes         = 200
	unknownSeriesCap         = 4096
	unknownSeriesLen         = 8
	// Une série d'accès est « régulière » quand six accès au moins sont espacés d'un intervalle presque constant d'au moins deux
	// secondes : c'est une sonde (supervision, répartiteur de charge), pas un scanner.
	regularMinHits      = 6
	regularMinGap       = 2 * time.Second
	regularMaxSpread    = 0.15
	probeSuggestionsMax = 50
)

// UnknownHostConfig règle le signal « hôte inconnu » (ADR 0020, étape 2.b) : une requête sur un nom sans route, ou une poignée de
// main TLS refusée faute de nom ou de certificat, verse des points MODÉRÉS à la note de l'IP.
//
// Un accès isolé ne prouve rien : un visiteur peut être envoyé là par une page tierce (<img src="http://votre-IP/">). Plusieurs
// d'affilée, ou des chemins de scan sur un hôte inconnu, mènent au ban par la note commune. Jamais de ban au premier accès.
// Le signal s'appuie sur le score cumulé (ip_score.enabled). Il naît en `detect`. Désactivé par défaut.
type UnknownHostConfig struct {
	// Mode : off (défaut) | detect | block.
	Mode string `json:"mode,omitempty"`
	// Points : points versés par accès (défaut 1, au plus 5). Le seuil de ban par défaut est 10.
	Points float64 `json:"points,omitempty"`
	// Probes : IP ou CIDR de sondes connues (supervision, répartiteur de charge), jamais comptées.
	Probes []string `json:"probes,omitempty"`
}

func (c UnknownHostConfig) mode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case UnknownHostDetect:
		return UnknownHostDetect
	case UnknownHostBlock:
		return UnknownHostBlock
	}
	return UnknownHostOff
}

// Active : le signal est en `detect` ou en `block`.
func (c UnknownHostConfig) Active() bool { return c.mode() != UnknownHostOff }

func (c UnknownHostConfig) points() float64 {
	if c.Points <= 0 {
		return defaultUnknownHostPoints
	}
	return c.Points
}

// ValidateUnknownHost refuse un réglage qui ne pourrait jamais servir ou qui bannirait au premier accès. Les sondes sont des
// adresses ou des CIDR : leur lecture est contrôlée par le moteur qui les charge (engines.decodeEphor).
func (c Config) ValidateUnknownHost() error {
	u := c.UnknownHost
	switch strings.ToLower(strings.TrimSpace(u.Mode)) {
	case "", UnknownHostOff, UnknownHostDetect, UnknownHostBlock:
	default:
		return fmt.Errorf("unknown_host.mode : %q invalide (attendu : off | detect | block)", u.Mode)
	}
	if u.Points < 0 || u.Points > maxUnknownHostPoints {
		return fmt.Errorf("unknown_host.points : %v hors de 0 – %v", u.Points, maxUnknownHostPoints)
	}
	if len(u.Probes) > maxUnknownProbes {
		return fmt.Errorf("unknown_host.probes : %d entrées, au plus %d", len(u.Probes), maxUnknownProbes)
	}
	if !u.Active() {
		return nil
	}
	if !c.IPScore.Enabled {
		return fmt.Errorf("unknown_host : demande ip_score.enabled (jamais de ban au premier accès : les points s'additionnent dans le score cumulé)")
	}
	ban := c.IPScore.BanThreshold
	if ban <= 0 {
		ban = defaultScoreBanThreshold
	}
	if u.points() >= ban {
		return fmt.Errorf("unknown_host.points : %v atteint le seuil de ban (%v), ce qui bannirait au premier accès", u.points(), ban)
	}
	return nil
}

// Probe est une IP dont les accès à des hôtes inconnus sont réguliers : une sonde probable, à exempter plutôt qu'à escalader.
type Probe struct {
	IP              string
	Hits            int64
	IntervalSeconds float64
}

type hitSeries struct {
	ts      [unknownSeriesLen]time.Time
	n       int // accès enregistrés dans ts (au plus unknownSeriesLen)
	next    int
	hits    int64
	regular bool
	gap     time.Duration
	last    time.Time
}

// unknownTracker retient, par IP et à taille fixe, les derniers accès à un hôte inconnu pour y reconnaître une cadence régulière.
type unknownTracker struct {
	mu sync.Mutex
	m  map[string]*hitSeries
}

func newUnknownTracker() *unknownTracker { return &unknownTracker{m: map[string]*hitSeries{}} }

// observe enregistre un accès et dit si la série de l'IP est régulière (et son intervalle moyen).
func (t *unknownTracker) observe(ip string, now time.Time) (regular bool, gap time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[ip]
	if s == nil {
		if len(t.m) >= unknownSeriesCap {
			t.evictLocked()
		}
		s = &hitSeries{}
		t.m[ip] = s
	}
	s.hits++
	s.last = now
	s.ts[s.next] = now
	s.next = (s.next + 1) % unknownSeriesLen
	if s.n < unknownSeriesLen {
		s.n++
	}
	s.regular, s.gap = s.analyse()
	return s.regular, s.gap
}

// analyse : les intervalles entre accès consécutifs, du plus ancien au plus récent, sont-ils presque constants ?
func (s *hitSeries) analyse() (bool, time.Duration) {
	if s.n < regularMinHits {
		return false, 0
	}
	ordered := make([]time.Time, 0, s.n)
	start := 0
	if s.n == unknownSeriesLen {
		start = s.next
	}
	for i := 0; i < s.n; i++ {
		ordered = append(ordered, s.ts[(start+i)%unknownSeriesLen])
	}
	gaps := make([]float64, 0, len(ordered)-1)
	var sum float64
	for i := 1; i < len(ordered); i++ {
		g := ordered[i].Sub(ordered[i-1]).Seconds()
		gaps = append(gaps, g)
		sum += g
	}
	mean := sum / float64(len(gaps))
	if mean < regularMinGap.Seconds() {
		return false, 0
	}
	var sq float64
	for _, g := range gaps {
		sq += (g - mean) * (g - mean)
	}
	if math.Sqrt(sq/float64(len(gaps)))/mean > regularMaxSpread {
		return false, 0
	}
	return true, time.Duration(mean * float64(time.Second))
}

// evictLocked retire une série, de préférence une qui n'est pas régulière et qui n'a pas servi depuis longtemps (échantillon de 16).
func (t *unknownTracker) evictLocked() {
	var victim string
	var oldest time.Time
	n := 0
	for ip, s := range t.m {
		if victim == "" || (!s.regular && s.last.Before(oldest)) {
			victim, oldest = ip, s.last
		}
		if n++; n >= 16 {
			break
		}
	}
	delete(t.m, victim)
}

func (t *unknownTracker) probes() []Probe {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Probe
	for ip, s := range t.m {
		if s.regular {
			out = append(out, Probe{IP: ip, Hits: s.hits, IntervalSeconds: math.Round(s.gap.Seconds()*10) / 10})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hits > out[j].Hits })
	if len(out) > probeSuggestionsMax {
		out = out[:probeSuggestionsMax]
	}
	return out
}

func (t *unknownTracker) forget(ip string) {
	t.mu.Lock()
	delete(t.m, ip)
	t.mu.Unlock()
}

// UnknownHostProbes liste les IP dont les accès à des hôtes inconnus sont réguliers : des sondes probables, que l'administrateur
// peut exempter (unknown_host.probes). Elles ne versent plus de points.
func (e *Engine) UnknownHostProbes() []Probe { return e.unknown.probes() }

// NoteUnknownHost verse à la note de l'IP un accès à un nom sans route ou sans certificat (name : le nom demandé, vide si inconnu).
// Sans effet quand le signal est off, sans score cumulé, ou pour ce qu'on ne bannit jamais : réseaux privés, Cloudflare, liste
// blanche d'Ephor, sondes déclarées. Une IP aux accès réguliers est une sonde probable : elle est proposée à l'exemption, pas notée.
func (e *Engine) NoteUnknownHost(ip, name string) {
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	probes := e.probes
	e.mu.RUnlock()
	if cfg.Enabled && cfg.Seasonal.Active() {
		e.seasonal.Record(seasonal.Entry, ip, 404, "")
	}
	mode := cfg.UnknownHost.mode()
	if !cfg.Enabled || mode == UnknownHostOff || !cfg.IPScore.Enabled || e.banFn == nil {
		return
	}
	if _, ok := bantarget.BanTarget(ip, nil); !ok || wl.allowedIP(ip) || probes.allowedIP(ip) {
		e.inc(threatUnknownHostTotal, "exempt")
		return
	}
	if regular, _ := e.unknown.observe(ip, e.counters.now()); regular {
		e.inc(threatUnknownHostTotal, "regular")
		return
	}
	if mode == UnknownHostDetect {
		e.inc(threatUnknownHostTotal, "shadow")
		if ok, _ := e.sigLog.Allow("unknown_host|" + ip); ok {
			e.log.Info("ephor: accès à un hôte inconnu (mode detect)", "ip", ip, "nom", clipValue(name))
		}
		return
	}
	e.inc(threatUnknownHostTotal, "counted")
	e.scoreBan(ip, "unknown_host", []router.BanSignal{{Name: "unknown_host", Points: cfg.UnknownHost.points(), Value: clipValue(name)}}, cfg)
}

func buildProbes(c UnknownHostConfig) *whitelist {
	var ips []string
	for _, p := range c.Probes {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) != nil || strings.Contains(p, "/") {
			ips = append(ips, p)
		}
	}
	return buildWhitelist(Whitelist{IPs: ips})
}
