// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// Modes d'un Seuil.
const (
	ThresholdOff    = "off"
	ThresholdDetect = "detect" // l'événement est compté et le dépassement journalisé, jamais appliqué
	ThresholdBlock  = "block"  // le dépassement applique l'action
)

// Actions d'un Seuil.
const (
	ThresholdBan   = "ban"   // ban de l'IP, avec la durée et l'escalade d'Ephor
	ThresholdScore = "score" // verse des points à la note commune (demande ip_score.enabled)
)

const (
	maxThresholdRules  = 50
	maxThresholdCount  = 10000
	minThresholdWindow = time.Second
	maxThresholdWindow = 24 * time.Hour
	thresholdBuckets   = 10 // un compteur par dixième de fenêtre : quelques dizaines d'octets par clé, quelle que soit la fenêtre
	thresholdShards    = 64
	thresholdShardCap  = 4096
)

// ThresholdRule est un Seuil (ADR 0020, étape 2.c) : une règle explicite « N événements en T, action », évaluée sur la réponse que la
// passerelle a rendue. Pas de regex sur du texte : un événement est une réponse qui correspond à un filtre structuré.
//
// Un événement compte pour l'IP (une IPv6 par son /64). Les requêtes qu'Ephor, un ban ou un profil IP ont refusées avant le routage
// ne comptent pas, ni celles des listes blanches d'Ephor.
type ThresholdRule struct {
	// Name identifie le Seuil dans les bans, les métriques et les journaux : minuscules, chiffres, « - » et « _ ».
	Name string `json:"name"`
	// Mode : off | detect (défaut) | block.
	Mode string `json:"mode,omitempty"`
	// Status : codes (« 401 ») ou classes (« 4xx », « 5xx ») ; vide = tous. Plusieurs valeurs : l'une ou l'autre.
	Status []string `json:"status,omitempty"`
	// Paths : préfixes de chemin ; vide = tous.
	Paths []string `json:"paths,omitempty"`
	// Methods : méthodes HTTP ; vide = toutes.
	Methods []string `json:"methods,omitempty"`
	// Hosts : noms de route (hôte de la route qui a servi la requête) ; vide = tous.
	Hosts []string `json:"hosts,omitempty"`
	// WAF : « hit » = la requête a déclenché une règle du WAF ; « blocked » = le WAF l'a refusée ; vide = sans condition.
	WAF string `json:"waf,omitempty"`
	// Count événements dans Window déclenchent l'action.
	Count  int      `json:"count"`
	Window Duration `json:"window"`
	// Action : ban (défaut) | score.
	Action string `json:"action,omitempty"`
	// Points : points versés à la note par un dépassement (action score ; défaut 4).
	Points float64 `json:"points,omitempty"`
}

// ThresholdsConfig règle les Seuils d'Ephor : le jeu fourni et les Seuils de l'administrateur.
type ThresholdsConfig struct {
	// Mode des Seuils fournis (auth-fail, waf-repeat) : off (défaut) | detect | block.
	Mode string `json:"mode,omitempty"`
	// Rules : les Seuils de l'administrateur, chacun avec son propre mode.
	Rules []ThresholdRule `json:"rules,omitempty"`
}

// providedThresholds est le jeu fourni. Leur mode est celui de ThresholdsConfig.Mode.
var providedThresholds = []ThresholdRule{
	{
		// Les échecs d'authentification que le score pondéré des erreurs 4xx ignore à dessein (401, 403) : dix sur un point d'entrée
		// de connexion en cinq minutes. Un 403 que le WAF a prononcé n'en est pas un.
		Name: "auth-fail", Status: []string{"401", "403"}, WAF: "!blocked", Count: 10, Window: Duration{5 * time.Minute}, Action: ThresholdBan,
		Paths: []string{"/login", "/signin", "/sign-in", "/auth", "/api/auth", "/api/login", "/user/login", "/account/login", "/oauth/token", "/wp-login.php", "/xmlrpc.php"},
	},
	{
		// Un client dont cinq requêtes en dix minutes déclenchent une règle du WAF insiste.
		Name: "waf-repeat", WAF: "hit", Count: 5, Window: Duration{10 * time.Minute}, Action: ThresholdBan,
	},
}

func normThresholdMode(m string, def string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case ThresholdOff:
		return ThresholdOff
	case ThresholdBlock:
		return ThresholdBlock
	case ThresholdDetect:
		return ThresholdDetect
	}
	return def
}

func (r ThresholdRule) mode(def string) string { return normThresholdMode(r.Mode, def) }

func (r ThresholdRule) points() float64 {
	if r.Points <= 0 {
		return 4
	}
	return r.Points
}

func validThresholdName(n string) bool {
	if n == "" || len(n) > 40 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validStatusToken(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) == 3 && s[1] == 'x' && s[2] == 'x' {
		return s[0] >= '1' && s[0] <= '5'
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 100 && n <= 599
}

// ValidateThresholds refuse un Seuil mal formé ou qui ne pourrait pas servir.
func (c Config) ValidateThresholds() error {
	t := c.Thresholds
	switch strings.ToLower(strings.TrimSpace(t.Mode)) {
	case "", ThresholdOff, ThresholdDetect, ThresholdBlock:
	default:
		return fmt.Errorf("thresholds.mode : %q invalide (attendu : off | detect | block)", t.Mode)
	}
	if len(t.Rules) > maxThresholdRules {
		return fmt.Errorf("thresholds.rules : %d Seuils, au plus %d", len(t.Rules), maxThresholdRules)
	}
	seen := map[string]bool{}
	for _, p := range providedThresholds {
		seen[p.Name] = true
	}
	for i, r := range t.Rules {
		what := fmt.Sprintf("thresholds.rules[%d]", i)
		if !validThresholdName(r.Name) {
			return fmt.Errorf("%s.name : %q invalide (minuscules, chiffres, - et _, 40 caractères au plus)", what, r.Name)
		}
		if seen[r.Name] {
			return fmt.Errorf("%s.name : %q est déjà pris (Seuil fourni ou doublon)", what, r.Name)
		}
		seen[r.Name] = true
		switch strings.ToLower(strings.TrimSpace(r.Mode)) {
		case "", ThresholdOff, ThresholdDetect, ThresholdBlock:
		default:
			return fmt.Errorf("%s.mode : %q invalide (attendu : off | detect | block)", what, r.Mode)
		}
		switch strings.ToLower(strings.TrimSpace(r.Action)) {
		case "", ThresholdBan, ThresholdScore:
		default:
			return fmt.Errorf("%s.action : %q invalide (attendu : ban | score)", what, r.Action)
		}
		if strings.EqualFold(strings.TrimSpace(r.Action), ThresholdScore) && r.mode(ThresholdDetect) != ThresholdOff && !c.IPScore.Enabled {
			return fmt.Errorf("%s : l'action score demande ip_score.enabled", what)
		}
		if r.Points < 0 || r.Points > 50 {
			return fmt.Errorf("%s.points : %v hors de 0 – 50", what, r.Points)
		}
		if r.Count < 1 || r.Count > maxThresholdCount {
			return fmt.Errorf("%s.count : %d hors de 1 – %d", what, r.Count, maxThresholdCount)
		}
		if w := r.Window.Duration; w < minThresholdWindow || w > maxThresholdWindow {
			return fmt.Errorf("%s.window : %s hors de %s – %s", what, w, minThresholdWindow, maxThresholdWindow)
		}
		for _, s := range r.Status {
			if !validStatusToken(s) {
				return fmt.Errorf("%s.status : %q n'est ni un code (401) ni une classe (4xx)", what, s)
			}
		}
		for _, p := range r.Paths {
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("%s.paths : %q doit commencer par /", what, p)
			}
		}
		switch r.WAF {
		case "", "hit", "blocked":
		default:
			return fmt.Errorf("%s.waf : %q invalide (attendu : hit | blocked)", what, r.WAF)
		}
	}
	return nil
}

// compiledThreshold est un Seuil prêt à servir.
type compiledThreshold struct {
	rule    ThresholdRule
	mode    string
	codes   map[int]bool
	classes map[int]bool // centaine : 4 pour 4xx
	methods map[string]bool
	hosts   map[string]bool
}

func compileThresholds(c ThresholdsConfig) []*compiledThreshold {
	var out []*compiledThreshold
	add := func(r ThresholdRule, def string) {
		m := r.mode(def)
		if m == ThresholdOff {
			return
		}
		ct := &compiledThreshold{rule: r, mode: m, codes: map[int]bool{}, classes: map[int]bool{}, methods: map[string]bool{}, hosts: map[string]bool{}}
		for _, s := range r.Status {
			s = strings.ToLower(strings.TrimSpace(s))
			if len(s) == 3 && s[1] == 'x' {
				ct.classes[int(s[0]-'0')] = true
			} else if n, err := strconv.Atoi(s); err == nil {
				ct.codes[n] = true
			}
		}
		for _, mth := range r.Methods {
			ct.methods[strings.ToUpper(strings.TrimSpace(mth))] = true
		}
		for _, h := range r.Hosts {
			ct.hosts[strings.ToLower(strings.TrimSpace(h))] = true
		}
		out = append(out, ct)
	}
	if pm := normThresholdMode(c.Mode, ThresholdOff); pm != ThresholdOff {
		for _, p := range providedThresholds {
			p.Mode = pm
			add(p, pm)
		}
	}
	for _, r := range c.Rules {
		add(r, ThresholdDetect)
	}
	return out
}

func (ct *compiledThreshold) matches(r *http.Request, route string, status int, obs *behavior.Observation) bool {
	if len(ct.codes) > 0 || len(ct.classes) > 0 {
		if !ct.codes[status] && !ct.classes[status/100] {
			return false
		}
	}
	if len(ct.methods) > 0 && !ct.methods[r.Method] {
		return false
	}
	if len(ct.hosts) > 0 && !ct.hosts[strings.ToLower(route)] {
		return false
	}
	if len(ct.rule.Paths) > 0 {
		hit := false
		for _, p := range ct.rule.Paths {
			if strings.HasPrefix(r.URL.Path, p) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	switch ct.rule.WAF {
	case "hit":
		if obs.WAFScore() <= 0 {
			return false
		}
	case "blocked":
		if !obs.WAFBlocked() {
			return false
		}
	case "!blocked": // réservé au jeu fourni : un refus du WAF n'est pas un échec d'authentification
		if obs.WAFBlocked() {
			return false
		}
	}
	return true
}

// ── Compteurs ────────────────────────────────────────────────────────────────

// bucketWindow compte les événements d'une fenêtre en dix compteurs, un par dixième de fenêtre : une mémoire fixe par clé.
type bucketWindow struct {
	window time.Duration
	start  time.Time // début du compteur 0
	counts [thresholdBuckets]uint16
	last   time.Time
}

func (b *bucketWindow) width() time.Duration { return b.window / thresholdBuckets }

// advance fait glisser la fenêtre jusqu'à now, en oubliant les compteurs sortis.
func (b *bucketWindow) advance(now time.Time) {
	if b.start.IsZero() {
		b.start = now.Truncate(b.width())
		return
	}
	w := b.width()
	shift := int(now.Sub(b.start) / w)
	if shift < thresholdBuckets {
		return
	}
	move := shift - (thresholdBuckets - 1) // décalage pour que now tombe dans le dernier compteur
	if move >= thresholdBuckets {
		b.counts = [thresholdBuckets]uint16{}
	} else {
		copy(b.counts[:], b.counts[move:])
		for i := thresholdBuckets - move; i < thresholdBuckets; i++ {
			b.counts[i] = 0
		}
	}
	b.start = b.start.Add(time.Duration(move) * w)
}

func (b *bucketWindow) add(now time.Time) int {
	b.last = now
	b.advance(now)
	i := int(now.Sub(b.start) / b.width())
	if i >= thresholdBuckets {
		i = thresholdBuckets - 1
	}
	if i < 0 {
		i = 0
	}
	if b.counts[i] < 65535 {
		b.counts[i]++
	}
	return b.total()
}

func (b *bucketWindow) total() int {
	t := 0
	for _, c := range b.counts {
		t += int(c)
	}
	return t
}

type thresholdShard struct {
	mu sync.Mutex
	m  map[string]*bucketWindow
}

// thresholdStore tient les compteurs de tous les Seuils, par clé « Seuil|IP » : en shards, borné, comme les compteurs d'Ephor.
type thresholdStore struct {
	now    func() time.Time
	shards [thresholdShards]thresholdShard
}

func newThresholdStore(now func() time.Time) *thresholdStore {
	s := &thresholdStore{now: now}
	for i := range s.shards {
		s.shards[i].m = map[string]*bucketWindow{}
	}
	return s
}

func (s *thresholdStore) shard(key string) *thresholdShard {
	h := fnv.New32a()
	h.Write([]byte(key)) //nolint:errcheck
	return &s.shards[h.Sum32()%thresholdShards]
}

// record compte un événement et rend le total de la fenêtre.
func (s *thresholdStore) record(rule string, window time.Duration, ip string) int {
	now := s.now()
	key := rule + "|" + counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.m[key]
	if b == nil || b.window != window {
		if len(sh.m) >= thresholdShardCap {
			evictOldest(sh.m)
		}
		b = &bucketWindow{window: window}
		sh.m[key] = b
	}
	return b.add(now)
}

func (s *thresholdStore) reset(rule, ip string) {
	key := rule + "|" + counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	delete(sh.m, key)
	sh.mu.Unlock()
}

// forget retire l'IP de tous les Seuils (ordre d'effacement RGPD).
func (s *thresholdStore) forget(ip string) {
	suffix := "|" + counterKey(ip)
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k := range sh.m {
			if strings.HasSuffix(k, suffix) {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

// evictOldest retire, parmi quelques entrées, celle qui n'a pas servi depuis le plus longtemps.
func evictOldest(m map[string]*bucketWindow) {
	var victim string
	var oldest time.Time
	n := 0
	for k, b := range m {
		if victim == "" || b.last.Before(oldest) {
			victim, oldest = k, b.last
		}
		if n++; n >= 16 {
			break
		}
	}
	delete(m, victim)
}

// ThresholdState : un compteur de Seuil tel qu'il est conservé sur disque.
type ThresholdState struct {
	Window time.Duration `json:"window"`
	Start  time.Time     `json:"start"`
	Counts []uint16      `json:"counts"`
}

func (s *thresholdStore) snapshot() map[string]ThresholdState {
	now := s.now()
	out := map[string]ThresholdState{}
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, b := range sh.m {
			b.advance(now)
			if b.total() == 0 {
				continue
			}
			out[k] = ThresholdState{Window: b.window, Start: b.start, Counts: append([]uint16(nil), b.counts[:]...)}
		}
		sh.mu.Unlock()
	}
	return out
}

func (s *thresholdStore) restore(in map[string]ThresholdState) {
	now := s.now()
	for k, ts := range in {
		if ts.Window < minThresholdWindow || ts.Window > maxThresholdWindow || len(ts.Counts) != thresholdBuckets {
			continue
		}
		b := &bucketWindow{window: ts.Window, start: ts.Start, last: now}
		copy(b.counts[:], ts.Counts)
		b.advance(now)
		if b.total() == 0 {
			continue
		}
		sh := s.shard(k)
		sh.mu.Lock()
		if _, exists := sh.m[k]; !exists && len(sh.m) < thresholdShardCap {
			sh.m[k] = b
		}
		sh.mu.Unlock()
	}
}

// ── Évaluation ───────────────────────────────────────────────────────────────

// observeThresholds évalue les Seuils sur une réponse rendue : chaque Seuil dont le filtre correspond compte l'événement ; au
// dépassement, l'action s'applique (block) ou est journalisée (detect). route est l'hôte de la route qui a servi la requête.
func (e *Engine) observeThresholds(r *http.Request, ip, route string, status int, obs *behavior.Observation) {
	e.mu.RLock()
	cfg := e.cfg
	rules := e.thresholds
	wl := e.wl
	e.mu.RUnlock()
	if !cfg.Enabled || len(rules) == 0 || wl.allowedIP(ip) || wl.allowedUA(r.Header.Get("User-Agent")) || wl.allowedPath(r.URL.Path) {
		return
	}
	for _, ct := range rules {
		if !ct.matches(r, route, status, obs) {
			continue
		}
		n := e.thresholdCounters.record(ct.rule.Name, ct.rule.Window.Duration, ip)
		if n < ct.rule.Count {
			continue
		}
		e.thresholdCounters.reset(ct.rule.Name, ip)
		e.thresholdTriggered(cfg, ct, ip, n, r)
	}
}

func (e *Engine) thresholdTriggered(cfg Config, ct *compiledThreshold, ip string, n int, r *http.Request) {
	why := fmt.Sprintf("%d événements en %s", n, ct.rule.Window.Duration)
	if ct.mode == ThresholdDetect {
		e.inc(threatThresholdTotal, "shadow")
		if ok, _ := e.sigLog.Allow("seuil|" + ct.rule.Name + "|" + ip); ok {
			e.log.Info("ephor: seuil dépassé (mode detect)", "seuil", ct.rule.Name, "ip", ip, "evenements", n, "fenetre", ct.rule.Window.Duration.String())
		}
		return
	}
	e.inc(threatThresholdTotal, "hit")
	signal := router.BanSignal{Name: "threshold:" + ct.rule.Name, Points: float64(n), Value: clipValue(why)}
	e.log.Warn("ephor: seuil dépassé", "seuil", ct.rule.Name, "ip", ip, "evenements", n, "action", ct.rule.Action)
	if strings.EqualFold(strings.TrimSpace(ct.rule.Action), ThresholdScore) {
		if cfg.IPScore.Enabled && e.banFn != nil {
			signal.Points = ct.rule.points()
			e.scoreBan(ip, "threshold:"+ct.rule.Name, []router.BanSignal{signal}, cfg)
		}
		return
	}
	if e.banFn != nil {
		e.inc(threatBansTotal, "threshold")
		e.banFn(ip, "threat: seuil "+ct.rule.Name, e.banExpiry(ip, cfg), []router.BanSignal{signal})
	}
}

// ThresholdNames liste les Seuils actifs (fournis et de l'administrateur), pour l'affichage.
func (e *Engine) ThresholdNames() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.thresholds))
	for _, ct := range e.thresholds {
		names = append(names, ct.rule.Name+" ("+ct.mode+")")
	}
	sort.Strings(names)
	return names
}
