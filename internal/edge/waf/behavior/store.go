// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package behavior est le magasin comportemental de la passerelle (ADR 0011) : une fenêtre glissante par IP, alimentée par
// toutes les requêtes que voit Ephor, avec le score du WAF, et d'où sortent des signaux de comportement. Un seul magasin par
// passerelle : Ephor y verse chaque requête, le WAF y ajoute le score de ses règles, CrowdSec ses décisions.
package behavior

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
)

const (
	defaultWindow = 60 * time.Second

	// Plafonds mémoire : un profil garde au plus maxEventsPerProfile événements compacts (une trentaine d'octets), le magasin au
	// plus maxProfiles profils. Passé le plafond, la plus ancienne information cède la place (fail-open, jamais d'épuisement).
	maxEventsPerProfile = 128
	maxProfiles         = 50000
	maxSubnetEvents     = 512
	maxSubnets          = 20000
	maxASNEvents        = 1024
	maxASNs             = 5000

	// asnWindowFactor : l'agrégat par ASN regarde une attaque distribuée « lente », sur dix fenêtres.
	asnWindowFactor = 10

	// analyseTTL : tant que rien n'a changé, l'analyse d'une IP est réutilisée (la vérification avant la requête suit
	// immédiatement l'enregistrement de la précédente).
	analyseTTL = time.Second
)

// Event représente une requête observée.
type Event struct {
	At       time.Time
	WafScore int    // score WAF de la requête (0 si aucun match)
	Status   int    // code HTTP de la réponse
	Method   string // GET, POST, …
	Path     string
	UA       string
	SourceIP string // IP source réelle, pour agrégation sous-réseau
	TLS      string // empreinte JA4 de la connexion (vide en HTTP clair et en HTTP/3)
	Route    string // route (hôte) qui a servi la requête, pour les références apprises par route
	Page     bool   // page HTML demandée par un navigateur (GET qui accepte text/html)
	Asset    bool   // image, feuille de style, script, police…
}

// Signal est un indicateur comportemental déclenché.
type Signal struct {
	Name  string
	Score int
	// Detect : signal né avec l'ADR 0011 ; il est listé mais ne compte pas dans le score du WAF.
	Detect bool `json:",omitempty"`
	// Cold : la référence apprise dont le signal dépend n'a pas assez d'observations ; il ne compte jamais, quel que soit son mode.
	Cold bool `json:",omitempty"`
}

// HAEntry est le format d'échange HA pour un profil IP : score + expiry + trust.
type HAEntry struct {
	Score     int       `json:"score"`
	ExpiresAt time.Time `json:"expires_at"`
	CleanReqs int64     `json:"clean_reqs,omitempty"`
}

// ProfileInfo est retourné par Profiles() pour la visibilité admin.
type ProfileInfo struct {
	Score      int      `json:"score"`
	Signals    []Signal `json:"signals"`
	TrustBonus int      `json:"trust_bonus"`
	CleanReqs  int64    `json:"clean_requests"`
	IsSubnet   bool     `json:"is_subnet,omitempty"`
}

// HAPayload est échangé entre nœuds HA.
type HAPayload struct {
	Entries map[string]HAEntry `json:"entries"` // ip → entry
}

// rec est un événement réduit à ce que les signaux lisent : les chaînes ne sont gardées que sous forme d'empreinte.
type rec struct {
	at       int64 // UnixNano
	waf      int32
	status   uint16
	flags    uint8
	method   uint8 // 'G' lecture, 'W' écriture, 0 autre
	uaHash   uint32
	pathHash uint32
}

const (
	flagPage uint8 = 1 << iota
	flagAsset
	flagTLSMismatch
)

type extSignal struct {
	points int
	until  time.Time
	cold   bool
}

type analysis struct {
	version uint64
	at      time.Time
	score   int
	signals []Signal
	valid   bool
}

// Profile contient l'historique glissant d'une IP.
type Profile struct {
	mu            sync.Mutex
	events        []rec
	cleanRequests int64 // compteur cumulatif de requêtes propres (non-fenêtré)
	ext           map[string]extSignal
	asn           uint32
	asnDone       bool
	version       uint64
	cache         analysis
}

type subRec struct {
	at int64
	ip uint32
}

// subnetProfile agrège les événements de toutes les IPs d'un sous-réseau /24 (/48 IPv6).
type subnetProfile struct {
	mu     sync.Mutex
	events []subRec
}

type asnRec struct {
	at  int64
	ip  uint32
	bad bool
}

// asnProfile agrège les événements de toutes les IP d'un même ASN, sur une fenêtre dix fois plus longue.
type asnProfile struct {
	mu     sync.Mutex
	events []asnRec
}

// Store conserve les profils par IP avec nettoyage périodique.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
	window   time.Duration
	now      func() time.Time

	subnetMu sync.RWMutex
	subnets  map[string]*subnetProfile // subnet key → profil agrégé

	asnMu    sync.RWMutex
	asnProfs map[uint32]*asnProfile

	asnLookup atomic.Pointer[func(ip string) uint32] // nil = pas de base ASN : pas d'agrégat par ASN
	tlsTable  atomic.Pointer[TLSTable]
	refs      *References
	trust     *trustBook
}

// NewStore crée un store comportemental.
// window : durée de la fenêtre glissante (ex. 60s).
func NewStore(window time.Duration) *Store {
	s := newStore(window)
	go s.gcLoop()
	return s
}

func newStore(window time.Duration) *Store {
	if window <= 0 {
		window = defaultWindow
	}
	s := &Store{
		profiles: make(map[string]*Profile),
		subnets:  make(map[string]*subnetProfile),
		asnProfs: make(map[uint32]*asnProfile),
		window:   window,
		now:      time.Now,
		refs:     newReferences(),
		trust:    newTrustBook(),
	}
	s.tlsTable.Store(defaultTLSTable())
	return s
}

// SetClock remplace l'horloge du magasin (rejeu d'access logs et tests de séries temporelles).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Window retourne la fenêtre glissante du magasin.
func (s *Store) Window() time.Duration { return s.window }

// SetASNLookup branche la base ASN de la passerelle ; nil la retire. La fonction rend 0 quand l'adresse est inconnue.
func (s *Store) SetASNLookup(fn func(ip string) uint32) {
	if fn == nil {
		s.asnLookup.Store(nil)
		return
	}
	s.asnLookup.Store(&fn)
}

// ASNEnabled indique si une base ASN est branchée.
func (s *Store) ASNEnabled() bool { return s.asnLookup.Load() != nil }

// subnetKey retourne la clé de sous-réseau d'une IP (/24 pour IPv4, /48 pour IPv6).
func subnetKey(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4[:3].String() + ".0/24"
	}
	// IPv6 : /48
	masked := parsed.Mask(net.CIDRMask(48, 128))
	return masked.String() + "/48"
}

func h32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func methodClass(m string) uint8 {
	switch m {
	case "GET", "HEAD", "OPTIONS", "":
		return 'G'
	case "POST", "PUT", "PATCH", "DELETE":
		return 'W'
	}
	return 0
}

func (s *Store) compact(ev Event) rec {
	r := rec{
		at:       ev.At.UnixNano(),
		waf:      int32(ev.WafScore),
		status:   uint16(ev.Status),
		method:   methodClass(ev.Method),
		uaHash:   h32(ev.UA),
		pathHash: h32(ev.Path),
	}
	if ev.Page {
		r.flags |= flagPage
	}
	if ev.Asset {
		r.flags |= flagAsset
	}
	if ev.TLS != "" && ev.UA != "" && s.tlsTable.Load().Mismatch(ev.UA, ev.TLS) {
		r.flags |= flagTLSMismatch
	}
	return r
}

// Score retourne le score comportemental actuel d'une IP SANS enregistrer d'événement : celui du WAF, qui ne compte que
// les signaux historiques. Inclut la contribution du sous-réseau si celui-ci est suspect.
func (s *Store) Score(ip string) (score int, signals []Signal) {
	return s.score(ip, s.now())
}

func (s *Store) score(ip string, now time.Time) (int, []Signal) {
	score, signals := 0, []Signal(nil)
	s.mu.RLock()
	p, ok := s.profiles[ip]
	s.mu.RUnlock()
	if ok {
		p.mu.Lock()
		score, signals = s.analysed(p, ip, now)
		p.mu.Unlock()
	}
	if sc, sg := s.subnetSignals(ip, now); sc > 0 || len(sg) > 0 {
		score += sc
		signals = append(append([]Signal(nil), signals...), sg...)
	}
	return score, signals
}

// Signals retourne tous les signaux actuels d'une IP, y compris ceux qui ne comptent pas dans le score du WAF.
func (s *Store) Signals(ip string) []Signal {
	_, sg := s.score(ip, s.now())
	return sg
}

// analysed réutilise l'analyse de l'IP tant que son historique n'a pas changé. p.mu doit être tenu.
func (s *Store) analysed(p *Profile, ip string, now time.Time) (int, []Signal) {
	if p.cache.valid && p.cache.version == p.version && now.Sub(p.cache.at) < analyseTTL && !now.Before(p.cache.at) {
		return p.cache.score, p.cache.signals
	}
	purge(p, now, s.window)
	score, signals := s.analyze(p, ip, now)
	p.cache = analysis{version: p.version, at: now, score: score, signals: signals, valid: true}
	return score, signals
}

func (s *Store) subnetSignals(ip string, now time.Time) (int, []Signal) {
	key := subnetKey(ip)
	if key == "" {
		return 0, nil
	}
	s.subnetMu.RLock()
	sp, ok := s.subnets[key]
	s.subnetMu.RUnlock()
	if !ok {
		return 0, nil
	}
	sp.mu.Lock()
	purgeSubnet(sp, now, s.window)
	sc, sg := analyzeSubnet(sp)
	sp.mu.Unlock()
	return sc, sg
}

// Record enregistre un événement pour une IP et retourne le score mis à jour (celui du WAF).
func (s *Store) Record(ip string, ev Event) (score int, signals []Signal) {
	if ev.At.IsZero() {
		ev.At = s.now()
	}
	r := s.compact(ev)

	s.mu.Lock()
	p, ok := s.profiles[ip]
	if !ok {
		if len(s.profiles) >= maxProfiles {
			s.evictLocked(ev.At)
		}
		p = &Profile{}
		s.profiles[ip] = p
	}
	s.mu.Unlock()

	p.mu.Lock()
	purge(p, ev.At, s.window)
	if len(p.events) >= maxEventsPerProfile {
		n := copy(p.events, p.events[maxEventsPerProfile/4:])
		p.events = p.events[:n]
	}
	p.events = append(p.events, r)
	p.version++
	clean := ev.WafScore == 0 && ev.Status >= 200 && ev.Status < 400
	if clean {
		p.cleanRequests++
	}
	score, signals = s.analysed(p, ip, ev.At)
	if !p.asnDone {
		p.asnDone = true
		if lookup := s.asnLookup.Load(); lookup != nil {
			p.asn = (*lookup)(ip)
		}
	}
	asn := p.asn
	p.mu.Unlock()

	s.trust.observe(ip, ev.At, clean, score > 0)
	s.recordSubnet(ip, ev.At)
	if asn != 0 {
		s.recordASN(asn, ip, ev)
	}
	if d := s.refs.observe(ip, ev, len(signals) > 0); d != nil {
		// Le signal vit jusqu'à la fin de la minute dont le compte a dépassé le débit normal.
		until := time.Unix(0, (ev.At.UnixNano()/int64(time.Minute)+1)*int64(time.Minute))
		s.addExt(ip, SignalRateDeviation, 3, until, d.cold)
	}
	return score, signals
}

func (s *Store) recordSubnet(ip string, at time.Time) {
	key := subnetKey(ip)
	if key == "" {
		return
	}
	s.subnetMu.Lock()
	sp, ok := s.subnets[key]
	if !ok {
		if len(s.subnets) >= maxSubnets {
			for k := range s.subnets {
				delete(s.subnets, k)
				break
			}
		}
		sp = &subnetProfile{}
		s.subnets[key] = sp
	}
	s.subnetMu.Unlock()
	sp.mu.Lock()
	purgeSubnet(sp, at, s.window)
	if len(sp.events) >= maxSubnetEvents {
		n := copy(sp.events, sp.events[maxSubnetEvents/4:])
		sp.events = sp.events[:n]
	}
	sp.events = append(sp.events, subRec{at: at.UnixNano(), ip: h32(ip)})
	sp.mu.Unlock()
}

func (s *Store) recordASN(asn uint32, ip string, ev Event) {
	s.asnMu.Lock()
	ap, ok := s.asnProfs[asn]
	if !ok {
		if len(s.asnProfs) >= maxASNs {
			for k := range s.asnProfs {
				delete(s.asnProfs, k)
				break
			}
		}
		ap = &asnProfile{}
		s.asnProfs[asn] = ap
	}
	s.asnMu.Unlock()
	ap.mu.Lock()
	purgeASN(ap, ev.At, s.window*asnWindowFactor)
	if len(ap.events) >= maxASNEvents {
		n := copy(ap.events, ap.events[maxASNEvents/4:])
		ap.events = ap.events[:n]
	}
	ap.events = append(ap.events, asnRec{at: ev.At.UnixNano(), ip: h32(ip), bad: ev.WafScore > 0 || (ev.Status >= 400 && ev.Status < 500)})
	ap.mu.Unlock()
}

// evictLocked libère de la place : d'abord les profils inactifs, sinon un profil arbitraire. s.mu doit être tenu.
func (s *Store) evictLocked(now time.Time) {
	cutoff := now.Add(-s.window).UnixNano()
	for ip, p := range s.profiles {
		p.mu.Lock()
		idle := len(p.events) == 0 || p.events[len(p.events)-1].at < cutoff
		p.mu.Unlock()
		if idle {
			delete(s.profiles, ip)
		}
	}
	if len(s.profiles) < maxProfiles {
		return
	}
	for ip := range s.profiles {
		delete(s.profiles, ip)
		return
	}
}

// AddSignal ajoute à l'IP un signal venu d'ailleurs (décision de CrowdSec…) valable jusqu'à until.
func (s *Store) AddSignal(ip, name string, points int, until time.Time) {
	s.addExt(ip, name, points, until, false)
}

func (s *Store) addExt(ip, name string, points int, until time.Time, cold bool) {
	if points <= 0 || !until.After(s.now()) {
		return
	}
	s.mu.Lock()
	p, ok := s.profiles[ip]
	if !ok {
		if len(s.profiles) >= maxProfiles {
			s.evictLocked(s.now())
		}
		p = &Profile{}
		s.profiles[ip] = p
	}
	s.mu.Unlock()
	p.mu.Lock()
	if p.ext == nil {
		p.ext = map[string]extSignal{}
	}
	if cur, ok := p.ext[name]; !ok || cur.points <= points || cur.until.Before(until) {
		p.ext[name] = extSignal{points: points, until: until, cold: cold}
	}
	p.version++
	p.mu.Unlock()
}

// BuildHAPayload construit le payload à envoyer aux nœuds pairs.
// N'envoie que les IPs avec un score > 0 encore actives dans la fenêtre.
func (s *Store) BuildHAPayload() HAPayload {
	now := s.now()

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make(map[string]HAEntry, len(s.profiles))
	for ip, p := range s.profiles {
		p.mu.Lock()
		if exp, ok := s.expiry(p, now); ok {
			// Le score envoyé ne contient pas le signal reçu d'un pair : le renvoyer l'entretiendrait indéfiniment.
			if score := s.ownScore(p, ip, now); score > 0 {
				entries[ip] = HAEntry{Score: score, ExpiresAt: exp, CleanReqs: p.cleanRequests}
			}
		}
		p.mu.Unlock()
	}
	return HAPayload{Entries: entries}
}

// expiry : la fin de validité du profil, s'il est encore actif dans la fenêtre. p.mu doit être tenu.
func (s *Store) expiry(p *Profile, now time.Time) (time.Time, bool) {
	if len(p.events) == 0 {
		return time.Time{}, false
	}
	last := time.Unix(0, p.events[len(p.events)-1].at)
	if !last.After(now.Add(-s.window)) {
		return time.Time{}, false
	}
	return last.Add(s.window), true
}

// ownScore : le score du profil sans le signal d'un pair. p.mu doit être tenu.
func (s *Store) ownScore(p *Profile, ip string, now time.Time) int {
	_, signals := s.analysed(p, ip, now)
	n := 0
	for _, sg := range signals {
		if !sg.Detect && sg.Name != SignalHAPeer {
			n += sg.Score
		}
	}
	return n
}

// ApplyHAPayload fusionne un payload HA reçu d'un pair, par maximum : si le pair a un score plus élevé que le nôtre, la
// différence entre en signal « ha_peer » jusqu'à l'expiration de l'entrée. Rejouer la même entrée ne change rien, et deux
// passerelles qui s'échangent leurs notes ne les gonflent pas l'une l'autre (une somme le ferait).
func (s *Store) ApplyHAPayload(p HAPayload) {
	now := s.now()
	for ip, entry := range p.Entries {
		if entry.ExpiresAt.Before(now) {
			continue // données périmées
		}
		s.mu.RLock()
		local, ok := s.profiles[ip]
		s.mu.RUnlock()
		own := 0
		if ok {
			local.mu.Lock()
			own = s.ownScore(local, ip, now)
			local.mu.Unlock()
		}
		if entry.Score > own {
			s.AddSignal(ip, SignalHAPeer, entry.Score-own, entry.ExpiresAt)
		}
		s.trust.raiseClean(ip, entry.CleanReqs, now)
		if ok {
			local.mu.Lock()
			if entry.CleanReqs > local.cleanRequests {
				local.cleanRequests = entry.CleanReqs
			}
			local.mu.Unlock()
		}
	}
}

// Snapshot retourne un HAPayload pouvant être sérialisé pour la persistance.
func (s *Store) Snapshot() HAPayload {
	return s.BuildHAPayload()
}

// RestoreSnapshot réinjecte un snapshot (chargé depuis le disque au démarrage) : le score repart en signal « restored »,
// valable jusqu'à l'expiration de l'entrée.
func (s *Store) RestoreSnapshot(snap HAPayload) {
	now := s.now()
	for ip, entry := range snap.Entries {
		if entry.ExpiresAt.Before(now) {
			continue
		}
		if entry.Score > 0 {
			s.AddSignal(ip, SignalRestored, entry.Score, entry.ExpiresAt)
		}
		if entry.CleanReqs > 0 {
			s.mu.Lock()
			p, ok := s.profiles[ip]
			if !ok {
				p = &Profile{}
				s.profiles[ip] = p
			}
			s.mu.Unlock()
			p.mu.Lock()
			if entry.CleanReqs > p.cleanRequests {
				p.cleanRequests = entry.CleanReqs
			}
			p.mu.Unlock()
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func purge(p *Profile, now time.Time, window time.Duration) {
	cutoff := now.Add(-window).UnixNano()
	i := 0
	for i < len(p.events) && p.events[i].at < cutoff {
		i++
	}
	if i > 0 {
		p.events = p.events[:copy(p.events, p.events[i:])]
		p.version++
	}
}

func purgeSubnet(sp *subnetProfile, now time.Time, window time.Duration) {
	cutoff := now.Add(-window).UnixNano()
	i := 0
	for i < len(sp.events) && sp.events[i].at < cutoff {
		i++
	}
	if i > 0 {
		sp.events = sp.events[:copy(sp.events, sp.events[i:])]
	}
}

func purgeASN(ap *asnProfile, now time.Time, window time.Duration) {
	cutoff := now.Add(-window).UnixNano()
	i := 0
	for i < len(ap.events) && ap.events[i].at < cutoff {
		i++
	}
	if i > 0 {
		ap.events = ap.events[:copy(ap.events, ap.events[i:])]
	}
}

// analyzeSubnet retourne le score et les signaux du profil sous-réseau.
func analyzeSubnet(sp *subnetProfile) (score int, signals []Signal) {
	n := len(sp.events)
	if n < 10 {
		return 0, nil
	}
	ips := make(map[uint32]struct{}, 16)
	for _, e := range sp.events {
		ips[e.ip] = struct{}{}
	}
	uniqueIPs := len(ips)
	if uniqueIPs < 5 {
		return 0, nil
	}
	// Signal : ≥5 IPs distinctes dans le sous-réseau avec activité coordonnée.
	s := 5
	if uniqueIPs >= 10 {
		s = 8
	}
	return s, []Signal{{Name: SignalDistributedScan, Score: s}}
}

func (s *Store) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.gc()
	}
}

func (s *Store) gc() {
	now := s.now()
	cutoff := now.Add(-s.window).UnixNano()
	s.mu.Lock()
	for ip, p := range s.profiles {
		p.mu.Lock()
		active := len(p.events) > 0 && p.events[len(p.events)-1].at > cutoff
		for name, e := range p.ext {
			if !e.until.After(now) {
				delete(p.ext, name)
			} else {
				active = true
			}
		}
		p.mu.Unlock()
		if !active {
			delete(s.profiles, ip)
		}
	}
	metrics.WAF.ProfilesActive.Set(float64(len(s.profiles)))
	s.mu.Unlock()

	s.subnetMu.Lock()
	for key, sp := range s.subnets {
		sp.mu.Lock()
		active := len(sp.events) > 0 && sp.events[len(sp.events)-1].at > cutoff
		sp.mu.Unlock()
		if !active {
			delete(s.subnets, key)
		}
	}
	s.subnetMu.Unlock()

	asnCutoff := now.Add(-s.window * asnWindowFactor).UnixNano()
	s.asnMu.Lock()
	for key, ap := range s.asnProfs {
		ap.mu.Lock()
		active := len(ap.events) > 0 && ap.events[len(ap.events)-1].at > asnCutoff
		ap.mu.Unlock()
		if !active {
			delete(s.asnProfs, key)
		}
	}
	s.asnMu.Unlock()

	s.trust.gc(now)
	s.refs.gc(now)
}

// Len retourne le nombre de profils IP actifs dans le store.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.profiles)
}

// DeleteProfile supprime manuellement le profil d'une IP (sa fenêtre et ses signaux). La confiance acquise reste : voir Forget.
func (s *Store) DeleteProfile(ip string) {
	s.mu.Lock()
	delete(s.profiles, ip)
	s.mu.Unlock()

	// Les événements de cette IP quittent l'agrégat de son sous-réseau.
	if key := subnetKey(ip); key != "" {
		h := h32(ip)
		s.subnetMu.Lock()
		if sp, ok := s.subnets[key]; ok {
			sp.mu.Lock()
			filtered := sp.events[:0]
			for _, e := range sp.events {
				if e.ip != h {
					filtered = append(filtered, e)
				}
			}
			sp.events = filtered
			sp.mu.Unlock()
			if len(filtered) == 0 {
				delete(s.subnets, key)
			}
		}
		s.subnetMu.Unlock()
	}
}

// Profiles retourne un snapshot des profils actifs avec score, signaux et trust.
// Les profils sous-réseau sont inclus avec le préfixe "subnet:".
func (s *Store) Profiles() map[string]ProfileInfo {
	now := s.now()
	cutoff := now.Add(-s.window).UnixNano()

	s.mu.RLock()
	out := make(map[string]ProfileInfo, len(s.profiles))
	for ip, p := range s.profiles {
		p.mu.Lock()
		active := len(p.events) > 0 && p.events[len(p.events)-1].at > cutoff
		for _, e := range p.ext {
			if e.until.After(now) {
				active = true
			}
		}
		if active {
			score, sigs := s.analysed(p, ip, now)
			if len(sigs) > 0 {
				out[ip] = ProfileInfo{
					Score:      score,
					Signals:    append([]Signal(nil), sigs...),
					TrustBonus: s.trust.bonus(ip, p.cleanRequests, now),
					CleanReqs:  p.cleanRequests,
				}
			}
		}
		p.mu.Unlock()
	}
	s.mu.RUnlock()

	s.subnetMu.RLock()
	for key, sp := range s.subnets {
		sp.mu.Lock()
		if len(sp.events) > 0 && sp.events[len(sp.events)-1].at > cutoff {
			score, sigs := analyzeSubnet(sp)
			if score > 0 {
				out["subnet:"+key] = ProfileInfo{Score: score, Signals: sigs, IsSubnet: true}
			}
		}
		sp.mu.Unlock()
	}
	s.subnetMu.RUnlock()

	return out
}

// NewReplayStore crée un magasin sans tâche de fond, pour rejouer des logs avec une horloge à soi (SetClock).
func NewReplayStore(window time.Duration) *Store { return newStore(window) }
