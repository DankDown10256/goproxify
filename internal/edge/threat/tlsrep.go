// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"hash/maphash"
	"math"
	"math/bits"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

const (
	tlsRepBits        = 2048
	tlsRepWords       = tlsRepBits / 64
	tlsRepShards      = 16
	tlsRepShardCap    = 256
	tlsRepPersistCap  = 1024
	defaultTLSRepIPs  = 20
	defaultTLSRepReqs = 200
	defaultTLSRepBad  = 0.6
	// minTLSRepWAF : une empreinte dont les requêtes sont mauvaises sans que le WAF en marque jamais une est plutôt une application
	// cassée (un chemin périmé que ses nombreux clients appellent en vain) qu'un outil d'attaque.
	minTLSRepWAF = 0.10
)

// TLSReputationConfig règle l'apprentissage de la réputation des empreintes TLS (ADR 0020, étape 4.c). Par empreinte JA4, la passerelle
// retient le nombre d'IP distinctes (comptage approché), la part de requêtes marquées par le WAF et la part de requêtes en erreur.
// Une empreinte partagée par beaucoup d'IP, dont la plupart des requêtes sont mauvaises, est **proposée** pour
// `custom_lists.tls_fingerprints` avec ses preuves. Rien n'est jamais bloqué automatiquement ; une pile de navigateur connue n'est jamais
// proposée. Désactivée par défaut.
type TLSReputationConfig struct {
	// Enabled apprend la réputation des empreintes et fait des propositions.
	Enabled bool `json:"enabled,omitempty"`
	// MinIPs : IP distinctes qui partagent l'empreinte avant toute proposition (défaut 20).
	MinIPs int `json:"min_ips,omitempty"`
	// MinRequests : requêtes vues avec cette empreinte avant toute proposition (défaut 200).
	MinRequests int `json:"min_requests,omitempty"`
	// MinBadShare : part des requêtes marquées par le WAF ou en erreur (4xx, 5xx) à partir de laquelle l'empreinte est proposée, de 0,3 à
	// 1 (défaut 0,6). Au moins un dixième des requêtes doit avoir déclenché une règle du WAF.
	MinBadShare float64 `json:"min_bad_share,omitempty"`
}

func (c TLSReputationConfig) minIPs() int {
	if c.MinIPs <= 0 {
		return defaultTLSRepIPs
	}
	return c.MinIPs
}

func (c TLSReputationConfig) minRequests() int {
	if c.MinRequests <= 0 {
		return defaultTLSRepReqs
	}
	return c.MinRequests
}

func (c TLSReputationConfig) minBad() float64 {
	if c.MinBadShare <= 0 {
		return defaultTLSRepBad
	}
	return c.MinBadShare
}

// ValidateTLSReputation refuse un réglage qui ne pourrait jamais servir.
func (c Config) ValidateTLSReputation() error {
	t := c.TLSReputation
	if t.MinIPs < 0 || t.MinIPs > 100000 {
		return fmt.Errorf("tls_reputation.min_ips : %d hors de 2 – 100000", t.MinIPs)
	}
	if t.MinIPs == 1 {
		return fmt.Errorf("tls_reputation.min_ips : 1 ne partage rien, au moins 2")
	}
	if t.MinRequests < 0 || t.MinRequests > 10_000_000 {
		return fmt.Errorf("tls_reputation.min_requests : %d hors de 1 – 10000000", t.MinRequests)
	}
	if t.MinBadShare != 0 && (t.MinBadShare < 0.3 || t.MinBadShare > 1) {
		return fmt.Errorf("tls_reputation.min_bad_share : %v hors de 0,3 – 1", t.MinBadShare)
	}
	return nil
}

type tlsRepEntry struct {
	first, last time.Time
	reqs        uint32
	bad         uint32 // marquées par le WAF ou en erreur
	waf         uint32 // marquées par le WAF
	errs        uint32 // en erreur (4xx, 5xx)
	browser     bool
	ips         [tlsRepWords]uint64
}

func (en *tlsRepEntry) distinct() float64 {
	set := 0
	for _, w := range en.ips {
		set += bits.OnesCount64(w)
	}
	switch {
	case set == 0:
		return 0
	case set >= tlsRepBits:
		return tlsRepBits * math.Log(tlsRepBits)
	}
	return -tlsRepBits * math.Log(1-float64(set)/tlsRepBits)
}

type tlsRepShard struct {
	mu sync.Mutex
	m  map[string]*tlsRepEntry
}

type tlsRepTracker struct {
	seed   maphash.Seed
	now    func() time.Time
	shards [tlsRepShards]tlsRepShard
}

func newTLSRepTracker(now func() time.Time) *tlsRepTracker {
	t := &tlsRepTracker{seed: maphash.MakeSeed(), now: now}
	for i := range t.shards {
		t.shards[i].m = map[string]*tlsRepEntry{}
	}
	return t
}

// record verse une requête servie à la réputation de l'empreinte de sa connexion. isBrowser est évalué une seule fois par empreinte.
func (t *tlsRepTracker) record(ja4, ip string, status int, wafMarked bool, isBrowser func(string) bool) {
	now := t.now()
	sh := &t.shards[maphash.String(t.seed, ja4)%tlsRepShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	en := sh.m[ja4]
	if en == nil {
		if len(sh.m) >= tlsRepShardCap {
			evictTLSRep(sh.m)
		}
		en = &tlsRepEntry{first: now}
		if isBrowser != nil {
			en.browser = isBrowser(ja4)
		}
		sh.m[ja4] = en
	}
	en.last = now
	if en.browser {
		// Une pile de navigateur est partagée par des millions de visiteurs : on ne retient que sa présence.
		return
	}
	en.reqs++
	isErr := status >= 400
	if wafMarked {
		en.waf++
	}
	if isErr {
		en.errs++
	}
	if wafMarked || isErr {
		en.bad++
	}
	bit := maphash.String(t.seed, ip) % tlsRepBits
	en.ips[bit/64] |= 1 << (bit % 64)
}

func evictTLSRep(m map[string]*tlsRepEntry) {
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

// TLSProposal est une empreinte proposée pour custom_lists.tls_fingerprints, avec ses preuves.
type TLSProposal struct {
	JA4       string    `json:"ja4"`
	IPs       int       `json:"ips"`
	Requests  int       `json:"requests"`
	BadShare  float64   `json:"bad_share"`
	WAFShare  float64   `json:"waf_share"`
	ErrShare  float64   `json:"error_share"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// TLSReputation est l'état de l'apprentissage et ses propositions.
type TLSReputation struct {
	Enabled bool `json:"enabled"`
	// Tracked : empreintes suivies ; Browsers : parmi elles, celles d'une pile de navigateur connue, jamais proposées.
	Tracked   int           `json:"tracked"`
	Browsers  int           `json:"browsers"`
	Proposals []TLSProposal `json:"proposals"`
}

func (t *tlsRepTracker) proposals(c TLSReputationConfig, listed map[string]bool) TLSReputation {
	out := TLSReputation{Enabled: true, Proposals: []TLSProposal{}}
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for ja4, en := range sh.m {
			out.Tracked++
			if en.browser {
				out.Browsers++
				continue
			}
			if listed[strings.ToLower(ja4)] || int(en.reqs) < c.minRequests() {
				continue
			}
			ips := en.distinct()
			bad, waf := float64(en.bad)/float64(en.reqs), float64(en.waf)/float64(en.reqs)
			if int(ips+0.5) < c.minIPs() || bad < c.minBad() || waf < minTLSRepWAF {
				continue
			}
			out.Proposals = append(out.Proposals, TLSProposal{
				JA4: ja4, IPs: int(ips + 0.5), Requests: int(en.reqs), BadShare: round3(bad), WAFShare: round3(waf),
				ErrShare: round3(float64(en.errs) / float64(en.reqs)), FirstSeen: en.first, LastSeen: en.last,
			})
		}
		sh.mu.Unlock()
	}
	sort.Slice(out.Proposals, func(i, j int) bool {
		a, b := out.Proposals[i], out.Proposals[j]
		if a.IPs != b.IPs {
			return a.IPs > b.IPs
		}
		return a.JA4 < b.JA4
	})
	return out
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// TLSRepState : la réputation d'une empreinte telle qu'elle est conservée sur disque. Aucune IP : une table de bits d'adresses hachées
// avec une graine propre au processus ne se relit pas, et on ne garde donc que les compteurs.
type TLSRepState struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Reqs  uint32    `json:"reqs"`
	Bad   uint32    `json:"bad"`
	WAF   uint32    `json:"waf"`
	Errs  uint32    `json:"errs"`
	IPs   uint32    `json:"ips"`
}

func (t *tlsRepTracker) snapshot() map[string]TLSRepState {
	type kv struct {
		k string
		s TLSRepState
	}
	var all []kv
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for ja4, en := range sh.m {
			if en.browser || en.reqs == 0 {
				continue
			}
			all = append(all, kv{ja4, TLSRepState{First: en.first, Last: en.last, Reqs: en.reqs, Bad: en.bad, WAF: en.waf, Errs: en.errs, IPs: uint32(en.distinct() + 0.5)}})
		}
		sh.mu.Unlock()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].s.Reqs > all[j].s.Reqs })
	if len(all) > tlsRepPersistCap {
		all = all[:tlsRepPersistCap]
	}
	out := make(map[string]TLSRepState, len(all))
	for _, e := range all {
		out[e.k] = e.s
	}
	return out
}

// restore relit les compteurs. Les adresses ne reviennent pas : le nombre d'IP relu est rendu par des bits fictifs répartis, qu'une
// IP réelle fera ensuite croître (un peu de sur-comptage au pire, jamais de sous-comptage).
func (t *tlsRepTracker) restore(in map[string]TLSRepState) {
	for ja4, s := range in {
		if s.Reqs == 0 || s.Bad > s.Reqs || s.WAF > s.Reqs || s.Errs > s.Reqs {
			continue
		}
		sh := &t.shards[maphash.String(t.seed, ja4)%tlsRepShards]
		sh.mu.Lock()
		if _, ok := sh.m[ja4]; !ok && len(sh.m) < tlsRepShardCap {
			en := &tlsRepEntry{first: s.First, last: s.Last, reqs: s.Reqs, bad: s.Bad, waf: s.WAF, errs: s.Errs}
			n := int(s.IPs)
			if n > tlsRepBits-1 {
				n = tlsRepBits - 1
			}
			for i := 0; i < n; i++ {
				bit := uint64(i) * 7919 % tlsRepBits
				en.ips[bit/64] |= 1 << (bit % 64)
			}
			sh.m[ja4] = en
		}
		sh.mu.Unlock()
	}
}

// observeTLSReputation verse la requête servie à la réputation de son empreinte.
func (e *Engine) observeTLSReputation(r *http.Request, ip string, status int, obs *behavior.Observation) {
	fp := tlsfp.FromContext(r.Context())
	if fp == nil || fp.JA4 == "" {
		return
	}
	e.mu.RLock()
	st := e.behavior
	e.mu.RUnlock()
	var browser func(string) bool
	if st != nil {
		browser = st.IsBrowserJA4
	}
	e.tlsrep.record(fp.JA4, ip, status, obs.WAFScore() > 0, browser)
}

// TLSReputation rend l'état de l'apprentissage et les empreintes proposées. Une empreinte déjà dans custom_lists.tls_fingerprints n'est
// pas reproposée.
func (e *Engine) TLSReputation() TLSReputation {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if !cfg.Enabled || !cfg.TLSReputation.Enabled {
		return TLSReputation{Proposals: []TLSProposal{}}
	}
	listed := map[string]bool{}
	for _, f := range cfg.CustomLists.TLSFingerprints {
		listed[strings.ToLower(strings.TrimSpace(f))] = true
	}
	return e.tlsrep.proposals(cfg.TLSReputation, listed)
}
