// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"hash/fnv"
	"net/netip"
	"sync"
	"time"
)

const (
	counterShards   = 64
	maxKeysPerShard = 4096 // ~262k clés suivies au total, par type de compteur
	maxEventsPerKey = 1024
	counterIdleTTL  = 10 * time.Minute
	counterGCPeriod = time.Minute
)

// counterKey normalise l'IP en clé de suivi : les IPv6 sont agrégées par /64,
// sinon un seul préfixe fournit 2^64 adresses (contournement du rate limit et épuisement mémoire).
func counterKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// counterStore gère les compteurs par IP en mémoire (rate + erreurs 4xx + déclenchements rate).
// Découpé en shards pour éviter un mutex global sur le chemin de requête ; chaque shard est borné.
type counterStore struct {
	shards [counterShards]counterShard
}

type counterShard struct {
	mu          sync.Mutex
	rate        map[string]*rateCounter
	errors      map[string]*eventWindow
	rateTrigger map[string]*eventWindow // déclenchements signal "rate" par IP
	lastGC      time.Time
}

func newCounterStore() *counterStore {
	s := &counterStore{}
	for i := range s.shards {
		s.shards[i].rate = make(map[string]*rateCounter)
		s.shards[i].errors = make(map[string]*eventWindow)
		s.shards[i].rateTrigger = make(map[string]*eventWindow)
	}
	return s
}

func (s *counterStore) shard(key string) *counterShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &s.shards[h.Sum32()%counterShards]
}

// makeRoom libère une place si la map est pleine : d'abord les entrées expirées,
// sinon une entrée arbitraire (fail-open plutôt que d'épuiser la mémoire).
func makeRoom[T any](sh *counterShard, m map[string]*T) {
	if len(m) < maxKeysPerShard {
		return
	}
	sh.gcLocked(time.Now())
	if len(m) < maxKeysPerShard {
		return
	}
	for k := range m {
		delete(m, k)
		threatEvictionsTotal.Inc()
		return
	}
}

// rateExceeded retourne true si l'IP dépasse le seuil de requêtes/seconde.
func (s *counterStore) rateExceeded(ip string, limit float64, window time.Duration) bool {
	key := counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.gcLocked(time.Now())

	rc, ok := sh.rate[key]
	if !ok {
		makeRoom(sh, sh.rate)
		rc = &rateCounter{}
		sh.rate[key] = rc
	}
	return rc.record(limit, window)
}

// errorExceeded retourne true si l'IP a dépassé le seuil d'erreurs 4xx dans la fenêtre.
func (s *counterStore) errorExceeded(ip string, threshold int, window time.Duration) bool {
	key := counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.gcLocked(time.Now())

	ew, ok := sh.errors[key]
	if !ok {
		makeRoom(sh, sh.errors)
		ew = &eventWindow{window: window}
		sh.errors[key] = ew
	}
	ew.record()
	return ew.count() >= threshold
}

func (s *counterStore) resetErrors(ip string) {
	key := counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	delete(sh.errors, key)
	sh.mu.Unlock()
}

// rateTriggerExceeded enregistre un déclenchement du signal "rate" pour l'IP
// et retourne true si le nombre de déclenchements dans la fenêtre atteint le seuil.
func (s *counterStore) rateTriggerExceeded(ip string, threshold int, window time.Duration) bool {
	key := counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	ew, ok := sh.rateTrigger[key]
	if !ok {
		makeRoom(sh, sh.rateTrigger)
		ew = &eventWindow{window: window}
		sh.rateTrigger[key] = ew
	}
	ew.record()
	return ew.count() >= threshold
}

func (s *counterStore) resetRateTrigger(ip string) {
	key := counterKey(ip)
	sh := s.shard(key)
	sh.mu.Lock()
	delete(sh.rateTrigger, key)
	sh.mu.Unlock()
}

// size retourne le nombre total de clés suivies (tous compteurs confondus).
func (s *counterStore) size() int {
	n := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		n += len(sh.rate) + len(sh.errors) + len(sh.rateTrigger)
		sh.mu.Unlock()
	}
	return n
}

// gcLocked nettoie les entrées inactives du shard (appelé avec le lock).
func (sh *counterShard) gcLocked(now time.Time) {
	if now.Sub(sh.lastGC) < counterGCPeriod {
		return
	}
	sh.lastGC = now
	for k, rc := range sh.rate {
		if now.Sub(rc.lastSeen) > counterIdleTTL {
			delete(sh.rate, k)
		}
	}
	for k, ew := range sh.errors {
		if now.Sub(ew.lastSeen) > counterIdleTTL {
			delete(sh.errors, k)
		}
	}
	for k, ew := range sh.rateTrigger {
		if now.Sub(ew.lastSeen) > counterIdleTTL {
			delete(sh.rateTrigger, k)
		}
	}
}

// ── Token bucket pour le rate ─────────────────────────────────────────────────

// rateCounter : `limit` req/s en moyenne, avec une capacité de burst de limit×window
// (rate_window = 1s → burst = limit ; 10s → tolère des pics plus longs).
type rateCounter struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

func (r *rateCounter) record(limit float64, window time.Duration) bool {
	now := time.Now()
	r.lastSeen = now

	max := limit * window.Seconds()
	if max < 1 {
		max = 1
	}

	if r.lastFill.IsZero() {
		r.lastFill = now
		r.tokens = max - 1
		return false
	}

	elapsed := now.Sub(r.lastFill).Seconds()
	r.lastFill = now
	r.tokens += elapsed * limit
	if r.tokens > max {
		r.tokens = max
	}
	if r.tokens >= 1 {
		r.tokens--
		return false
	}
	return true
}

// ── Sliding window pour les erreurs ──────────────────────────────────────────

type eventWindow struct {
	events   []time.Time
	window   time.Duration
	lastSeen time.Time
}

func (w *eventWindow) record() {
	now := time.Now()
	w.lastSeen = now
	if len(w.events) >= maxEventsPerKey {
		w.events = w.events[1:]
	}
	w.events = append(w.events, now)
}

func (w *eventWindow) count() int {
	now := time.Now()
	cutoff := now.Add(-w.window)
	// Compacter : retirer les événements hors fenêtre.
	i := 0
	for i < len(w.events) && w.events[i].Before(cutoff) {
		i++
	}
	w.events = w.events[i:]
	return len(w.events)
}
