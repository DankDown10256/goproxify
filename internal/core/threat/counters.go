// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"sync"
	"time"
)

// counterStore gère les compteurs par IP en mémoire (rate + erreurs 4xx + déclenchements rate).
type counterStore struct {
	mu          sync.Mutex
	rate        map[string]*rateCounter
	errors      map[string]*eventWindow
	rateTrigger map[string]*eventWindow // déclenchements signal "rate" par IP
	lastGC      time.Time
}

func newCounterStore() *counterStore {
	return &counterStore{
		rate:        make(map[string]*rateCounter),
		errors:      make(map[string]*eventWindow),
		rateTrigger: make(map[string]*eventWindow),
	}
}

// rateExceeded retourne true si l'IP dépasse le seuil de requêtes/seconde.
func (s *counterStore) rateExceeded(ip string, limit float64, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()

	rc, ok := s.rate[ip]
	if !ok {
		rc = &rateCounter{window: window}
		s.rate[ip] = rc
	}
	return rc.record(limit)
}

// errorExceeded retourne true si l'IP a dépassé le seuil d'erreurs 4xx dans la fenêtre.
func (s *counterStore) errorExceeded(ip string, threshold int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()

	ew, ok := s.errors[ip]
	if !ok {
		ew = &eventWindow{window: window}
		s.errors[ip] = ew
	}
	ew.record()
	return ew.count() >= threshold
}

func (s *counterStore) resetErrors(ip string) {
	s.mu.Lock()
	delete(s.errors, ip)
	s.mu.Unlock()
}

// rateTriggerExceeded enregistre un déclenchement du signal "rate" pour l'IP
// et retourne true si le nombre de déclenchements dans la fenêtre atteint le seuil.
func (s *counterStore) rateTriggerExceeded(ip string, threshold int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ew, ok := s.rateTrigger[ip]
	if !ok {
		ew = &eventWindow{window: window}
		s.rateTrigger[ip] = ew
	}
	ew.record()
	return ew.count() >= threshold
}

func (s *counterStore) resetRateTrigger(ip string) {
	s.mu.Lock()
	delete(s.rateTrigger, ip)
	s.mu.Unlock()
}

// gcLocked nettoie les entrées inactives (appelé avec le lock).
func (s *counterStore) gcLocked() {
	now := time.Now()
	if now.Sub(s.lastGC) < 5*time.Minute {
		return
	}
	s.lastGC = now
	for ip, rc := range s.rate {
		if now.Sub(rc.lastSeen) > 10*time.Minute {
			delete(s.rate, ip)
		}
	}
	for ip, ew := range s.errors {
		if now.Sub(ew.lastSeen) > 10*time.Minute {
			delete(s.errors, ip)
		}
	}
	for ip, ew := range s.rateTrigger {
		if now.Sub(ew.lastSeen) > 10*time.Minute {
			delete(s.rateTrigger, ip)
		}
	}
}

// ── Token bucket pour le rate ─────────────────────────────────────────────────

type rateCounter struct {
	tokens   float64
	max      float64
	lastFill time.Time
	lastSeen time.Time
	window   time.Duration
}

func (r *rateCounter) record(limit float64) bool {
	now := time.Now()
	r.lastSeen = now

	// Calcul du max depuis la fenêtre (ex: 100 req/s sur 1s = max 100 tokens).
	r.max = limit

	if r.lastFill.IsZero() {
		r.lastFill = now
		r.tokens = r.max - 1
		return false
	}

	elapsed := now.Sub(r.lastFill).Seconds()
	r.lastFill = now
	r.tokens += elapsed * limit
	if r.tokens > r.max {
		r.tokens = r.max
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
