// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package behavior implémente l'analyse comportementale stateful du WAF.
// Chaque IP accumule des événements dans une fenêtre glissante ;
// un score comportemental est calculé à chaque requête.
package behavior

import (
	"math"
	"sync"
	"time"
)

// Event représente une requête observée.
type Event struct {
	At       time.Time
	WafScore int    // score WAF de la requête (0 si aucun match)
	Status   int    // code HTTP de la réponse
	Method   string // GET, POST, …
	Path     string
	UA       string
}

// Signal est un indicateur comportemental déclenché.
type Signal struct {
	Name  string
	Score int
}

// HAEntry est le format d'échange HA pour un profil IP : score + expiry.
type HAEntry struct {
	Score     int       `json:"score"`
	ExpiresAt time.Time `json:"expires_at"`
}

// HAPayload est échangé entre nœuds HA.
type HAPayload struct {
	Entries map[string]HAEntry `json:"entries"` // ip → entry
}

// Profile contient l'historique glissant d'une IP.
type Profile struct {
	mu     sync.Mutex
	events []Event // fenêtre glissante, purgée à chaque accès
}

// Store conserve les profils par IP avec nettoyage périodique.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
	window   time.Duration
}

// NewStore crée un store comportemental.
// window : durée de la fenêtre glissante (ex. 60s).
func NewStore(window time.Duration) *Store {
	s := &Store{
		profiles: make(map[string]*Profile),
		window:   window,
	}
	go s.gcLoop()
	return s
}

// Score retourne le score comportemental actuel d'une IP SANS enregistrer d'événement.
// Utilisé avant de servir la requête pour décider de bloquer immédiatement.
func (s *Store) Score(ip string) (score int, signals []Signal) {
	s.mu.RLock()
	p, ok := s.profiles[ip]
	s.mu.RUnlock()
	if !ok {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	purgeEvents(p, time.Now(), s.window)
	return analyze(p.events)
}

// Record enregistre un événement pour une IP et retourne le score mis à jour.
func (s *Store) Record(ip string, ev Event) (score int, signals []Signal) {
	s.mu.Lock()
	p, ok := s.profiles[ip]
	if !ok {
		p = &Profile{}
		s.profiles[ip] = p
	}
	s.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	purgeEvents(p, ev.At, s.window)
	p.events = append(p.events, ev)
	return analyze(p.events)
}

// BuildHAPayload construit le payload à envoyer aux nœuds pairs.
// N'envoie que les IPs avec un score > 0 encore actives dans la fenêtre.
func (s *Store) BuildHAPayload() HAPayload {
	now := time.Now()
	cutoff := now.Add(-s.window)

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make(map[string]HAEntry, len(s.profiles))
	for ip, p := range s.profiles {
		p.mu.Lock()
		if len(p.events) > 0 && p.events[len(p.events)-1].At.After(cutoff) {
			score, _ := analyze(p.events)
			if score > 0 {
				entries[ip] = HAEntry{
					Score:     score,
					ExpiresAt: p.events[len(p.events)-1].At.Add(s.window),
				}
			}
		}
		p.mu.Unlock()
	}
	return HAPayload{Entries: entries}
}

// ApplyHAPayload fusionne un payload HA reçu d'un pair.
// Stratégie : on prend le max du score local et du score pair,
// en injectant un événement synthétique si le pair a un score plus élevé.
func (s *Store) ApplyHAPayload(p HAPayload) {
	now := time.Now()
	for ip, entry := range p.Entries {
		if entry.ExpiresAt.Before(now) {
			continue // données périmées
		}
		localScore, _ := s.Score(ip)
		if entry.Score <= localScore {
			continue // on a déjà plus d'info localement
		}
		// WafScore minimum à 8 pour franchir le seuil waf_score_accumulation.
		delta := entry.Score - localScore
		if delta < 8 {
			delta = 8
		}
		synthetic := Event{
			At:       now,
			WafScore: delta,
			Status:   200,
			Method:   "GET",
			Path:     "/",
			UA:       "",
		}
		s.Record(ip, synthetic)
	}
}

// Snapshot retourne un HAPayload pouvant être sérialisé pour la persistance.
// Identique à BuildHAPayload mais inclut toutes les IPs actives (même score=0).
func (s *Store) Snapshot() HAPayload {
	return s.BuildHAPayload()
}

// RestoreSnapshot réinjecte un snapshot (chargé depuis le disque au démarrage).
func (s *Store) RestoreSnapshot(snap HAPayload) {
	// On ne filtre pas sur ExpiresAt pour permettre la restauration immédiate.
	now := time.Now()
	for ip, entry := range snap.Entries {
		if entry.ExpiresAt.Before(now) {
			continue
		}
		delta := entry.Score
		if delta < 1 {
			continue
		}
		if delta < 8 {
			delta = 8
		}
		s.mu.Lock()
		p, ok := s.profiles[ip]
		if !ok {
			p = &Profile{}
			s.profiles[ip] = p
		}
		s.mu.Unlock()
		p.mu.Lock()
		p.events = append(p.events, Event{
			At:       now,
			WafScore: delta,
			Status:   200,
			Method:   "GET",
			Path:     "/",
		})
		p.mu.Unlock()
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func purgeEvents(p *Profile, now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	i := 0
	for i < len(p.events) && p.events[i].At.Before(cutoff) {
		i++
	}
	if i > 0 {
		p.events = p.events[i:]
	}
}

// analyze calcule le score comportemental à partir des événements de la fenêtre.
func analyze(events []Event) (total int, signals []Signal) {
	n := len(events)
	if n == 0 {
		return 0, nil
	}

	var (
		count4xx    int
		wafScoreSum int
		postCount   int
		paths       = make(map[string]struct{}, n)
		uas         = make(map[string]struct{}, 4)
		timestamps  = make([]time.Time, 0, n)
	)

	for _, e := range events {
		if e.Status >= 400 && e.Status < 500 {
			count4xx++
		}
		wafScoreSum += e.WafScore
		if e.Method == "POST" || e.Method == "PUT" || e.Method == "PATCH" {
			postCount++
		}
		if e.Path != "" {
			paths[e.Path] = struct{}{}
		}
		if e.UA != "" {
			uas[e.UA] = struct{}{}
		}
		timestamps = append(timestamps, e.At)
	}

	add := func(name string, score int) {
		signals = append(signals, Signal{name, score})
		total += score
	}

	// ── Signal 1 : taux de 4xx élevé (>40 %) ─────────────────────────────
	if n >= 5 && count4xx*100/n >= 40 {
		add("high_4xx_rate", 4)
	}

	// ── Signal 2 : scan de chemins (>15 paths uniques dans la fenêtre) ────
	if len(paths) >= 15 {
		add("path_scanning", 3)
	}

	// ── Signal 3 : score WAF cumulatif inter-requêtes ─────────────────────
	if wafScoreSum >= 8 {
		s := 3
		if wafScoreSum >= 15 {
			s = 5
		}
		add("waf_score_accumulation", s)
	}

	// ── Signal 4 : rotation de User-Agent (bot qui se camoufle) ──────────
	if len(uas) >= 3 {
		add("ua_rotation", 3)
	}

	// ── Signal 5 : rafale (burst) — >30 req dans les 10 dernières secondes
	if burstCount(timestamps, 10*time.Second) >= 30 {
		add("request_burst", 4)
	}

	// ── Signal 6 : ratio POST anormalement élevé (>70 % sur ≥10 req) ─────
	if n >= 10 && postCount*100/n >= 70 {
		add("high_post_ratio", 2)
	}

	// ── Signal 7 : entropie des paths élevée ─────────────────────────────
	if n >= 20 && pathEntropy(paths, n) > 0.85 {
		add("high_path_entropy", 2)
	}

	return total, signals
}

func burstCount(ts []time.Time, d time.Duration) int {
	if len(ts) == 0 {
		return 0
	}
	cutoff := ts[len(ts)-1].Add(-d)
	count := 0
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Before(cutoff) {
			break
		}
		count++
	}
	return count
}

func pathEntropy(paths map[string]struct{}, total int) float64 {
	if total <= 1 || len(paths) <= 1 {
		return 0
	}
	unique := float64(len(paths))
	p := unique / float64(total)
	if p <= 0 || p > 1 {
		return 0
	}
	h := -p * math.Log2(p) * unique / math.Log2(float64(total))
	if h > 1 {
		h = 1
	}
	return h
}

func (s *Store) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.gc()
	}
}

func (s *Store) gc() {
	cutoff := time.Now().Add(-s.window)
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, p := range s.profiles {
		p.mu.Lock()
		active := len(p.events) > 0 && p.events[len(p.events)-1].At.After(cutoff)
		p.mu.Unlock()
		if !active {
			delete(s.profiles, ip)
		}
	}
}

// Len retourne le nombre de profils IP actifs dans le store.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.profiles)
}

// DeleteProfile supprime manuellement le profil d'une IP.
func (s *Store) DeleteProfile(ip string) {
	s.mu.Lock()
	delete(s.profiles, ip)
	s.mu.Unlock()
}

// Profiles retourne un snapshot des profils actifs : ip → score.
func (s *Store) Profiles() map[string]int {
	now := time.Now()
	cutoff := now.Add(-s.window)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.profiles))
	for ip, p := range s.profiles {
		p.mu.Lock()
		if len(p.events) > 0 && p.events[len(p.events)-1].At.After(cutoff) {
			score, _ := analyze(p.events)
			if score > 0 {
				out[ip] = score
			}
		}
		p.mu.Unlock()
	}
	return out
}
