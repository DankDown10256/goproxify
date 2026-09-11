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
// Un goroutine de nettoyage est lancé en arrière-plan.
func NewStore(window time.Duration) *Store {
	s := &Store{
		profiles: make(map[string]*Profile),
		window:   window,
	}
	go s.gcLoop()
	return s
}

// Record enregistre un événement pour une IP et retourne le score comportemental actuel.
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

	// Purge des événements hors fenêtre.
	cutoff := ev.At.Add(-s.window)
	i := 0
	for i < len(p.events) && p.events[i].At.Before(cutoff) {
		i++
	}
	p.events = append(p.events[i:], ev)

	return analyze(p.events)
}

// analyze calcule le score comportemental à partir des événements de la fenêtre.
func analyze(events []Event) (total int, signals []Signal) {
	n := len(events)
	if n == 0 {
		return 0, nil
	}

	// Compteurs
	var (
		count4xx     int
		wafScoreSum  int
		postCount    int
		paths        = make(map[string]struct{}, n)
		uas          = make(map[string]struct{}, 4)
		timestamps   = make([]time.Time, 0, n)
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
	// Détecte les attaques fragmentées : plusieurs requêtes faibles = une forte.
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

	// ── Signal 5 : rafale (burst) — entropie temporelle faible ───────────
	// Si >30 req dans les 10 dernières secondes → burst
	if burstCount(timestamps, 10*time.Second) >= 30 {
		add("request_burst", 4)
	}

	// ── Signal 6 : ratio POST anormalement élevé (>70 % sur ≥10 req) ─────
	if n >= 10 && postCount*100/n >= 70 {
		add("high_post_ratio", 2)
	}

	// ── Signal 7 : entropie des paths élevée (chemins très variables) ─────
	if n >= 20 && pathEntropy(paths, n) > 0.85 {
		add("high_path_entropy", 2)
	}

	return total, signals
}

// burstCount retourne le nombre de requêtes dans les `d` dernières secondes.
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

// pathEntropy retourne l'entropie de Shannon normalisée des chemins uniques.
// 1.0 = chaque requête touche un chemin différent (scan pur).
func pathEntropy(paths map[string]struct{}, total int) float64 {
	if total <= 1 || len(paths) <= 1 {
		return 0
	}
	// On n'a que les clés uniques, pas les fréquences individuelles.
	// On approxime : chaque chemin unique = total/unique occurrences.
	unique := float64(len(paths))
	p := unique / float64(total)
	if p <= 0 || p > 1 {
		return 0
	}
	// Entropie normalisée : −(p·log2(p)·unique) / log2(total)
	h := -p * math.Log2(p) * unique / math.Log2(float64(total))
	if h > 1 {
		h = 1
	}
	return h
}

// gcLoop nettoie les profils inactifs toutes les 5 minutes.
func (s *Store) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.gc()
	}
}

func (s *Store) gc() {
	cutoff := time.Now().Add(-s.window * 2)
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
