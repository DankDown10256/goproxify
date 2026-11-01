// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package seasonal

import (
	"sync"
	"time"
)

// Hard est le profil durci d'une route pendant une attaque probable (ADR 0020, étape 3.c) : le plafond de débit que les IP sans
// historique propre ne peuvent pas dépasser. Il est calculé sur ce que la route reçoit d'ordinaire à cette heure, non sur une
// constante : une route d'ordinaire calme est plafonnée bas, une route d'ordinaire chargée haut.
type Hard struct {
	// Rate : requêtes par seconde admises pour l'ensemble des IP sans historique.
	Rate float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newHard(rate float64, now time.Time) *Hard {
	return &Hard{Rate: rate, tokens: rate * 2, last: now}
}

// Allow prélève un jeton ; faux quand le plafond est atteint. La rafale admise vaut deux secondes de débit.
func (h *Hard) Allow(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if d := now.Sub(h.last).Seconds(); d > 0 {
		h.tokens += d * h.Rate
		if max := h.Rate * 2; h.tokens > max {
			h.tokens = max
		}
		h.last = now
	}
	if h.tokens >= 1 {
		h.tokens--
		return true
	}
	return false
}

// Hardened retourne le profil durci de la route, nil quand elle n'est pas durcie. Lecture sans verrou, pour le chemin des requêtes.
func (t *Tracker) Hardened(route string) *Hard {
	if rs, ok := (*t.routes.Load())[route]; ok {
		return rs.hard.Load()
	}
	return nil
}
