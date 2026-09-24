// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"context"
	"time"
)

const (
	defaultTarpitDelay = 5 * time.Second
	maxTarpitDelay     = 30 * time.Second // reste sous les WriteTimeout usuels
	defaultTarpitSlots = 200
)

// TarpitConfig ralentit la réponse aux IP détectées par Sentinel au lieu de refuser
// aussitôt : le bot immobilise ses propres connexions.
type TarpitConfig struct {
	Enabled bool `json:"enabled"`
	// DelayMs : durée de rétention avant la réponse (défaut 5000, max 30000).
	DelayMs int `json:"delay_ms,omitempty"`
	// MaxConcurrent : requêtes retenues en même temps (défaut 200). Au-delà, refus immédiat,
	// sinon le tarpit épuiserait les connexions et goroutines du Core lui-même.
	MaxConcurrent int `json:"max_concurrent,omitempty"`
}

func (c TarpitConfig) delay() time.Duration {
	d := time.Duration(c.DelayMs) * time.Millisecond
	if d <= 0 {
		return defaultTarpitDelay
	}
	return min(d, maxTarpitDelay)
}

func (c TarpitConfig) slots() int {
	if c.MaxConcurrent <= 0 {
		return defaultTarpitSlots
	}
	return c.MaxConcurrent
}

// TarpitWait retient la requête le temps configuré et retourne true si elle a été retenue.
// Retourne false, sans attendre, si le tarpit est désactivé ou saturé : l'appelant doit alors
// refuser immédiatement. Le client qui se déconnecte libère son slot aussitôt.
func (e *Engine) TarpitWait(ctx context.Context) bool {
	e.mu.RLock()
	cfg := e.cfg.Tarpit
	slots := e.tarpitSlots
	e.mu.RUnlock()
	if !cfg.Enabled || slots == nil {
		return false
	}
	select {
	case slots <- struct{}{}:
	default:
		e.inc(threatTarpitTotal, "full")
		return false
	}
	threatTarpitActive.Inc()
	defer func() {
		threatTarpitActive.Dec()
		<-slots
	}()
	e.inc(threatTarpitTotal, "held")
	timer := time.NewTimer(cfg.delay())
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return true
}
