// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Balancer choisit un backend pour chaque requête.
type Balancer interface {
	Next(r *http.Request) *router.Backend
}

// ---- Round Robin --------------------------------------------------------

type roundRobin struct {
	backends []router.Backend
	idx      atomic.Uint64
}

func newRoundRobin(bs []router.Backend) *roundRobin {
	return &roundRobin{backends: bs}
}

func (rr *roundRobin) Next(_ *http.Request) *router.Backend {
	if len(rr.backends) == 0 {
		return nil
	}
	i := rr.idx.Add(1) - 1
	b := &rr.backends[i%uint64(len(rr.backends))]
	return b
}

// ---- Weighted -----------------------------------------------------------

type weighted struct {
	backends []router.Backend
	weights  []int
	total    int
	idx      atomic.Uint64
}

func newWeighted(bs []router.Backend) *weighted {
	total := 0
	weights := make([]int, len(bs))
	for i, b := range bs {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		weights[i] = w
		total += w
	}
	return &weighted{backends: bs, weights: weights, total: total}
}

func (w *weighted) Next(_ *http.Request) *router.Backend {
	if len(w.backends) == 0 {
		return nil
	}
	n := int(w.idx.Add(1)-1) % w.total
	acc := 0
	for i, wt := range w.weights {
		acc += wt
		if n < acc {
			return &w.backends[i]
		}
	}
	return &w.backends[0]
}

// ---- Sticky session (cookie) -------------------------------------------

type sticky struct {
	inner      Balancer
	backends   []router.Backend
	cookieName string
}

func newSticky(inner Balancer, bs []router.Backend, cookieName string) *sticky {
	return &sticky{inner: inner, backends: bs, cookieName: cookieName}
}

func (s *sticky) Next(r *http.Request) *router.Backend {
	if c, err := r.Cookie(s.cookieName); err == nil {
		for i := range s.backends {
			if s.backends[i].URL == c.Value {
				return &s.backends[i]
			}
		}
	}
	return s.inner.Next(r)
}

// ---- Circuit Breaker ----------------------------------------------------

type cbState int

const (
	cbClosed   cbState = iota
	cbOpen     cbState = iota
	cbHalfOpen cbState = iota
)

type circuitBreaker struct {
	inner     Balancer
	cfg       *router.CBConfig
	failures  int
	state     cbState
	openUntil time.Time
}

func newCB(inner Balancer, cfg *router.CBConfig) *circuitBreaker {
	return &circuitBreaker{inner: inner, cfg: cfg}
}

func (cb *circuitBreaker) Next(r *http.Request) *router.Backend {
	if cb.state == cbOpen {
		if time.Now().Before(cb.openUntil) {
			return nil
		}
		cb.state = cbHalfOpen
	}
	return cb.inner.Next(r)
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.failures = 0
	cb.state = cbClosed
}

func (cb *circuitBreaker) RecordFailure() {
	cb.failures++
	if cb.failures >= cb.cfg.Threshold {
		cb.state = cbOpen
		cb.openUntil = time.Now().Add(cb.cfg.Timeout)
	}
}

// ---- Adaptive (least-load) ----------------------------------------------

// metricsScorer est une interface minimale pour injecter AgentMetricsStore sans import circulaire.
type metricsScorer interface {
	Score(hostIP string) float64
}

type adaptive struct {
	backends []router.Backend
	metrics  metricsScorer
	fallback Balancer
}

func newAdaptive(bs []router.Backend, m metricsScorer) *adaptive {
	return &adaptive{backends: bs, metrics: m, fallback: newRoundRobin(bs)}
}

func (a *adaptive) Next(_ *http.Request) *router.Backend {
	if len(a.backends) == 0 {
		return nil
	}
	bestIdx := -1
	bestScore := float64(1 << 62)
	scored := 0
	for i := range a.backends {
		ip := backendIP(a.backends[i].URL)
		score := float64(-1)
		if a.metrics != nil {
			score = a.metrics.Score(ip)
		}
		if score < 0 {
			continue
		}
		scored++
		if score < bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	// Aucune métrique → round-robin ; sinon choisir parmi les backends scorés.
	if scored == 0 || bestIdx < 0 {
		return a.fallback.Next(nil)
	}
	return &a.backends[bestIdx]
}

// backendIP extrait l'IP hôte d'une URL de backend.
func backendIP(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	// hostname DNS : retourne tel quel, ne sera probablement pas dans les métriques
	return host
}

// NewBalancer construit la chaîne balancer pour une route.
func NewBalancer(route *router.Route, metrics metricsScorer) Balancer {
	bs := route.Backends
	var b Balancer
	switch route.LB {
	case router.LBWeighted:
		b = newWeighted(bs)
	case router.LBAdaptive:
		if metrics != nil {
			b = newAdaptive(bs, metrics)
		} else {
			b = newRoundRobin(bs)
		}
	default:
		b = newRoundRobin(bs)
	}
	if route.StickyCookie != "" {
		b = newSticky(b, bs, route.StickyCookie)
	}
	if route.CircuitBreaker != nil {
		b = newCB(b, route.CircuitBreaker)
	}
	return b
}
