// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/router"
)

// rateLimiter implémente un token bucket par IP.
type rateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens/seconde
	lastRefill time.Time
	lastSeen   time.Time
	mu         sync.Mutex
}

func (r *rateLimiter) allow() bool {
	ok, _ := r.allowWithTokens()
	return ok
}

func (r *rateLimiter) allowWithTokens() (bool, float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.lastRefill = now
	r.lastSeen = now
	r.tokens = min(r.maxTokens, r.tokens+elapsed*r.refillRate)
	if r.tokens >= 1 {
		r.tokens--
		return true, r.tokens
	}
	return false, r.tokens
}

func (r *rateLimiter) applyConfig(cfg *router.RateLimitConfig) {
	burst := float64(cfg.Burst)
	if burst == 0 {
		burst = cfg.RequestsPerSecond * 2
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxTokens = burst
	r.refillRate = cfg.RequestsPerSecond
	if r.tokens > burst {
		r.tokens = burst
	}
}

type rateLimitStore struct {
	mu         sync.Mutex
	buckets    map[string]*rateLimiter
	lastPurge  time.Time
	idleTTL    time.Duration
	purgeEvery time.Duration
}

var rlStore = &rateLimitStore{
	buckets:    make(map[string]*rateLimiter),
	idleTTL:    10 * time.Minute,
	purgeEvery: time.Minute,
}

// RateLimit retourne un middleware appliquant la config de rate limit de la route.
func RateLimit(cfg *router.RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || cfg.RequestsPerSecond <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rateLimitKey(r, cfg)
			rl := rlStore.get(key, cfg)
			allowed, tokens := rl.allowWithTokens()
			metrics.RateLimit.TokensCurrent.WithLabelValues(r.Host, key).Set(tokens)
			if !allowed {
				metrics.Pipeline.BlockedTotal.WithLabelValues(r.Host, "ratelimit", "rate_exceeded").Inc()
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-RateLimit-Limit", formatRPS(cfg.RequestsPerSecond))
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitKey dérive la clé de rate-limit selon cfg.KeyBy.
// "ip" ou vide → adresse IP (comportement historique).
// "jwt_sub", "jwt_email" → claim JWT correspondant.
// "jwt_claim:<nom>" → claim JWT arbitraire.
// Si le claim est absent ou le token manquant, repli sur l'IP.
func rateLimitKey(r *http.Request, cfg *router.RateLimitConfig) string {
	ip := clientIP(r)
	if cfg.KeyBy == "" || cfg.KeyBy == "ip" {
		return ip
	}
	claims := GetJWTClaims(r.Context())
	if claims == nil {
		return ip
	}
	claimName := ""
	switch cfg.KeyBy {
	case "jwt_sub":
		claimName = "sub"
	case "jwt_email":
		claimName = "email"
	default:
		if after, ok := strings.CutPrefix(cfg.KeyBy, "jwt_claim:"); ok {
			claimName = after
		}
	}
	if claimName == "" {
		return ip
	}
	if v, ok := claims[claimName]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ip
}

func (s *rateLimitStore) get(ip string, cfg *router.RateLimitConfig) *rateLimiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(time.Now())
	if rl, ok := s.buckets[ip]; ok {
		rl.applyConfig(cfg)
		return rl
	}
	burst := float64(cfg.Burst)
	if burst == 0 {
		burst = cfg.RequestsPerSecond * 2
	}
	now := time.Now()
	rl := &rateLimiter{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: cfg.RequestsPerSecond,
		lastRefill: now,
		lastSeen:   now,
	}
	s.buckets[ip] = rl
	return rl
}

func (s *rateLimitStore) purgeLocked(now time.Time) {
	if s.purgeEvery <= 0 || s.idleTTL <= 0 {
		return
	}
	if !s.lastPurge.IsZero() && now.Sub(s.lastPurge) < s.purgeEvery {
		return
	}
	s.lastPurge = now
	for ip, rl := range s.buckets {
		rl.mu.Lock()
		idle := now.Sub(rl.lastSeen) > s.idleTTL
		rl.mu.Unlock()
		if idle {
			delete(s.buckets, ip)
		}
	}
}

func formatRPS(rps float64) string {
	if rps == float64(int(rps)) {
		return strconv.Itoa(int(rps))
	}
	return strconv.FormatFloat(rps, 'f', 2, 64)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
