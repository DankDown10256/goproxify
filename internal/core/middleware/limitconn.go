// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// connCounter comptabilise les connexions actives par IP pour une route donnée.
type connCounter struct {
	mu       sync.Mutex
	counts   map[string]*atomic.Int64
	lastSeen map[string]time.Time
}

var lcStore = &connCounter{
	counts:   make(map[string]*atomic.Int64),
	lastSeen: make(map[string]time.Time),
}

func (cc *connCounter) counter(ip string) *atomic.Int64 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.lastSeen[ip] = time.Now()
	if c, ok := cc.counts[ip]; ok {
		return c
	}
	c := &atomic.Int64{}
	cc.counts[ip] = c
	return c
}

func (cc *connCounter) purge() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, t := range cc.lastSeen {
		if t.Before(cutoff) && cc.counts[ip].Load() == 0 {
			delete(cc.counts, ip)
			delete(cc.lastSeen, ip)
		}
	}
}

var lcPurgeOnce sync.Once

// LimitConn retourne un middleware limitant le nombre de connexions simultanées par IP, par route
// (routeID entre dans la clé : une IP très active sur une route ne consomme pas le quota d'une autre).
func LimitConn(routeID string, cfg *router.LimitConnConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || cfg.MaxPerIP <= 0 {
			return next
		}
		max := int64(cfg.MaxPerIP)
		lcPurgeOnce.Do(func() {
			go func() {
				for range time.NewTicker(5 * time.Minute).C {
					lcStore.purge()
				}
			}()
		})
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			c := lcStore.counter(routeID + "|" + ip)
			cur := c.Add(1)
			defer c.Add(-1)
			if cur > max {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "503 Service Unavailable — too many connections", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
