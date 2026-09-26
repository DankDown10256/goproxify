// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// DiskCache est un cache proxy HTTP sur disque (RFC 7234 simplifié).
type DiskCache struct {
	dir string
	mu  sync.Mutex
}

// New crée un DiskCache utilisant dir comme répertoire de stockage.
func New(dir string) *DiskCache {
	_ = os.MkdirAll(dir, 0o755)
	return &DiskCache{dir: dir}
}

type cacheEntry struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
	Expires time.Time           `json:"expires"`
}

func cacheKey(r *http.Request) string {
	raw := r.Method + r.Host + r.URL.Path + r.URL.RawQuery
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

func (dc *DiskCache) filePath(key string) string {
	return fmt.Sprintf("%s/%s.json", dc.dir, key)
}

func (dc *DiskCache) get(key string) *cacheEntry {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	data, err := os.ReadFile(dc.filePath(key))
	if err != nil {
		return nil
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil
	}
	if time.Now().After(entry.Expires) {
		return nil
	}
	return &entry
}

func (dc *DiskCache) set(key string, entry *cacheEntry) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(dc.filePath(key), data, 0o644)
}

// parseMaxAge extrait max-age depuis la valeur d'un header Cache-Control.
// Retourne -1 si absent ou invalide.
func parseMaxAge(cc string) int {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			val := strings.TrimPrefix(part, "max-age=")
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				return n
			}
		}
	}
	return -1
}

// responseRecorder capture la réponse du handler suivant.
type responseRecorder struct {
	code    int
	headers http.Header
	buf     bytes.Buffer
}

func (rr *responseRecorder) Header() http.Header         { return rr.headers }
func (rr *responseRecorder) WriteHeader(code int)        { rr.code = code }
func (rr *responseRecorder) Write(b []byte) (int, error) { return rr.buf.Write(b) }

// Middleware applique le cache disque (legacy : TTL depuis Cache-Control backend).
func (dc *DiskCache) Middleware(next http.Handler) http.Handler {
	return dc.MiddlewareWithConfig(nil)(next)
}

// MiddlewareWithConfig applique le cache disque avec configuration avancée.
func (dc *DiskCache) MiddlewareWithConfig(cfg *router.CacheConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		allowedMethods := map[string]bool{"GET": true, "HEAD": true}
		if cfg != nil && len(cfg.Methods) > 0 {
			allowedMethods = make(map[string]bool, len(cfg.Methods))
			for _, m := range cfg.Methods {
				allowedMethods[strings.ToUpper(m)] = true
			}
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowedMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			// Bypass : si un header ou cookie de bypass est présent et non vide
			if cfg != nil && isBypass(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			key := cacheKey(r)

			if entry := dc.get(key); entry != nil {
				for name, vals := range entry.Headers {
					for _, v := range vals {
						w.Header().Add(name, v)
					}
				}
				w.Header().Set("X-Cache", "HIT")
				w.WriteHeader(entry.Status)
				w.Write(entry.Body) //nolint:errcheck
				return
			}

			rec := &responseRecorder{
				code:    http.StatusOK,
				headers: make(http.Header),
			}
			next.ServeHTTP(rec, r)

			w.Header().Set("X-Cache", "MISS")
			for name, vals := range rec.headers {
				for _, v := range vals {
					w.Header().Add(name, v)
				}
			}
			w.WriteHeader(rec.code)
			w.Write(rec.buf.Bytes()) //nolint:errcheck

			// Déterminer le TTL à appliquer
			ttl := resolveTTL(rec.code, rec.headers, cfg)
			if ttl <= 0 {
				return
			}
			dc.set(key, &cacheEntry{
				Status:  rec.code,
				Headers: map[string][]string(rec.headers),
				Body:    rec.buf.Bytes(),
				Expires: time.Now().Add(ttl),
			})
		})
	}
}

// isBypass retourne vrai si la requête doit contourner le cache.
func isBypass(r *http.Request, cfg *router.CacheConfig) bool {
	for _, h := range cfg.BypassHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	for _, name := range cfg.BypassCookies {
		if _, err := r.Cookie(name); err == nil {
			return true
		}
	}
	return false
}

// parseTTL convertit une string de durée humaine ("10m", "1h", "30s") en time.Duration.
func parseTTL(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err == nil {
		return d
	}
	// Accepter "10m30s" déjà géré par ParseDuration.
	// Essayer un entier seul (secondes).
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// resolveTTL détermine combien de temps mettre en cache la réponse.
// Ordre de priorité : CacheConfig.ValidRules > Cache-Control backend.
func resolveTTL(status int, headers http.Header, cfg *router.CacheConfig) time.Duration {
	// CacheConfig rules (proxy_cache_valid)
	if cfg != nil && len(cfg.ValidRules) > 0 {
		for _, rule := range cfg.ValidRules {
			if matchesRule(status, rule.StatusCodes) {
				return parseTTL(rule.TTL)
			}
		}
		// Si des règles sont définies mais aucune ne correspond, ne pas cacher.
		return 0
	}

	// Fallback legacy : max-age du backend
	cc := headers.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		return 0
	}
	if maxAge := parseMaxAge(cc); maxAge > 0 {
		return time.Duration(maxAge) * time.Second
	}
	return 0
}

func matchesRule(status int, codes []int) bool {
	if len(codes) == 0 {
		return true // "any"
	}
	for _, c := range codes {
		if c == status {
			return true
		}
	}
	return false
}
