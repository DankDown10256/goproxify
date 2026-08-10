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

func (rr *responseRecorder) Header() http.Header        { return rr.headers }
func (rr *responseRecorder) WriteHeader(code int)       { rr.code = code }
func (rr *responseRecorder) Write(b []byte) (int, error) { return rr.buf.Write(b) }

// Middleware applique le cache disque.
func (dc *DiskCache) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
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

		// Stocker si cacheable
		if rec.code == http.StatusOK {
			cc := rec.headers.Get("Cache-Control")
			if !strings.Contains(cc, "no-store") {
				maxAge := parseMaxAge(cc)
				if maxAge > 0 {
					expires := time.Now().Add(time.Duration(maxAge) * time.Second)
					entry := &cacheEntry{
						Status:  rec.code,
						Headers: map[string][]string(rec.headers),
						Body:    rec.buf.Bytes(),
						Expires: expires,
					}
					dc.set(key, entry)
				}
			}
		}
	})
}
