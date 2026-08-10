// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// BackendHealth suit l'état de santé d'un backend par URL.
type BackendHealth struct {
	mu      sync.RWMutex
	healthy map[string]bool
	downUntil map[string]time.Time // quarantine courte après échec de dial/proxy
	log     *slog.Logger
}

func NewBackendHealth(log *slog.Logger) *BackendHealth {
	return &BackendHealth{
		healthy:   make(map[string]bool),
		downUntil: make(map[string]time.Time),
		log:       log,
	}
}

// IsHealthy retourne true si le backend est considéré en bonne santé.
// Un backend inconnu est considéré sain par défaut.
func (h *BackendHealth) IsHealthy(url string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if until, ok := h.downUntil[url]; ok {
		if time.Now().Before(until) {
			return false
		}
	}
	v, ok := h.healthy[url]
	return !ok || v
}

// MarkDown place le backend en quarantaine temporaire (failover immédiat).
func (h *BackendHealth) MarkDown(url string, ttl time.Duration) {
	if h == nil || url == "" {
		return
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	h.mu.Lock()
	h.downUntil[url] = time.Now().Add(ttl)
	h.mu.Unlock()
	if h.log != nil {
		h.log.Info("backend quarantine", "url", url, "ttl", ttl.String())
	}
}

// MarkUp lève la quarantaine après un succès.
func (h *BackendHealth) MarkUp(url string) {
	if h == nil || url == "" {
		return
	}
	h.mu.Lock()
	delete(h.downUntil, url)
	h.healthy[url] = true
	h.mu.Unlock()
}

// Status retourne "up", "down" ou "unknown" pour une URL backend.
// unknown = jamais observé (considéré sain au runtime via IsHealthy).
func (h *BackendHealth) Status(url string) string {
	if h == nil || url == "" {
		return "unknown"
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if until, ok := h.downUntil[url]; ok && time.Now().Before(until) {
		return "down"
	}
	v, ok := h.healthy[url]
	if !ok {
		return "unknown"
	}
	if v {
		return "up"
	}
	return "down"
}

// Snapshot retourne le statut connu de chaque backend (url → up|down|unknown).
func (h *BackendHealth) Snapshot() map[string]string {
	out := make(map[string]string)
	if h == nil {
		return out
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	now := time.Now()
	seen := make(map[string]struct{}, len(h.healthy)+len(h.downUntil))
	for url := range h.healthy {
		seen[url] = struct{}{}
	}
	for url := range h.downUntil {
		seen[url] = struct{}{}
	}
	for url := range seen {
		if until, ok := h.downUntil[url]; ok && now.Before(until) {
			out[url] = "down"
			continue
		}
		if v, ok := h.healthy[url]; ok {
			if v {
				out[url] = "up"
			} else {
				out[url] = "down"
			}
		} else {
			out[url] = "unknown"
		}
	}
	return out
}

// StartChecks lance les health checks pour une liste d'URLs.
func (h *BackendHealth) StartChecks(urls []string, interval time.Duration) {
	for _, u := range urls {
		go h.loop(u, interval)
	}
}

func (h *BackendHealth) loop(url string, interval time.Duration) {
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		resp, err := client.Get(url + "/health")
		ok := err == nil && resp.StatusCode < 500
		if resp != nil {
			resp.Body.Close()
		}
		h.mu.Lock()
		prev := h.healthy[url]
		h.healthy[url] = ok
		if ok {
			delete(h.downUntil, url)
		}
		h.mu.Unlock()
		if prev != ok && h.log != nil {
			h.log.Info("backend health change", "url", url, "healthy", ok)
		}
		time.Sleep(interval)
	}
}
