// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// probeConfig regroupe les paramètres d'une sonde par URL.
type probeConfig struct {
	path               string
	interval           time.Duration
	timeout            time.Duration
	healthyThreshold   int
	unhealthyThreshold int
}

func defaultProbeConfig() probeConfig {
	return probeConfig{
		path:               "/health",
		interval:           30 * time.Second,
		timeout:            5 * time.Second,
		healthyThreshold:   1,
		unhealthyThreshold: 1,
	}
}

func probeConfigFrom(cfg *router.HealthCheckConfig) probeConfig {
	p := defaultProbeConfig()
	if cfg == nil {
		return p
	}
	if cfg.Path != "" {
		p.path = cfg.Path
	}
	if cfg.Interval > 0 {
		p.interval = cfg.Interval
	}
	if cfg.Timeout > 0 {
		p.timeout = cfg.Timeout
	}
	if cfg.HealthyThreshold > 0 {
		p.healthyThreshold = cfg.HealthyThreshold
	}
	if cfg.UnhealthyThreshold > 0 {
		p.unhealthyThreshold = cfg.UnhealthyThreshold
	}
	return p
}

// backendState suit l'état de santé d'un backend avec compteurs de seuil.
type backendState struct {
	healthy    bool
	downUntil  time.Time
	streak     int  // succès consécutifs (>0) ou échecs consécutifs (<0)
	cfg        probeConfig
}

// BackendHealth suit l'état de santé d'un backend par URL.
type BackendHealth struct {
	mu      sync.RWMutex
	states  map[string]*backendState
	watched map[string]struct{} // URLs avec un goroutine de check actif
	log     *slog.Logger
	OnDown  func(url string) // appelé quand un backend passe healthy→unhealthy
}

func NewBackendHealth(log *slog.Logger) *BackendHealth {
	return &BackendHealth{
		states:  make(map[string]*backendState),
		watched: make(map[string]struct{}),
		log:     log,
	}
}

// IsHealthy retourne true si le backend est considéré en bonne santé.
// Un backend inconnu est considéré sain par défaut.
func (h *BackendHealth) IsHealthy(u string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	st, ok := h.states[u]
	if !ok {
		return true
	}
	if time.Now().Before(st.downUntil) {
		return false
	}
	return st.healthy
}

// MarkDown place le backend en quarantaine temporaire (failover immédiat).
func (h *BackendHealth) MarkDown(u string, ttl time.Duration) {
	if h == nil || u == "" {
		return
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	h.mu.Lock()
	st := h.getOrCreateLocked(u)
	st.downUntil = time.Now().Add(ttl)
	h.mu.Unlock()
	if h.log != nil {
		h.log.Info("backend quarantine", "url", u, "ttl", ttl.String())
	}
}

// MarkUp lève la quarantaine après un succès.
func (h *BackendHealth) MarkUp(u string) {
	if h == nil || u == "" {
		return
	}
	h.mu.Lock()
	st := h.getOrCreateLocked(u)
	st.downUntil = time.Time{}
	st.healthy = true
	h.mu.Unlock()
}

// Status retourne "up", "down" ou "unknown" pour une URL backend.
func (h *BackendHealth) Status(u string) string {
	if h == nil || u == "" {
		return "unknown"
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	st, ok := h.states[u]
	if !ok {
		return "unknown"
	}
	if time.Now().Before(st.downUntil) {
		return "down"
	}
	if st.healthy {
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
	for u, st := range h.states {
		if now.Before(st.downUntil) {
			out[u] = "down"
			continue
		}
		if st.healthy {
			out[u] = "up"
		} else {
			out[u] = "down"
		}
	}
	return out
}

func (h *BackendHealth) getOrCreateLocked(u string) *backendState {
	if st, ok := h.states[u]; ok {
		return st
	}
	st := &backendState{healthy: true, cfg: defaultProbeConfig()}
	h.states[u] = st
	return st
}

// quarantineDuration retourne la durée de quarantaine adaptée au type d'erreur.
func quarantineDuration(err error) time.Duration {
	if err == nil {
		return 15 * time.Second
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Temporary() {
			return 0
		}
		if errors.Is(ne.Err, syscall.ECONNRESET) || errors.Is(ne.Err, syscall.EPIPE) {
			return 0
		}
		if errors.Is(ne.Err, syscall.ECONNREFUSED) {
			return 15 * time.Second
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return 0
	}
	return 15 * time.Second
}

// StartChecks lance les health checks actifs avec la config par défaut.
// Idempotent : les URLs déjà surveillées ne lancent pas de nouvelle goroutine.
func (h *BackendHealth) StartChecks(urls []string, interval time.Duration) {
	cfg := defaultProbeConfig()
	if interval > 0 {
		cfg.interval = interval
	}
	h.startChecksWithConfig(urls, cfg)
}

// StartChecksFromRoutes lance les health checks en utilisant la HealthCheckConfig de chaque route.
func (h *BackendHealth) StartChecksFromRoutes(routes []*router.Route) {
	// Construire une map url → meilleure config connue.
	// Si plusieurs routes partagent un même backend, on prend la première config non-nil.
	cfgByURL := make(map[string]probeConfig)
	for _, r := range routes {
		if r == nil || r.Type == router.RouteUDP {
			continue
		}
		pc := probeConfigFrom(r.HealthCheck)
		for _, b := range r.Backends {
			if b.URL == "" {
				continue
			}
			if _, seen := cfgByURL[b.URL]; !seen {
				cfgByURL[b.URL] = pc
			}
		}
	}
	h.mu.Lock()
	var toStart []struct {
		url string
		cfg probeConfig
	}
	for u, pc := range cfgByURL {
		if _, ok := h.watched[u]; !ok {
			h.watched[u] = struct{}{}
			// Stocker la config dans l'état
			st := h.getOrCreateLocked(u)
			st.cfg = pc
			toStart = append(toStart, struct {
				url string
				cfg probeConfig
			}{u, pc})
		}
	}
	h.mu.Unlock()
	for _, item := range toStart {
		go h.loop(item.url, item.cfg)
	}
}

func (h *BackendHealth) startChecksWithConfig(urls []string, cfg probeConfig) {
	h.mu.Lock()
	var toStart []string
	for _, u := range urls {
		if u == "" {
			continue
		}
		if _, ok := h.watched[u]; !ok {
			h.watched[u] = struct{}{}
			st := h.getOrCreateLocked(u)
			st.cfg = cfg
			toStart = append(toStart, u)
		}
	}
	h.mu.Unlock()
	for _, u := range toStart {
		go h.loop(u, cfg)
	}
}

func (h *BackendHealth) loop(target string, cfg probeConfig) {
	for {
		ok := probeWithConfig(target, cfg)
		h.mu.Lock()
		st := h.getOrCreateLocked(target)
		prevHealthy := st.healthy
		if ok {
			if st.streak < 0 {
				st.streak = 0
			}
			st.streak++
			if st.streak >= cfg.healthyThreshold {
				st.healthy = true
				st.downUntil = time.Time{}
			}
		} else {
			if st.streak > 0 {
				st.streak = 0
			}
			st.streak--
			if -st.streak >= cfg.unhealthyThreshold {
				st.healthy = false
			}
		}
		wentDown := prevHealthy && !st.healthy
		changed := prevHealthy != st.healthy
		h.mu.Unlock()
		if changed && h.log != nil {
			h.log.Info("backend health change", "url", target, "healthy", ok)
		}
		if wentDown && h.OnDown != nil {
			h.OnDown(target)
		}
		time.Sleep(cfg.interval)
	}
}

// probeClient ne vérifie pas le certificat backend : la sonde teste la vivacité,
// pas l'authenticité.
var probeClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

const probeTimeout = 5 * time.Second

// probeWithConfig teste la vivacité d'un backend avec une config personnalisée.
func probeWithConfig(target string, cfg probeConfig) bool {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return tcpReachable(target, cfg.timeout)
	}
	client := probeClient
	if cfg.timeout != probeTimeout {
		client = &http.Client{
			Timeout: cfg.timeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	path := cfg.path
	if path == "" {
		path = "/health"
	}
	resp, err := client.Get(strings.TrimSuffix(target, "/") + path)
	if err != nil {
		return tcpReachable(hostPort(u), cfg.timeout)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	}
	return true
}

// probe est l'API de compatibilité utilisée dans les tests.
func probe(target string) bool {
	return probeWithConfig(target, defaultProbeConfig())
}

func tcpReachable(addr string, timeout time.Duration) bool {
	if addr == "" {
		return false
	}
	if timeout <= 0 {
		timeout = probeTimeout
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// hostPort retourne l'adresse dialable d'une URL, en complétant le port implicite.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
