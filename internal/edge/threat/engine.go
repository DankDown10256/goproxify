// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package threat implémente le moteur de détection automatique des menaces de la passerelle.
// Il est indépendant des bans manuels (natifs) et s'active/désactive à chaud.
package threat

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Name est l'identifiant affiché dans les logs pour ce moteur.
const Name = "Sentinel"

// contextKey est la clé de contexte pour transmettre la raison Sentinel à l'access log.
type contextKey struct{}

// SignalFromContext retourne la raison Sentinel attachée à la requête (vide si aucune).
func SignalFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKey{}).(string); ok {
		return v
	}
	return ""
}

// BanCallback est appelé quand le moteur détecte une menace et doit bannir une IP.
// Le caller (server.go) ajoute le ban au BanStore et le notifie à Admin.
type BanCallback func(ip, reason string, expires time.Time)

// signal représente un critère déclenché avec son score.
type signal struct {
	reason string
	score  int
}

// scoreForReason retourne le score par défaut selon la raison.
func scoreForReason(reason string) int {
	switch reason {
	case "ip", "custom_ip":
		return 5 // critique
	case "ua", "custom_ua":
		return 3 // moyen
	case "path", "custom_path":
		return 2
	case "rate":
		return 4
	default:
		return 1
	}
}

// globalBucket est un token bucket unique pour la limite globale de req/s.
type globalBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64 // tokens/s
	lastFill time.Time
}

func (b *globalBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if !b.lastFill.IsZero() {
		elapsed := now.Sub(b.lastFill).Seconds()
		b.tokens += elapsed * b.rate
		if b.tokens > b.max {
			b.tokens = b.max
		}
	} else {
		b.tokens = b.max
	}
	b.lastFill = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Engine est le moteur de détection. Un seul par passerelle, démarré via Start().
type Engine struct {
	mu  sync.RWMutex
	cfg Config

	lists    *Lists
	counters *counterStore
	wl       *whitelist
	custom   *customLists // entrées inline compilées

	globalBkt *globalBucket // limiteur global DDoS (nil = désactivé)

	banFn BanCallback
	sim   bool // rejeu hors production : ni métriques Prometheus ni effets de bord

	tarpitSlots chan struct{} // slots du tarpit ; recréé quand MaxConcurrent change
	log   *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// New crée un moteur de détection (non démarré).
func New(log *slog.Logger, banFn BanCallback) *Engine {
	return &Engine{
		lists:    newLists(log),
		counters: newCounterStore(),
		log:      log,
		banFn:    banFn,
		done:     make(chan struct{}),
	}
}

// Start démarre la boucle de refresh des listes.
func (e *Engine) Start(ctx context.Context) {
	e.lists.seedDefaults()
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	go e.run(ctx)
}

// Stop arrête proprement le moteur.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.done
}

// UpdateConfig remplace la config à chaud.
func (e *Engine) UpdateConfig(cfg Config) {
	cfg.defaults()

	var bkt *globalBucket
	if cfg.GlobalRPS > 0 {
		burst := float64(cfg.GlobalBurst)
		if burst <= 0 {
			burst = cfg.GlobalRPS * 2
		}
		bkt = &globalBucket{rate: cfg.GlobalRPS, max: burst}
	}

	e.mu.Lock()
	e.cfg = cfg
	e.wl = buildWhitelist(cfg.Whitelist)
	e.custom = buildCustomLists(cfg.CustomLists)
	e.globalBkt = bkt
	if cfg.Tarpit.Enabled && (e.tarpitSlots == nil || cap(e.tarpitSlots) != cfg.Tarpit.slots()) {
		e.tarpitSlots = make(chan struct{}, cfg.Tarpit.slots())
	}
	e.mu.Unlock()

	if cfg.Enabled {
		e.lists.loadFromDisk(cfg.Lists)
	}
}

// CheckGlobal retourne false si la requête dépasse la limite globale de req/s.
// Doit être appelé en tête de dispatch, avant toute résolution de route.
func (e *Engine) CheckGlobal() bool {
	e.mu.RLock()
	bkt := e.globalBkt
	e.mu.RUnlock()

	if bkt == nil {
		return true
	}
	if bkt.allow() {
		return true
	}
	threatGlobalRateLimitTotal.Inc()
	return false
}

// Enabled retourne vrai si le moteur est actif.
func (e *Engine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Enabled
}

// Check analyse une requête entrante.
// Retourne (blocked, reason) :
//   - blocked=true + reason si la requête doit être rejetée (mode block) ou loguée (mode detect).
//   - La requête est enrichie avec la raison dans le contexte pour l'access log.
//
// Le contexte retourné est enrichi même en mode detect pour que l'access log le trace.
func (e *Engine) Check(r *http.Request, ip string) (blocked bool, reason string) {
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	custom := e.custom
	e.mu.RUnlock()

	if !cfg.Enabled {
		e.inc(threatChecksTotal, "allow")
		return false, ""
	}
	if wl.allowedIP(ip) {
		e.inc(threatChecksTotal, "allow")
		return false, ""
	}

	ua := r.Header.Get("User-Agent")
	if wl.allowedUA(ua) {
		e.inc(threatChecksTotal, "allow")
		return false, ""
	}
	path := r.URL.Path
	if wl.allowedPath(path) {
		e.inc(threatChecksTotal, "allow")
		return false, ""
	}

	// Collecte des signaux.
	var signals []signal

	if cfg.Lists.IPEnabled && e.lists.MatchIP(ip) {
		signals = append(signals, signal{"ip", scoreForReason("ip")})
	}
	if custom != nil && custom.matchIP(ip) {
		signals = append(signals, signal{"custom_ip", scoreForReason("custom_ip")})
	}
	if cfg.Lists.UAEnabled && ua != "" && e.lists.MatchUA(ua) {
		signals = append(signals, signal{"ua", scoreForReason("ua")})
	}
	if custom != nil && ua != "" && custom.matchUA(ua) {
		signals = append(signals, signal{"custom_ua", scoreForReason("custom_ua")})
	}
	if cfg.Lists.PathEnabled && e.lists.MatchPath(path) {
		signals = append(signals, signal{"path", scoreForReason("path")})
	}
	if custom != nil && custom.matchPath(path) {
		signals = append(signals, signal{"custom_path", scoreForReason("custom_path")})
	}
	if cfg.RateLimit > 0 && e.counters.rateExceeded(ip, cfg.RateLimit, cfg.RateWindow.Duration) {
		signals = append(signals, signal{"rate", scoreForReason("rate")})
	}

	if len(signals) == 0 {
		e.inc(threatChecksTotal, "allow")
		return false, ""
	}

	// Score cumulatif.
	total := 0
	var topReason string
	for _, s := range signals {
		total += s.score
		e.inc(threatSignalsTotal, s.reason)
		if topReason == "" {
			topReason = s.reason
		}
	}

	triggered := cfg.ScoreThreshold <= 0 || total >= cfg.ScoreThreshold

	isDetect := strings.EqualFold(cfg.Mode, "detect")
	action := "block"
	if isDetect || !triggered {
		action = "detect"
	}
	e.inc(threatChecksTotal, action)

	e.log.Warn("sentinel: signal détecté",
		"ip", ip,
		"signals", len(signals),
		"score", total,
		"threshold", cfg.ScoreThreshold,
		"triggered", triggered,
		"mode", cfg.Mode,
		"reason", topReason,
	)

	if triggered && !isDetect {
		if topReason != "rate" {
			// Signal non-rate (path, ip, ua, custom_*) : bannir immédiatement.
			if e.banFn != nil {
				expires := time.Now().Add(cfg.BanDuration.Duration)
				e.inc(threatBansTotal, topReason)
				e.banFn(ip, "threat: "+topReason, expires)
			}
		} else {
			// Signal rate : ban conditionnel après N déclenchements.
			e.maybeRateBan(ip, topReason, cfg)
		}
		return true, "threat: " + topReason
	}
	// detect ou score insuffisant : signale sans bloquer
	return false, "threat: " + topReason
}

// maybeRateBan déclenche un ban automatique si le signal "rate" a été déclenché
// assez de fois (RateBanThreshold) dans la fenêtre RateBanWindow.
func (e *Engine) maybeRateBan(ip, topReason string, cfg Config) {
	if e.banFn == nil || cfg.RateLimit <= 0 {
		return
	}
	// Seulement si le signal principal est "rate" ou si "rate" est parmi les signaux actifs.
	// On ne ban pas sur un signal rate isolé sous le seuil de score global.
	threshold := cfg.RateBanThreshold
	if threshold <= 0 {
		threshold = 1
	}
	window := cfg.RateBanWindow.Duration
	if window <= 0 {
		window = cfg.RateWindow.Duration
	}

	if !e.counters.rateTriggerExceeded(ip, threshold, window) {
		return
	}
	e.counters.resetRateTrigger(ip)
	expires := time.Now().Add(cfg.BanDuration.Duration)
	e.log.Warn("sentinel: ban automatique rate", "ip", ip, "threshold", threshold, "window", window)
	e.inc(threatSignalsTotal, "rate_ban")
	e.inc(threatBansTotal, "rate")
	e.banFn(ip, "threat: rate excessif", expires)
}

// RecordStatus doit être appelé après chaque réponse pour alimenter les compteurs 4xx.
func (e *Engine) RecordStatus(ip string, status int) {
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	e.mu.RUnlock()

	if !cfg.Enabled || cfg.ErrorThreshold <= 0 {
		return
	}
	if status < 400 || status >= 500 {
		return
	}
	if wl.allowedIP(ip) {
		return
	}

	if e.counters.errorExceeded(ip, cfg.ErrorThreshold, cfg.ErrorWindow.Duration) {
		isDetect := strings.EqualFold(cfg.Mode, "detect")
		e.log.Warn("sentinel: ban automatique 4xx", "ip", ip, "status", status, "detect", isDetect)
		e.inc(threatSignalsTotal, "error4xx")
		if !isDetect && e.banFn != nil {
			expires := time.Now().Add(cfg.BanDuration.Duration)
			e.inc(threatBansTotal, "error4xx")
			e.banFn(ip, "threat: erreurs 4xx répétées", expires)
		}
		e.counters.resetErrors(ip)
	}
}

// WithSignal enrichit le contexte de la requête avec la raison du signal Sentinel.
// Utilisé par server.go pour transmettre la raison à l'access log.
func WithSignal(r *http.Request, reason string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, reason))
}

// MergeRouteWhitelists fusionne les IPs/CIDRs issus des labels sentinel_whitelist
// de toutes les routes dans la whitelist globale du moteur, sans écraser les entrées
// configurées manuellement dans Config.Whitelist.
func (e *Engine) MergeRouteWhitelists(entries []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Dédupliquer : combiner whitelist manuelle + entrées routes.
	seen := make(map[string]struct{}, len(e.cfg.Whitelist.IPs)+len(entries))
	merged := make([]string, 0, len(e.cfg.Whitelist.IPs)+len(entries))
	for _, ip := range e.cfg.Whitelist.IPs {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			merged = append(merged, ip)
		}
	}
	for _, ip := range entries {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			merged = append(merged, ip)
		}
	}
	cfg := e.cfg
	cfg.Whitelist.IPs = merged
	e.cfg = cfg
	e.wl = buildWhitelist(cfg.Whitelist)
}

// ApplyHAPayload applique les listes reçues d'un peer HA.
func (e *Engine) ApplyHAPayload(p HAPayload) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	e.lists.ApplyHAPayload(p, cfg.Lists)
}

// BuildHAPayload construit le payload pour un peer HA.
func (e *Engine) BuildHAPayload() HAPayload {
	return e.lists.BuildHAPayload()
}

func (e *Engine) run(ctx context.Context) {
	defer close(e.done)

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if cfg.Enabled {
		e.lists.refresh(ctx, cfg.Lists)
	}

	for {
		e.mu.RLock()
		cfg = e.cfg
		e.mu.RUnlock()

		interval := cfg.Lists.RefreshInterval.Duration
		if interval <= 0 {
			interval = 6 * time.Hour
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			e.mu.RLock()
			cfg = e.cfg
			e.mu.RUnlock()
			if cfg.Enabled {
				e.lists.refresh(ctx, cfg.Lists)
			}
		}
	}
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

type whitelist struct {
	nets  []*net.IPNet
	ips   []net.IP
	uas   []string
	paths []string
}

func buildWhitelist(wl Whitelist) *whitelist {
	w := &whitelist{}
	for _, s := range wl.IPs {
		if strings.Contains(s, "/") {
			if _, n, err := net.ParseCIDR(s); err == nil {
				w.nets = append(w.nets, n)
			}
		} else if ip := net.ParseIP(s); ip != nil {
			w.ips = append(w.ips, ip)
		}
	}
	for _, s := range wl.UAs {
		w.uas = append(w.uas, strings.ToLower(s))
	}
	for _, s := range wl.Paths {
		w.paths = append(w.paths, strings.ToLower(s))
	}
	return w
}

func (w *whitelist) allowedIP(ipStr string) bool {
	if w == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, wip := range w.ips {
		if wip.Equal(ip) {
			return true
		}
	}
	return false
}

func (w *whitelist) allowedUA(ua string) bool {
	if w == nil || ua == "" {
		return false
	}
	uaLow := strings.ToLower(ua)
	for _, s := range w.uas {
		if strings.Contains(uaLow, s) {
			return true
		}
	}
	return false
}

func (w *whitelist) allowedPath(path string) bool {
	if w == nil {
		return false
	}
	pathLow := strings.ToLower(path)
	for _, p := range w.paths {
		if strings.HasPrefix(pathLow, p) {
			return true
		}
	}
	return false
}

// ── Custom inline lists ───────────────────────────────────────────────────────

type customLists struct {
	nets  []*net.IPNet
	ips   []net.IP
	uas   []string
	paths []string
}

func buildCustomLists(c CustomListsConfig) *customLists {
	cl := &customLists{}
	for _, s := range c.IPs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			if _, n, err := net.ParseCIDR(s); err == nil {
				cl.nets = append(cl.nets, n)
			}
		} else if ip := net.ParseIP(s); ip != nil {
			cl.ips = append(cl.ips, ip)
		}
	}
	for _, s := range c.UAs {
		if t := strings.TrimSpace(s); t != "" {
			cl.uas = append(cl.uas, strings.ToLower(t))
		}
	}
	for _, s := range c.Paths {
		if t := strings.TrimSpace(s); t != "" {
			cl.paths = append(cl.paths, strings.ToLower(t))
		}
	}
	return cl
}

func (cl *customLists) matchIP(ipStr string) bool {
	if cl == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range cl.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, cip := range cl.ips {
		if cip.Equal(ip) {
			return true
		}
	}
	return false
}

func (cl *customLists) matchUA(ua string) bool {
	if cl == nil {
		return false
	}
	uaLow := strings.ToLower(ua)
	for _, s := range cl.uas {
		if strings.Contains(uaLow, s) {
			return true
		}
	}
	return false
}

func (cl *customLists) matchPath(path string) bool {
	if cl == nil {
		return false
	}
	pathLow := strings.ToLower(path)
	for _, p := range cl.paths {
		if strings.HasPrefix(pathLow, p) {
			return true
		}
	}
	return false
}
