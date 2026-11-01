// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package threat implémente le moteur de détection automatique des menaces de la passerelle.
// Il est indépendant des bans manuels (natifs) et s'active/désactive à chaud.
package threat

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logthrottle"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/seasonal"
	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// Name est l'identifiant affiché dans les logs pour ce moteur.
const Name = "Ephor"

// contextKey est la clé de contexte pour transmettre la raison Ephor à l'access log.
type contextKey struct{}

// SignalFromContext retourne la raison Ephor attachée à la requête (vide si aucune).
func SignalFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKey{}).(string); ok {
		return v
	}
	return ""
}

// BanCallback est appelé quand le moteur détecte une menace et doit bannir une IP.
// Le caller (server.go) ajoute le ban au BanStore et le notifie à Admin. signals dit pourquoi : chaque signal avec ses
// points et la valeur observée, de sorte que leur somme explique la décision (ADR 0011).
type BanCallback func(ip, reason string, expires time.Time, signals []router.BanSignal)

// signal représente un critère déclenché avec son score.
type signal struct {
	reason string
	score  int
	value  string // ce qui a déclenché le signal (chemin, User-Agent, empreinte…), borné
}

// maxSignalValue borne la valeur affichée d'un signal : elle vient de la requête, donc de l'attaquant.
const maxSignalValue = 120

// clipValue borne une valeur observée et en retire les caractères de contrôle.
func clipValue(v string) string {
	r := make([]rune, 0, len(v))
	for _, c := range v {
		if len(r) == maxSignalValue {
			r = append(r, '…')
			break
		}
		if unicode.IsControl(c) {
			c = '?'
		}
		r = append(r, c)
	}
	return string(r)
}

func banSignals(signals []signal) []router.BanSignal {
	out := make([]router.BanSignal, len(signals))
	for i, s := range signals {
		out[i] = router.BanSignal{Name: s.reason, Points: float64(s.score), Value: s.value}
	}
	return out
}

// scoreForReason retourne le score par défaut selon la raison.
func scoreForReason(reason string) int {
	switch reason {
	case "ip", "custom_ip", "tls_fp":
		return 5 // critique
	case "ua", "custom_ua":
		return 3 // moyen
	case "path", "custom_path":
		return 2
	case "decoy":
		return 8 // presque sûrement un scanner : un deuxième accès suffit au ban par défaut (10)
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
	decoys   *decoySet    // chemins-leurres compilés ; nil quand les leurres sont off
	probes   *whitelist   // sondes déclarées (unknown_host.probes), jamais notées
	unknown  *unknownTracker
	seasonal *seasonal.Tracker // référence saisonnière du trafic (ADR 0020, étape 3)

	thresholds        []*compiledThreshold // Seuils actifs (fournis et de l'administrateur), compilés
	thresholdCounters *thresholdStore
	// Seuils à clé de compte, d'empreinte ou d'ASN (ADR 0020, étape 4.a) : compteurs et protections en mémoire seulement.
	keyRules    []*compiledThreshold
	logins      []LoginRoute
	keyCounters *thresholdStore
	enum        *enumTracker // valeurs distinctes par IP et gabarit (ADR 0020, étape 4.b)
	tlsrep      *tlsRepTracker // réputation des empreintes TLS (ADR 0020, étape 4.c)
	enumShape   EnumShapeFunc
	enumKnown   EnumKnownFunc
	protected   *protectedStore
	accountKey  []byte
	// decoyGuard : vrai quand le trafic légitime de la route qui sert la requête utilise son chemin (SetDecoyGuard).
	decoyGuard func(r *http.Request) bool

	globalBkt *globalBucket // limiteur global DDoS (nil = désactivé)

	banFn    BanCallback
	sim      bool            // rejeu hors production : ni métriques Prometheus ni effets de bord
	behavior *behavior.Store // magasin comportemental de la passerelle, commun avec le WAF (nil en simulation)

	priorBans func(ip string, since time.Time) int // bans Ephor précédents d'une IP (bans graduels)

	tarpitSlots chan struct{} // slots du tarpit ; recréé quand MaxConcurrent change
	log         *slog.Logger
	sigLog      *logthrottle.Limiter // une ligne « signal détecté » par IP et par motif et par minute

	cancel       context.CancelFunc
	seasonalDone chan struct{}

	seasonalNotify func(active []seasonal.Event) // prévient l'Admin (SetSeasonalNotify)
	seasonalDirty  atomic.Bool
	seasonalSent   time.Time

	done chan struct{}
}

// New crée un moteur de détection (non démarré).
func New(log *slog.Logger, banFn BanCallback) *Engine {
	e := &Engine{
		lists:    newLists(log),
		counters: newCounterStore(),
		unknown:  newUnknownTracker(),
		log:      log,
		sigLog:   logthrottle.New(time.Minute),
		banFn:    banFn,
		done:     make(chan struct{}),
	}
	e.thresholdCounters = newThresholdStore(func() time.Time { return e.counters.now() })
	e.keyCounters = newThresholdStore(func() time.Time { return e.counters.now() })
	e.enum = newEnumTracker(func() time.Time { return e.counters.now() })
	e.tlsrep = newTLSRepTracker(func() time.Time { return e.counters.now() })
	e.protected = newProtectedStore(func() time.Time { return e.counters.now() })
	e.accountKey = newAccountKey()
	e.seasonal = seasonal.New(func() time.Time { return e.counters.now() }, e.onSeasonalEvent)
	return e
}

// Start démarre la boucle de refresh des listes.
func (e *Engine) Start(ctx context.Context) {
	e.lists.seedDefaults()
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	go e.run(ctx)
	e.seasonalDone = make(chan struct{})
	go e.runSeasonal(ctx)
}

// Stop arrête proprement le moteur.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.done
	if e.seasonalDone != nil {
		<-e.seasonalDone
	}
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
	e.decoys = buildDecoys(cfg.Decoys)
	e.probes = buildProbes(cfg.UnknownHost)
	e.thresholds = compileThresholds(cfg.Thresholds)
	e.keyRules = keyedThresholds(e.thresholds)
	e.logins = cfg.Thresholds.Logins
	e.seasonal.SetParams(cfg.Seasonal.params())
	e.globalBkt = bkt
	if cfg.Tarpit.Enabled && (e.tarpitSlots == nil || cap(e.tarpitSlots) != cfg.Tarpit.slots()) {
		e.tarpitSlots = make(chan struct{}, cfg.Tarpit.slots())
	}
	st := e.behavior
	e.mu.Unlock()
	e.applyBehaviorConfig(st, cfg)

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
	decoys := e.decoys
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
		signals = append(signals, signal{"ip", scoreForReason("ip"), ip})
	}
	if custom != nil && custom.matchIP(ip) {
		signals = append(signals, signal{"custom_ip", scoreForReason("custom_ip"), ip})
	}
	if custom != nil && custom.matchTLS(tlsfp.FromContext(r.Context())) {
		signals = append(signals, signal{"tls_fp", scoreForReason("tls_fp"), tlsValue(tlsfp.FromContext(r.Context()))})
	}
	if cfg.Lists.UAEnabled && ua != "" && e.lists.MatchUA(ua) {
		signals = append(signals, signal{"ua", scoreForReason("ua"), clipValue(ua)})
	}
	if custom != nil && ua != "" && custom.matchUA(ua) {
		signals = append(signals, signal{"custom_ua", scoreForReason("custom_ua"), clipValue(ua)})
	}
	if cfg.Lists.PathEnabled && e.lists.MatchPath(path) {
		signals = append(signals, signal{"path", scoreForReason("path"), clipValue(path)})
	}
	if custom != nil && custom.matchPath(path) {
		signals = append(signals, signal{"custom_path", scoreForReason("custom_path"), clipValue(path)})
	}
	if decoys != nil && e.decoySignal(cfg, decoys, r, ip) {
		signals = append(signals, signal{"decoy", scoreForReason("decoy"), clipValue(path)})
	}
	if cfg.RateLimit > 0 && e.counters.rateExceeded(ip, cfg.RateLimit, cfg.RateWindow.Duration) {
		signals = append(signals, signal{"rate", scoreForReason("rate"), fmt.Sprintf("> %g req/s", cfg.RateLimit)})
	}

	isDetect := strings.EqualFold(cfg.Mode, "detect")
	if len(signals) == 0 {
		// Aucun signal de liste ni de débit sur cette requête, mais la note commune peut avoir franchi le seuil sur les seuls
		// signaux de comportement (un scanner qui ne touche que des chemins valides).
		if cfg.IPScore.Enabled && e.banFn != nil && e.hasBehavior() {
			if why := e.decideNote(ip, e.counters.currentScore(ip), false, isDetect, cfg); why != nil {
				e.clearNote(ip)
				e.log.Warn("ephor: ban sur note commune", "ip", ip, "signaux", len(why))
				e.inc(threatBansTotal, "behavior")
				e.inc(threatChecksTotal, "block")
				e.banFn(ip, "threat: score cumulé", e.banExpiry(ip, cfg), why)
				return true, "threat: score cumulé"
			}
		}
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

	action := "block"
	if isDetect || !triggered {
		action = "detect"
	}
	e.inc(threatChecksTotal, action)

	// Un scanner qui envoie des centaines de requêtes en parallèle déclenchait une ligne par requête : une
	// seule par IP et par motif et par minute, avec le nombre de signaux regroupés.
	if ok, n := e.sigLog.Allow("signal|" + ip + "|" + topReason); ok {
		args := []any{
			"ip", ip,
			"signals", len(signals),
			"score", total,
			"threshold", cfg.ScoreThreshold,
			"triggered", triggered,
			"mode", cfg.Mode,
			"reason", topReason,
		}
		if n > 0 {
			args = append(args, "repeats", n)
		}
		e.log.Warn("ephor: signal détecté", args...)
	}

	if triggered && !isDetect {
		if cfg.IPScore.Enabled {
			e.scoreBan(ip, topReason, banSignals(signals), cfg)
		} else if topReason != "rate" {
			// Signal non-rate (path, ip, ua, custom_*) : bannir immédiatement.
			if e.banFn != nil {
				expires := e.banExpiry(ip, cfg)
				e.inc(threatBansTotal, topReason)
				e.banFn(ip, "threat: "+topReason, expires, banSignals(signals))
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

func (e *Engine) hasBehavior() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.behavior != nil
}

// tlsValue : l'empreinte à afficher, JA4 de préférence (plus lisible que le MD5 du JA3).
func tlsValue(fp *tlsfp.Fingerprint) string {
	if fp == nil {
		return ""
	}
	if fp.JA4 != "" {
		return "JA4 " + fp.JA4
	}
	return "JA3 " + fp.JA3Hash
}

// SetPriorBansFunc fournit le nombre de bans Ephor déjà posés sur une IP depuis `since` (hors
// ceux antérieurs à son dernier déban). Sans elle, les bans ne sont pas graduels.
func (e *Engine) SetPriorBansFunc(fn func(ip string, since time.Time) int) {
	e.mu.Lock()
	e.priorBans = fn
	e.mu.Unlock()
}

// banExpiry calcule la fin d'un ban : la durée de base, allongée si l'IP est récidiviste.
func (e *Engine) banExpiry(ip string, cfg Config) time.Time {
	now := e.counters.now()
	d := cfg.BanDuration.Duration
	if !cfg.Escalation.Enabled {
		return now.Add(d)
	}
	e.mu.RLock()
	fn := e.priorBans
	e.mu.RUnlock()
	if fn == nil {
		return now.Add(d)
	}
	prior := fn(ip, now.Add(-cfg.Escalation.Window.Duration))
	if prior > 0 {
		longer := escalatedDuration(d, prior, cfg.Escalation)
		e.log.Warn("ephor: ban graduel", "ip", ip, "bans_precedents", prior, "duree", longer, "duree_de_base", d)
		d = longer
	}
	return now.Add(d)
}

// escalatedDuration retourne base × Factor^prior, plafonnée à MaxDuration sans jamais descendre
// sous base (un plafond inférieur à la durée de base ne raccourcit pas les bans).
func escalatedDuration(base time.Duration, prior int, c EscalationConfig) time.Duration {
	if base <= 0 || prior <= 0 {
		return base
	}
	limit := c.MaxDuration.Duration
	if limit < base {
		limit = base
	}
	f := float64(base) * math.Pow(c.Factor, float64(prior))
	if f >= float64(limit) {
		return limit
	}
	return time.Duration(f)
}

// scoreBan ajoute les points de la requête au score de l'IP et la bannit quand le score cumulé
// atteint le seuil. Une IP des listes de menaces est bannie tout de suite, sans attendre.
func (e *Engine) scoreBan(ip, topReason string, signals []router.BanSignal, cfg Config) {
	if e.banFn == nil {
		return
	}
	acc := e.counters.addScore(ip, cfg.IPScore.HalfLife.Duration, signals...)
	immediate := topReason == "ip" || topReason == "custom_ip"
	why := e.decideNote(ip, acc, immediate, false, cfg)
	if why == nil {
		e.log.Info("ephor: score cumulé", "ip", ip, "score", acc, "ban_threshold", cfg.IPScore.BanThreshold)
		return
	}
	e.clearNote(ip)
	expires := e.banExpiry(ip, cfg)
	reason := "threat: score cumulé"
	label := "score"
	if immediate {
		reason, label = "threat: "+topReason, topReason
	} else {
		e.log.Warn("ephor: ban sur score cumulé", "ip", ip, "score", acc, "ban_threshold", cfg.IPScore.BanThreshold)
	}
	e.inc(threatBansTotal, label)
	e.banFn(ip, reason, expires, why)
}

// clearNote remet à zéro la note d'une IP qui vient d'être bannie : son score cumulé et sa fenêtre de comportement, sinon chaque
// requête qui précède l'application du ban en poserait un nouveau. La confiance acquise reste.
func (e *Engine) clearNote(ip string) {
	e.counters.resetScore(ip)
	e.mu.RLock()
	st := e.behavior
	e.mu.RUnlock()
	if st != nil {
		st.DeleteProfile(ip)
	}
}

// IPScore retourne le score cumulé actuel d'une IP (décroissance appliquée) ; 0 si inconnue.
func (e *Engine) IPScore(ip string) float64 { return e.counters.currentScore(ip) }

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
	expires := e.banExpiry(ip, cfg)
	e.log.Warn("ephor: ban automatique rate", "ip", ip, "threshold", threshold, "window", window)
	e.inc(threatSignalsTotal, "rate_ban")
	e.inc(threatBansTotal, "rate")
	e.banFn(ip, "threat: rate excessif", expires, []router.BanSignal{{
		Name:   "rate",
		Points: float64(threshold * scoreForReason("rate")),
		Value:  fmt.Sprintf("%d dépassements de %g req/s en %s", threshold, cfg.RateLimit, window),
	}})
}

// RecordStatus alimente les compteurs 4xx sans connaître le chemin (pas de pondération par route).
func (e *Engine) RecordStatus(ip string, status int) { e.RecordResponse(ip, "", status) }

// RecordResponse doit être appelé après chaque réponse pour alimenter les compteurs 4xx : le compteur
// error_threshold / error_window, ou le score cumulé quand ip_score.errors est actif.
func (e *Engine) RecordResponse(ip, path string, status int) {
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	e.mu.RUnlock()

	if !cfg.Enabled {
		return
	}
	if status < 400 || status >= 500 {
		return
	}
	if cfg.IPScore.Enabled && cfg.IPScore.Errors.Enabled {
		e.recordErrorScore(ip, path, status, cfg, wl)
		return
	}
	if cfg.ErrorThreshold <= 0 {
		return
	}
	if wl.allowedIP(ip) {
		return
	}

	if e.counters.errorExceeded(ip, cfg.ErrorThreshold, cfg.ErrorWindow.Duration) {
		isDetect := strings.EqualFold(cfg.Mode, "detect")
		e.log.Warn("ephor: ban automatique 4xx", "ip", ip, "status", status, "detect", isDetect)
		e.inc(threatSignalsTotal, "error4xx")
		if !isDetect && e.banFn != nil {
			expires := e.banExpiry(ip, cfg)
			e.inc(threatBansTotal, "error4xx")
			e.banFn(ip, "threat: erreurs 4xx répétées", expires, []router.BanSignal{{
				Name:   "error4xx",
				Points: float64(cfg.ErrorThreshold),
				Value:  fmt.Sprintf("%d erreurs 4xx en %s", cfg.ErrorThreshold, cfg.ErrorWindow.Duration),
			}})
		}
		e.counters.resetErrors(ip)
	}
}

// recordErrorScore verse une erreur 4xx pondérée au score de l'IP et la bannit au seuil.
func (e *Engine) recordErrorScore(ip, path string, status int, cfg Config, wl *whitelist) {
	if wl.allowedIP(ip) || wl.allowedPath(path) {
		return
	}
	points := cfg.IPScore.Errors.points(status, path)
	if points <= 0 {
		return
	}
	acc := e.counters.addScore(ip, cfg.IPScore.HalfLife.Duration,
		router.BanSignal{Name: "error4xx", Points: points, Value: clipValue(fmt.Sprintf("%d %s", status, path))})
	why := e.decideNote(ip, acc, false, false, cfg)
	if why == nil {
		return
	}
	e.clearNote(ip)
	isDetect := strings.EqualFold(cfg.Mode, "detect")
	e.log.Warn("ephor: ban sur erreurs 4xx pondérées", "ip", ip, "status", status, "score", acc, "detect", isDetect)
	e.inc(threatSignalsTotal, "error4xx")
	if !isDetect && e.banFn != nil {
		e.inc(threatBansTotal, "error4xx")
		e.banFn(ip, "threat: erreurs 4xx répétées", e.banExpiry(ip, cfg), why)
	}
}

// WhitelistedIP indique si l'IP est exemptée d'Ephor (liste blanche globale ou des routes).
func (e *Engine) WhitelistedIP(ip string) bool {
	e.mu.RLock()
	wl := e.wl
	e.mu.RUnlock()
	return wl.allowedIP(ip)
}

// ResetIP remet à zéro les compteurs d'une IP débannie depuis l'Admin.
func (e *Engine) ResetIP(ip string) {
	e.counters.reset(ip)
	e.mu.RLock()
	st := e.behavior
	e.mu.RUnlock()
	if st != nil {
		st.DeleteProfile(ip)
	}
}

// WithSignal enrichit le contexte de la requête avec la raison du signal Ephor et la signale à l'access log.
func WithSignal(r *http.Request, reason string) *http.Request {
	edgelog.NoteThreat(r.Context(), reason)
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, reason))
}

// MergeRouteWhitelists fusionne les IPs/CIDRs issus des labels ephor_whitelist
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
	tls   map[string]struct{} // JA3 (MD5) et JA4, en minuscules
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
	for _, s := range c.TLSFingerprints {
		if t := strings.ToLower(strings.TrimSpace(s)); t != "" {
			if cl.tls == nil {
				cl.tls = map[string]struct{}{}
			}
			cl.tls[t] = struct{}{}
		}
	}
	return cl
}

// matchTLS : l'empreinte JA3 ou JA4 de la connexion figure dans la liste (jamais vrai en HTTP clair ou QUIC).
func (cl *customLists) matchTLS(fp *tlsfp.Fingerprint) bool {
	return cl != nil && fp.Matches(cl.tls)
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

// WhitelistIPs rend les IP et CIDR exemptés d'Ephor (liste blanche globale et entrées des routes), pour que d'autres détecteurs qui
// bannissent visent les mêmes cibles (bantarget.BanTarget).
func (e *Engine) WhitelistIPs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.cfg.Whitelist.IPs...)
}

// Harden durcit les seuils d'Ephor pour dur, puis les rétablit (action « mode strict » des automatisations) : le seuil de ban du score
// cumulé et le seuil d'erreurs 4xx sont divisés par deux, au plus bas à 2. Si la configuration a changé entre-temps, elle n'est pas
// touchée à l'échéance. Sans effet quand Ephor est coupé.
func (e *Engine) Harden(dur time.Duration) error {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if !cfg.Enabled {
		return fmt.Errorf("Ephor est désactivé : rien à durcir")
	}
	half := func(v float64) float64 {
		if v/2 < 2 {
			return math.Min(v, 2)
		}
		return v / 2
	}
	strict := cfg
	strict.IPScore.BanThreshold = half(cfg.IPScore.BanThreshold)
	if cfg.ErrorThreshold > 0 {
		strict.ErrorThreshold = int(half(float64(cfg.ErrorThreshold)))
	}
	e.UpdateConfig(strict)
	e.log.Warn("ephor: mode strict", "duree", dur, "seuil_ban", strict.IPScore.BanThreshold, "seuil_erreurs", strict.ErrorThreshold)
	go func() {
		time.Sleep(dur)
		e.mu.RLock()
		cur := e.cfg
		e.mu.RUnlock()
		if cur.IPScore.BanThreshold == strict.IPScore.BanThreshold && cur.ErrorThreshold == strict.ErrorThreshold {
			cur.IPScore.BanThreshold, cur.ErrorThreshold = cfg.IPScore.BanThreshold, cfg.ErrorThreshold
			e.UpdateConfig(cur)
		}
	}()
	return nil
}
