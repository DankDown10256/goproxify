// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// contextKey est la clé de contexte pour transmettre les matches WAF au access log.
type contextKey struct{}

// MatchesFromContext retourne les matches WAF attachés à la requête (nil si aucun).
func MatchesFromContext(ctx context.Context) []Match {
	if v, ok := ctx.Value(contextKey{}).([]Match); ok {
		return v
	}
	return nil
}

// Match représente une règle déclenchée.
type Match struct {
	RuleID       int
	Category     string
	Severity     Severity
	AnomalyScore int
	Message      string
	Target       string
	Value        string
}

var (
	wafMatchesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "waf",
		Name:      "matches_total",
		Help:      "Nombre de déclenchements WAF.",
	}, []string{"host", "category", "severity", "action"})

	wafRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "waf",
		Name:      "requests_inspected_total",
		Help:      "Nombre de requêtes inspectées par le WAF.",
	}, []string{"host"})

	wafBehaviorTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "waf",
		Name:      "behavior_signals_total",
		Help:      "Signaux comportementaux détectés par le WAF.",
	}, []string{"host", "signal"})
)

// BanCallback est appelé par le moteur comportemental quand une IP doit être bannie.
type BanCallback func(ip, reason string, expires time.Time)

// Engine est le moteur WAF.
type Engine struct {
	mu      sync.RWMutex
	rules   []Rule   // règles par défaut + custom compilées
	exclude map[int]bool
	log     *slog.Logger

	banFn BanCallback // optionnel, câblé via SetBanCallback

	// behaviorStores : un store comportemental par host (isolation vhost).
	// Alloué à la première utilisation via behaviorStoreFor().
	behaviorMu     sync.Mutex
	behaviorStores map[string]*behavior.Store // host → store
	behaviorWindow time.Duration              // fenêtre commune (premier appel la fixe)
}

// SetBanCallback enregistre le callback de ban comportemental (server.go → BanStore).
func (e *Engine) SetBanCallback(fn BanCallback) {
	e.mu.Lock()
	e.banFn = fn
	e.mu.Unlock()
}

// BehaviorStore retourne le store comportemental agrégé (tous hosts confondus).
// Exposé pour la sync HA : on utilise un store synthétique "_all".
func (e *Engine) BehaviorStore() *behavior.Store {
	return e.behaviorStoreForHost("_all", 60)
}

// BehaviorProfiles retourne tous les profils IP actifs, tous hosts confondus.
func (e *Engine) BehaviorProfiles() map[string]behavior.ProfileInfo {
	e.behaviorMu.Lock()
	stores := make([]*behavior.Store, 0, len(e.behaviorStores))
	for _, s := range e.behaviorStores {
		stores = append(stores, s)
	}
	e.behaviorMu.Unlock()

	merged := make(map[string]behavior.ProfileInfo)
	for _, s := range stores {
		for ip, info := range s.Profiles() {
			if info.Score > merged[ip].Score {
				merged[ip] = info
			}
		}
	}
	return merged
}

// DeleteBehaviorProfile supprime le profil comportemental d'une IP (tous hosts).
func (e *Engine) DeleteBehaviorProfile(ip string) {
	e.behaviorMu.Lock()
	stores := make([]*behavior.Store, 0, len(e.behaviorStores))
	for _, s := range e.behaviorStores {
		stores = append(stores, s)
	}
	e.behaviorMu.Unlock()
	for _, s := range stores {
		s.DeleteProfile(ip)
	}
}

// SaveSnapshot sérialise les profils comportementaux vers path (JSON).
func (e *Engine) SaveSnapshot(path string) error {
	e.behaviorMu.Lock()
	stores := make(map[string]*behavior.Store, len(e.behaviorStores))
	for h, s := range e.behaviorStores {
		stores[h] = s
	}
	e.behaviorMu.Unlock()

	type hostSnap struct {
		Host    string            `json:"host"`
		Payload behavior.HAPayload `json:"payload"`
	}
	snaps := make([]hostSnap, 0, len(stores))
	for h, s := range stores {
		snaps = append(snaps, hostSnap{Host: h, Payload: s.Snapshot()})
	}
	data, err := json.Marshal(snaps)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadSnapshot restaure les profils depuis path (JSON). Ignore les erreurs de lecture.
func (e *Engine) LoadSnapshot(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	type hostSnap struct {
		Host    string            `json:"host"`
		Payload behavior.HAPayload `json:"payload"`
	}
	var snaps []hostSnap
	if err := json.Unmarshal(data, &snaps); err != nil {
		e.log.Warn("waf: snapshot invalide, ignoré", "path", path, "err", err)
		return
	}
	for _, hs := range snaps {
		s := e.behaviorStoreForHost(hs.Host, 60)
		s.RestoreSnapshot(hs.Payload)
	}
	e.log.Info("waf: snapshot comportemental restauré", "path", path, "hosts", len(snaps))
}

// NewEngine crée un moteur WAF avec les règles par défaut.
func NewEngine(cfg *router.WAFConfig, log *slog.Logger) *Engine {
	e := &Engine{log: log}
	e.reload(cfg)
	return e
}

// UpdateConfig recharge la configuration à chaud (nouvelles règles custom, exclusions).
func (e *Engine) UpdateConfig(cfg *router.WAFConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reload(cfg)
}

// platformExcludeIDs mappe chaque plateforme applicative vers les IDs de règles
// qui génèrent des faux positifs sur elle.
var platformExcludeIDs = map[string][]int{
	// CMS & E-commerce
	"wordpress":  {941100, 941110, 941120, 942100, 942110, 942120},
	"drupal":     {941100, 941110, 942100, 942110},
	"joomla":     {941100, 941110, 942100, 942110},
	"magento":    {941100, 941110, 942100, 942110, 942120},
	"prestashop": {941100, 942100, 942110},
	"ghost":      {941100, 941110, 941120},
	"strapi":     {941100, 942100, 942110},
	// Frameworks
	"nextjs":   {942100, 942110, 934200, 934210},
	"laravel":  {942100, 942110, 942120},
	"symfony":  {942100, 942110, 942120},
	"django":   {942100, 942110},
	// Collaboration & fichiers
	"nextcloud":   {941100, 930100, 930110},
	"dokuwiki":    {941100, 941110},
	"mattermost":  {941100, 942100},
	"discourse":   {941100, 941110, 941120},
	"rocketchat":  {941100, 942100},
	// DevOps & Infra
	"gitea":     {941100, 941110, 942100, 930100},
	"forgejo":   {941100, 941110, 942100, 930100},
	"portainer": {932100, 942100},
	"proxmox":   {932100, 932110, 933100},
	"grafana":   {942100, 942110},
	"zabbix":    {942100, 942110},
	// Outils métier
	"odoo":     {942100, 942110, 941100},
	"n8n":      {934200, 942100, 941100},
	"keycloak": {942100, 920100},
	// Médias & Selfhosted
	"jellyfin":    {930100, 930110},
	"immich":      {930100, 941100},
	"vaultwarden": {942100, 941110},
	// Administration
	"cpanel": {941100, 941110, 920100},
}

func (e *Engine) reload(cfg *router.WAFConfig) {
	exclude := make(map[int]bool)
	rules := DefaultRules()
	if cfg != nil {
		for _, id := range cfg.ExcludeIDs {
			exclude[id] = true
		}
		for _, p := range cfg.ExcludePlatforms {
			for _, id := range platformExcludeIDs[p] {
				exclude[id] = true
			}
		}
		if len(cfg.CustomRules) > 0 {
			custom, err := CompileCustomRules(cfg.CustomRules)
			if err != nil {
				e.log.Error("waf: erreur compilation règles custom", "err", err)
			} else {
				rules = append(rules, custom...)
			}
		}
	}
	e.rules = rules
	e.exclude = exclude
}

// Inspect analyse une requête et retourne les correspondances.
// excludeIDs additionnels (par route) sont fusionnés avec ceux du moteur.
func (e *Engine) Inspect(r *http.Request, maxBodyMB int, excludeIDs ...int) []Match {
	e.mu.RLock()
	rules := e.rules
	baseExclude := e.exclude
	e.mu.RUnlock()

	exclude := baseExclude
	if len(excludeIDs) > 0 {
		exclude = make(map[int]bool, len(baseExclude)+len(excludeIDs))
		for id := range baseExclude {
			exclude[id] = true
		}
		for _, id := range excludeIDs {
			exclude[id] = true
		}
	}

	uri := r.URL.RequestURI()
	args := extractArgs(r)
	headers := extractHeaders(r)
	cookies := extractCookies(r)
	body, bodyVals := readBody(r, maxBodyMB)

	targetValues := map[Target][]string{
		TargetURI:     {uri},
		TargetArgs:    append(args, bodyVals...),
		TargetHeaders: headers,
		TargetCookies: cookies,
		TargetBody:    {body},
	}

	var matches []Match
	for _, rule := range rules {
		if exclude[rule.ID] {
			continue
		}
		for _, target := range rule.Targets {
			values := targetValues[target]
			for _, val := range values {
				if val == "" {
					continue
				}
				if loc := rule.Pattern.FindStringIndex(val); loc != nil {
					excerpt := val[loc[0]:loc[1]]
					if len(excerpt) > 64 {
						excerpt = excerpt[:64] + "..."
					}
					matches = append(matches, Match{
						RuleID:       rule.ID,
						Category:     rule.Category,
						Severity:     rule.Severity,
						AnomalyScore: rule.AnomalyScore,
						Message:      rule.Message,
						Target:       targetName(target),
						Value:        excerpt,
					})
					goto nextRule
				}
			}
		}
	nextRule:
	}
	return matches
}

// InspectResponse analyse un corps de réponse (règles TargetResponse uniquement).
func (e *Engine) InspectResponse(body string, excludeIDs ...int) []Match {
	e.mu.RLock()
	rules := e.rules
	baseExclude := e.exclude
	e.mu.RUnlock()

	exclude := baseExclude
	if len(excludeIDs) > 0 {
		exclude = make(map[int]bool, len(baseExclude)+len(excludeIDs))
		for id := range baseExclude {
			exclude[id] = true
		}
		for _, id := range excludeIDs {
			exclude[id] = true
		}
	}

	var matches []Match
	for _, rule := range rules {
		if exclude[rule.ID] {
			continue
		}
		for _, target := range rule.Targets {
			if target != TargetResponse {
				continue
			}
			if loc := rule.Pattern.FindStringIndex(body); loc != nil {
				excerpt := body[loc[0]:loc[1]]
				if len(excerpt) > 64 {
					excerpt = excerpt[:64] + "..."
				}
				matches = append(matches, Match{
					RuleID:       rule.ID,
					Category:     rule.Category,
					Severity:     rule.Severity,
					AnomalyScore: rule.AnomalyScore,
					Message:      rule.Message,
					Target:       "response",
					Value:        excerpt,
				})
				break
			}
		}
	}
	return matches
}

// behaviorStoreForHost retourne le store comportemental pour un host donné.
// La fenêtre est fixée au premier appel et reste constante.
func (e *Engine) behaviorStoreForHost(host string, windowSec int) *behavior.Store {
	e.behaviorMu.Lock()
	defer e.behaviorMu.Unlock()
	if e.behaviorStores == nil {
		e.behaviorStores = make(map[string]*behavior.Store)
	}
	s, ok := e.behaviorStores[host]
	if !ok {
		w := time.Duration(windowSec) * time.Second
		if w <= 0 {
			w = 60 * time.Second
		}
		if e.behaviorWindow == 0 {
			e.behaviorWindow = w
		}
		s = behavior.NewStore(e.behaviorWindow)
		e.behaviorStores[host] = s
	}
	return s
}

// Middleware retourne un handler HTTP WAF.
func (e *Engine) Middleware(cfg *router.WAFConfig, next http.Handler) http.Handler {
	maxBody := 10
	var excludeIDs []int
	if cfg != nil {
		if cfg.MaxBodyMB > 0 {
			maxBody = cfg.MaxBodyMB
		}
		excludeIDs = cfg.ExcludeIDs
	}
	block := cfg == nil || cfg.Mode != "detect"
	anomalyThreshold := 0
	behaviorEnabled := false
	behaviorThreshold := 8
	behaviorWindowSec := 60
	var trustedNets []*net.IPNet
	var wafWhitelistNets []*net.IPNet
	if cfg != nil {
		anomalyThreshold = cfg.AnomalyThreshold
		behaviorEnabled = cfg.BehaviorEnabled
		if cfg.BehaviorThreshold > 0 {
			behaviorThreshold = cfg.BehaviorThreshold
		}
		if cfg.BehaviorWindowSec > 0 {
			behaviorWindowSec = cfg.BehaviorWindowSec
		}
		trustedNets = parseTrustedProxies(cfg.TrustedProxies)
		wafWhitelistNets = parseTrustedProxies(cfg.WAFWhitelistIPs)
	}

	// Vérifier si des règles TargetResponse existent pour décider de bufferiser les réponses.
	hasResponseRules := e.hasResponseRules()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		ip := realIP(r, trustedNets)

		// Bypass WAF complet pour les IPs/CIDRs en whitelist (Fail2Ban/Sentinel restent actifs).
		if len(wafWhitelistNets) > 0 && ipMatchesNets(ip, wafWhitelistNets) {
			next.ServeHTTP(w, r)
			return
		}

		wafRequestsTotal.WithLabelValues(host).Inc()

		// ── Étape 1 : vérification comportementale PRÉ-requête ────────────
		if behaviorEnabled {
			bStore := e.behaviorStoreForHost(host, behaviorWindowSec)
			preScore, _ := bStore.Score(ip)
			effectiveThreshold := behaviorThreshold + bStore.TrustBonus(ip)
			if preScore >= effectiveThreshold && block {
				e.log.Warn("waf: blocage comportemental immédiat",
					"ip", ip, "score", preScore, "threshold", effectiveThreshold)
				wafBehaviorTotal.WithLabelValues(host, "pre_block").Inc()
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
		}

		// ── Étape 2 : inspection WAF requête ─────────────────────────────
		matches := e.Inspect(r, maxBody, excludeIDs...)

		wafScore := 0
		for _, m := range matches {
			wafScore += m.AnomalyScore
		}

		triggered := false
		if len(matches) > 0 {
			if anomalyThreshold > 0 {
				triggered = wafScore >= anomalyThreshold
			} else {
				triggered = true
			}
		}

		if len(matches) > 0 {
			ctx := context.WithValue(r.Context(), contextKey{}, matches)
			r = r.WithContext(ctx)

			for _, m := range matches {
				action := "detect"
				if triggered && block {
					action = "block"
				}
				wafMatchesTotal.WithLabelValues(host, m.Category, m.Severity.String(), action).Inc()
				e.log.Warn("waf: règle déclenchée",
					"rule_id", m.RuleID,
					"category", m.Category,
					"severity", m.Severity.String(),
					"score", m.AnomalyScore,
					"message", m.Message,
					"target", m.Target,
					"ip", ip,
					"uri", r.URL.RequestURI(),
					"block", triggered && block,
				)
			}

			if triggered && block {
				if behaviorEnabled {
					e.postRecord(host, ip, r, wafScore, http.StatusForbidden, behaviorWindowSec, behaviorThreshold, block)
				}
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("X-WAF-Match", matches[0].Category)
		}

		// ── Étape 3 : service de la requête ──────────────────────────────
		// Si des règles de réponse existent, bufferiser pour inspection.
		// Un upgrade WebSocket ne peut pas être bufférisé : la connexion est détournée.
		if hasResponseRules && !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			rc := &responseCapture{
				ResponseWriter: w,
				buf:            &bytes.Buffer{},
				status:         http.StatusOK,
				maxBodyMB:      maxBody,
			}
			next.ServeHTTP(rc, r)

			respMatches := e.InspectResponse(rc.buf.String(), excludeIDs...)
			for _, m := range respMatches {
				action := "detect"
				if block {
					action = "block"
				}
				wafMatchesTotal.WithLabelValues(host, m.Category, m.Severity.String(), action).Inc()
				e.log.Warn("waf: fuite dans la réponse",
					"rule_id", m.RuleID,
					"category", m.Category,
					"severity", m.Severity.String(),
					"message", m.Message,
					"ip", ip,
					"uri", r.URL.RequestURI(),
				)
			}
			if len(respMatches) > 0 && block {
				// La réponse n'a pas encore été envoyée : on peut encore bloquer.
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				if behaviorEnabled {
					e.postRecord(host, ip, r, wafScore+respMatches[0].AnomalyScore, rc.status, behaviorWindowSec, behaviorThreshold, block)
				}
				return
			}
			// Aucune fuite ou mode detect : transmettre la réponse bufferisée.
			status := rc.status
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			_, _ = w.Write(rc.buf.Bytes())

			if behaviorEnabled {
				e.postRecord(host, ip, r, wafScore, rc.status, behaviorWindowSec, behaviorThreshold, block)
			}
			return
		}

		if behaviorEnabled {
			rw := &statusCapture{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			e.postRecord(host, ip, r, wafScore, rw.status, behaviorWindowSec, behaviorThreshold, block)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// postRecord enregistre un événement dans le store comportemental après la requête.
// Si le nouveau score dépasse le seuil, appelle banFn (ban immédiat pour les suivantes).
func (e *Engine) postRecord(host, ip string, r *http.Request, wafScore, status, windowSec, threshold int, block bool) {
	bStore := e.behaviorStoreForHost(host, windowSec)
	bScore, bSignals := bStore.Record(ip, behavior.Event{
		At:       time.Now(),
		WafScore: wafScore,
		Status:   status,
		Method:   r.Method,
		Path:     r.URL.Path,
		UA:       r.UserAgent(),
	})
	if len(bSignals) == 0 {
		return
	}
	for _, sig := range bSignals {
		wafBehaviorTotal.WithLabelValues(host, sig.Name).Inc()
	}
	e.log.Warn("waf: signal comportemental",
		"ip", ip, "score", bScore, "threshold", threshold, "signals", bSignals)

	effectiveThreshold := threshold + bStore.TrustBonus(ip)
	if bScore >= effectiveThreshold && block {
		e.mu.RLock()
		banFn := e.banFn
		e.mu.RUnlock()
		if banFn != nil {
			expires := time.Now().Add(24 * time.Hour)
			banFn(ip, "waf: comportement suspect", expires)
		}
	}
}

// hasResponseRules indique si au moins une règle cible TargetResponse.
func (e *Engine) hasResponseRules() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		for _, t := range r.Targets {
			if t == TargetResponse {
				return true
			}
		}
	}
	return false
}

// responseCapture bufferise le corps de la réponse pour inspection WAF.
// La réponse n'est PAS transmise automatiquement : l'appelant décide.
type responseCapture struct {
	http.ResponseWriter
	buf           *bytes.Buffer
	status        int
	headerWritten bool
	maxBodyMB     int
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.status = code
	rc.headerWritten = true
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if rc.status == 0 {
		rc.status = http.StatusOK
	}
	limit := int64(rc.maxBodyMB) * 1024 * 1024
	if int64(rc.buf.Len()) < limit {
		remaining := limit - int64(rc.buf.Len())
		if int64(len(b)) <= remaining {
			rc.buf.Write(b)
		} else {
			rc.buf.Write(b[:remaining])
		}
	}
	return len(b), nil
}

func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// statusCapture wrappe ResponseWriter pour capturer le code HTTP.
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.status = code
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *statusCapture) Write(b []byte) (int, error) {
	if sc.status == 0 {
		sc.status = http.StatusOK
	}
	return sc.ResponseWriter.Write(b)
}

func (sc *statusCapture) Flush() {
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap laisse http.NewResponseController atteindre Hijack : sans lui, l'upgrade WebSocket échoue en 502.
func (sc *statusCapture) Unwrap() http.ResponseWriter { return sc.ResponseWriter }

// realIP extrait l'IP réelle depuis les headers proxy.
// trustedCIDRs : liste de CIDRs de proxies de confiance parsés.
// Si vide, on retourne directement RemoteAddr sans lire les headers (sécurisé par défaut).
func realIP(r *http.Request, trustedNets []*net.IPNet) string {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteHost == "" {
		remoteHost = r.RemoteAddr
	}

	// Sans proxy de confiance configuré : RemoteAddr est l'IP source.
	if len(trustedNets) == 0 {
		return remoteHost
	}

	// Vérifier que le RemoteAddr appartient à un réseau de confiance.
	remoteIP := net.ParseIP(remoteHost)
	trusted := remoteIP != nil && ipInNets(remoteIP, trustedNets)
	if !trusted {
		return remoteHost
	}

	// Le proxy est de confiance — on peut lire les headers.
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return strings.TrimSpace(cf)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Prendre la première IP (client original).
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return remoteHost
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ipMatchesNets vérifie si l'adresse IP (string) est couverte par l'un des réseaux.
func ipMatchesNets(ipStr string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	return ipInNets(parsed, nets)
}

// parseTrustedProxies compile une liste de CIDRs en []*net.IPNet.
func parseTrustedProxies(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			c += "/32"
		}
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

// --- helpers ----------------------------------------------------------------

func extractArgs(r *http.Request) []string {
	var vals []string
	for _, v := range r.URL.Query() {
		vals = append(vals, strings.Join(v, " "))
	}
	return vals
}

func extractHeaders(r *http.Request) []string {
	var vals []string
	for k, v := range r.Header {
		vals = append(vals, k+": "+strings.Join(v, " "))
	}
	return vals
}

func extractCookies(r *http.Request) []string {
	var vals []string
	for _, c := range r.Cookies() {
		vals = append(vals, c.Value)
	}
	return vals
}

// readBody lit le corps et retourne (raw string, valeurs extraites de JSON/form).
// Les valeurs extraites sont ajoutées aux TargetArgs pour inspecter le contenu décodé.
func readBody(r *http.Request, maxMB int) (raw string, extracted []string) {
	if r.Body == nil || r.ContentLength == 0 {
		return "", nil
	}
	limit := int64(maxMB) * 1024 * 1024
	orig := r.Body
	data, err := io.ReadAll(io.LimitReader(orig, limit))
	// Seuls les premiers maxMB sont inspectés : le corps complet doit néanmoins repartir vers le backend.
	defer func() {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(data), orig), orig}
	}()
	if err != nil || len(data) == 0 {
		return "", nil
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	raw = string(data)

	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "application/json":
		extracted = extractJSON(data)
	case "application/x-www-form-urlencoded":
		if vals, err := url.ParseQuery(raw); err == nil {
			for _, v := range vals {
				extracted = append(extracted, v...)
			}
		}
	case "multipart/form-data":
		if err := r.ParseMultipartForm(limit); err == nil {
			for _, v := range r.MultipartForm.Value {
				extracted = append(extracted, v...)
			}
		}
	}
	return raw, extracted
}

// extractJSON aplatit les valeurs string d'un JSON arbitraire (objet ou tableau).
func extractJSON(data []byte) []string {
	var out []string
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch vv := v.(type) {
		case string:
			out = append(out, vv)
		case map[string]interface{}:
			for _, val := range vv {
				walk(val)
			}
		case []interface{}:
			for _, val := range vv {
				walk(val)
			}
		}
	}
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err == nil {
		walk(parsed)
	}
	return out
}

func targetName(t Target) string {
	switch t {
	case TargetURI:
		return "uri"
	case TargetArgs:
		return "args"
	case TargetBody:
		return "body"
	case TargetHeaders:
		return "headers"
	case TargetCookies:
		return "cookies"
	case TargetResponse:
		return "response"
	}
	return "unknown"
}

// WatchCustomRulesFile surveille path et recharge les règles custom dès que le fichier change.
// path doit pointer vers un fichier JSON contenant un tableau de router.CustomRule.
// Le watcher tourne jusqu'à l'annulation du contexte.
// Les règles standards OWASP restent actives — seules les custom sont remplacées.
func (e *Engine) WatchCustomRulesFile(ctx context.Context, path string) {
	var lastMod time.Time
	reload := func() {
		info, err := os.Stat(path)
		if err != nil || info.ModTime().Equal(lastMod) {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			e.log.Error("waf: lecture fichier règles custom", "path", path, "err", err)
			return
		}
		var defs []router.CustomRule
		if err := json.Unmarshal(data, &defs); err != nil {
			e.log.Error("waf: fichier règles custom invalide", "path", path, "err", err)
			return
		}
		compiled, err := CompileCustomRules(defs)
		if err != nil {
			e.log.Error("waf: compilation règles custom", "path", path, "err", err)
			return
		}
		e.mu.Lock()
		// Conserver uniquement les règles non-custom (DefaultRules) puis ajouter les nouvelles.
		base := DefaultRules()
		e.rules = append(base, compiled...)
		e.mu.Unlock()
		lastMod = info.ModTime()
		e.log.Info("waf: règles custom rechargées depuis fichier", "path", path, "count", len(defs))
	}

	reload() // chargement initial
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reload()
		}
	}
}
