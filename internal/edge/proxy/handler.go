// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/errorpages"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/tracing"
)

// Handler est le reverse proxy HTTP pour une route donnée.
type Handler struct {
	route        *router.Route
	balancer     Balancer
	cb           *circuitBreaker // non-nil si route.CircuitBreaker est configuré
	health       *BackendHealth
	peers        *PeerRegistry
	log          *slog.Logger
	transport    http.RoundTripper
	conditionRes []*regexp.Regexp // parallèle à route.Conditions ; nil si pas regex
	subFilterRes []*regexp.Regexp // parallèle à route.SubFilters ; nil si pas regex
	rpByBackend  sync.Map         // backend URL -> *httputil.ReverseProxy (revue P1 #4)
}

type proxyAttemptKey struct{}
type backendCallStartKey struct{}

type proxyAttempt struct {
	writeOnError bool
	attempt      int
	backend      string
	failed       bool
	err          error // erreur transport pour distinguer transitoire vs panne réelle
}

func NewHandler(route *router.Route, health *BackendHealth, metrics metricsScorer, peers *PeerRegistry, log *slog.Logger) *Handler {
	bal, cb := NewBalancer(route, metrics)
	return &Handler{
		route:        route,
		balancer:     bal,
		cb:           cb,
		health:       health,
		peers:        peers,
		log:          log,
		transport:    buildTransport(route),
		conditionRes: compileConditionRegexes(route),
		subFilterRes: compileSubFilterRegexes(route),
	}
}

func compileSubFilterRegexes(route *router.Route) []*regexp.Regexp {
	if route == nil || len(route.SubFilters) == 0 {
		return nil
	}
	out := make([]*regexp.Regexp, len(route.SubFilters))
	for i, f := range route.SubFilters {
		if !f.Regex || f.From == "" {
			continue
		}
		re, err := regexp.Compile(f.From)
		if err != nil {
			continue
		}
		out[i] = re
	}
	return out
}

func compileConditionRegexes(route *router.Route) []*regexp.Regexp {
	if route == nil || len(route.Conditions) == 0 {
		return nil
	}
	out := make([]*regexp.Regexp, len(route.Conditions))
	for i, c := range route.Conditions {
		if !c.Regex || c.Value == "" {
			continue
		}
		re, err := regexp.Compile(c.Value)
		if err != nil {
			continue
		}
		out[i] = re
	}
	return out
}

// buildTransport construit un http.Transport adapté aux timeouts et buffer de la route.
func buildTransport(route *router.Route) http.RoundTripper {
	connectTimeout := 10 * time.Second
	if route.ConnectTimeout > 0 {
		connectTimeout = route.ConnectTimeout
	}
	responseTimeout := 30 * time.Second
	if route.ResponseTimeout > 0 {
		responseTimeout = route.ResponseTimeout
	}
	// SendTimeout n'a pas d'équivalent direct dans http.Transport ;
	// on l'applique comme WriteTimeout via un wrapper si nécessaire.
	// Pour l'instant on l'utilise comme TLSHandshakeTimeout.
	tlsTimeout := 10 * time.Second
	if route.SendTimeout > 0 {
		tlsTimeout = route.SendTimeout
	}

	t := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: responseTimeout,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: route.TLSSkipVerify, //nolint:gosec
		},
	}
	applyHTTPVersion(t, route.HttpVersion)
	// Délégation terminate (et backends HTTPS adressés par IP) : le SNI doit être
	// le Host virtuel (domaine client), pas l'IP de l'URL backend — sinon passerelle B
	// ne trouve pas de certificat (GetCertificate(SNI=192.168.x.x)).
	if route.TLSSkipVerify || strings.HasPrefix(route.ID, "deleg-") {
		return &hostSNITransport{base: t}
	}
	return t
}

// applyHTTPVersion force HTTP/1.1 ou HTTP/2 vers le backend (auto = défaut Go).
func applyHTTPVersion(t *http.Transport, ver string) {
	switch strings.TrimSpace(strings.ToLower(ver)) {
	case "1.1", "http/1.1", "http1.1":
		t.ForceAttemptHTTP2 = false
		// Désactive la négociation ALPN h2 (sinon HTTPS bascule en HTTP/2).
		t.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	case "2", "h2", "http/2", "http2":
		t.ForceAttemptHTTP2 = true
	}
}

// maxSNITransports borne la map bySNI pour éviter la fuite mémoire en multi-tenant.
// Au-delà du cap, le transport est construit correctement mais non mis en cache.
const maxSNITransports = 512

// hostSNITransport force le SNI TLS = Host HTTP (vhost), pas le hostname de l'URL.
type hostSNITransport struct {
	base  *http.Transport
	mu    sync.Mutex
	bySNI map[string]*http.Transport
}

func (t *hostSNITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || t.base == nil {
		return t.base.RoundTrip(req)
	}
	sni := hostnameForSNI(req.Host)
	if sni == "" {
		sni = hostnameForSNI(req.URL.Host)
	}
	// Si le Host est déjà une IP, laisser le SNI par défaut (URL).
	if sni == "" || net.ParseIP(sni) != nil {
		return t.base.RoundTrip(req)
	}
	tr := t.transportForSNI(sni)
	return tr.RoundTrip(req)
}

func (t *hostSNITransport) transportForSNI(sni string) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bySNI == nil {
		t.bySNI = make(map[string]*http.Transport)
	}
	if tr, ok := t.bySNI[sni]; ok {
		return tr
	}
	tr := t.base.Clone()
	cfg := tr.TLSClientConfig
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	cfg.ServerName = sni
	tr.TLSClientConfig = cfg
	if len(t.bySNI) < maxSNITransports {
		t.bySNI[sni] = tr
	}
	return tr
}

func hostnameForSNI(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// logAccess enregistre la requête selon le format configuré pour la route.
func (h *Handler) logAccess(r *http.Request, status, size int, dur time.Duration) {
	cfg := h.route.Logging
	if cfg != nil && !cfg.AccessLog {
		return
	}
	format := "combined"
	if cfg != nil && cfg.Format != "" {
		format = cfg.Format
	}
	switch format {
	case "off":
		return
	case "minimal":
		h.log.Info("access", "method", r.Method, "path", r.URL.Path, "status", status, "ms", dur.Milliseconds())
	case "json":
		h.log.Info("access",
			"host", r.Host, "method", r.Method, "path", r.URL.Path,
			"status", status, "bytes", size, "ms", dur.Milliseconds(),
			"ip", clientIP(r), "ua", r.UserAgent(), "referer", r.Referer(),
		)
	default: // combined
		h.log.Info(fmt.Sprintf(`%s - [%s] "%s %s" %d %d "%s" "%s"`,
			clientIP(r), time.Now().Format("02/Jan/2006:15:04:05 -0700"),
			r.Method, r.URL.RequestURI(), status, size,
			r.Referer(), r.UserAgent(),
		))
	}
}

// logError enregistre une erreur proxy avec le niveau configuré pour la route.
func (h *Handler) logError(msg string, args ...any) {
	level := slog.LevelWarn
	if h.route.Logging != nil {
		switch h.route.Logging.Level {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "error":
			level = slog.LevelError
		}
	}
	h.log.Log(nil, level, msg, args...)
}

// writeError sert la page d'erreur pour le code HTTP donné.
// Ordre : template bibliothèque → pages legacy (URL/HTML) → page native.
func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, status int) {
	reqID := r.Header.Get("X-Request-ID")
	if h.route.ErrorPages != nil {
		if body, redirect, ok := errorpages.ResolveCustom(h.route.ErrorPages, status, r.Host, reqID, r.Header.Get("Accept-Language"), errorpages.DefaultStore()); ok {
			if redirect != "" {
				http.Redirect(w, r, redirect, http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(status)
			w.Write([]byte(body)) //nolint:errcheck
			return
		}
	}
	html := errorpages.Render(status, r.Host, reqID, r.Header.Get("Accept-Language"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(html)) //nolint:errcheck
}

// statusRecorder capture le code de statut et la taille de réponse.
type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	n, err := sr.ResponseWriter.Write(b)
	sr.size += n
	return n, err
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter { return sr.ResponseWriter }

func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(sr.ResponseWriter).Hijack()
}

func (sr *statusRecorder) Flush() {
	http.NewResponseController(sr.ResponseWriter).Flush() //nolint:errcheck
}

// ServeHTTP implémente http.Handler : sélectionne le backend et proxifie.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() { h.logAccess(r, sr.status, sr.size, time.Since(start)) }()
	w = sr

	if isUpgrade(r) && h.route.Websocket != nil && !*h.route.Websocket {
		h.writeError(w, r, http.StatusBadRequest)
		return
	}

	// Shadow mirror : le body est pipé en parallèle vers le backend primaire et le miroir.
	// Un pipe évite de bloquer la goroutine requête sur io.ReadAll avant que le primaire commence.
	// GetBody est mis à nil : les retries ne peuvent pas rejouer le body (trade-off acceptable
	// pour une feature de test/observation).
	if h.route.Shadow != nil && h.route.Shadow.Backend != "" && r.Body != nil {
		metrics.Routing.ShadowTotal.WithLabelValues(h.route.Host).Inc()
		var shadowBuf bytes.Buffer
		pr, pw := io.Pipe()
		origBody := r.Body
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(io.MultiWriter(pw, &shadowBuf), origBody)
			_ = origBody.Close()
			pw.Close()
		}()
		r.Body = io.NopCloser(pr)
		r.GetBody = nil
		method, uri, host, hdr := r.Method, r.URL.RequestURI(), r.Host, r.Header.Clone()
		defer func() {
			_, _ = io.Copy(io.Discard, pr) // purge si le primaire n'a pas lu le body en entier
			<-done
			go h.fireShadow(method, uri, host, hdr, shadowBuf.Bytes())
		}()
	}

	// Routage conditionnel : si une condition correspond, court-circuit vers le backend dédié
	if override := h.matchCondition(r); override != "" {
		h.doURL(w, r, override, 0)
		return
	}

	// Canary : basculement header/cookie ou par pourcentage
	if h.route.Canary != nil && h.route.Canary.Backend != "" {
		if h.isCanary(r) {
			metrics.Routing.CanaryTotal.WithLabelValues(h.route.Host).Inc()
			h.doURL(w, r, h.route.Canary.Backend, 0)
			return
		}
	}

	candidates := h.failoverCandidates(r)
	if len(candidates) == 0 {
		h.writeError(w, r, http.StatusServiceUnavailable)
		return
	}

	attempts := make([]*router.Backend, 0, len(candidates))
	for _, b := range candidates {
		if h.health.IsHealthy(b.URL) {
			attempts = append(attempts, b)
		}
	}
	// Fail-open : la sonde de santé est un signal, pas un verrou. Si elle déclare
	// tout le pool down on tente quand même — le trafic réel fait autorité, et
	// une sonde qui se trompe ne doit pas transformer un backend joignable en 502.
	if len(attempts) == 0 {
		attempts = candidates
		h.log.Warn("aucun backend sain, tentative quand même", "host", h.route.Host, "backends", len(candidates))
	}

	for i, backend := range attempts {
		if i > 0 {
			metrics.Backend.RetriesTotal.WithLabelValues(h.route.Host, attempts[i-1].URL).Inc()
		}
		// Dernière chance d'écrire l'erreur : plus aucun candidat après celui-ci
		writeOnError := i == len(attempts)-1
		ok, responded, transportErr := h.do(w, r, backend, i, writeOnError)
		if ok {
			h.health.MarkUp(backend.URL)
			if h.cb != nil {
				h.cb.RecordSuccess()
			}
			if h.route.StickyCookie != "" {
				http.SetCookie(w, &http.Cookie{
					Name:     h.route.StickyCookie,
					Value:    backend.URL,
					Path:     "/",
					HttpOnly: true,
					Secure:   middleware.CookieSecure(r),
					SameSite: http.SameSiteLaxMode,
				})
			}
			return
		}
		// Échec dial/proxy : quarantaine uniquement pour les vraies pannes.
		// Les erreurs transitoires (EOF, ECONNRESET) ne quarantinent pas le backend
		// pour ne pas bloquer les requêtes concurrentes du navigateur.
		if ttl := quarantineDuration(transportErr); ttl > 0 {
			h.health.MarkDown(backend.URL, ttl)
		}
		if h.cb != nil {
			h.cb.RecordFailure()
		}
		if responded {
			return
		}
		if h.route.Retry != nil && i < len(attempts)-1 {
			wait := h.route.Retry.InitialWait * time.Duration(math.Pow(2, float64(i)))
			if wait > h.route.Retry.MaxWait {
				wait = h.route.Retry.MaxWait
			}
			if wait > 0 {
				select {
				case <-time.After(wait):
				case <-r.Context().Done():
					return
				}
			}
		}
	}
	h.writeError(w, r, http.StatusBadGateway)
}

// failoverCandidates ordonne les backends : préférence balancer, puis les autres.
func (h *Handler) failoverCandidates(r *http.Request) []*router.Backend {
	n := len(h.route.Backends)
	if n == 0 {
		return nil
	}
	out := make([]*router.Backend, 0, n)
	seen := make(map[string]bool, n)

	// Preferé par le balancer (adaptive / RR / weighted / sticky)
	if pref := h.balancer.Next(r); pref != nil && h.health.IsHealthy(pref.URL) {
		out = append(out, pref)
		seen[pref.URL] = true
	}
	for i := range h.route.Backends {
		b := &h.route.Backends[i]
		if seen[b.URL] {
			continue
		}
		out = append(out, b)
		seen[b.URL] = true
	}
	return h.applySlowStart(r, out)
}

// applySlowStart détourne une part des requêtes destinées à un backend en montée en charge
// vers un backend plus avancé : le backend ramping reçoit ~f de sa part nominale.
// Sans alternative plus avancée (un seul backend, tous en montée), l'ordre est inchangé.
func (h *Handler) applySlowStart(r *http.Request, out []*router.Backend) []*router.Backend {
	window := time.Duration(h.route.SlowStartSec) * time.Second
	if window <= 0 || len(out) < 2 {
		return out
	}
	pref := out[0]
	f := h.health.RampFactor(pref.URL, window)
	if f >= 1 || rand.Float64() < f {
		return out
	}
	// Une session collante existante garde son backend, quitte à le charger trop tôt.
	if h.route.StickyCookie != "" {
		if c, err := r.Cookie(h.route.StickyCookie); err == nil && c.Value == pref.URL {
			return out
		}
	}
	// Alternative : parcours cyclique à partir du backend suivant, pour répartir le trafic détourné.
	n := len(h.route.Backends)
	start := 0
	for i := range h.route.Backends {
		if h.route.Backends[i].URL == pref.URL {
			start = i
			break
		}
	}
	for k := 1; k < n; k++ {
		alt := &h.route.Backends[(start+k)%n]
		if alt.URL == pref.URL || !h.health.IsHealthy(alt.URL) || h.health.RampFactor(alt.URL, window) <= f {
			continue
		}
		metrics.Backend.SlowStartShifted.WithLabelValues(h.route.Host, pref.URL).Inc()
		reordered := make([]*router.Backend, 0, len(out))
		reordered = append(reordered, alt)
		for _, b := range out {
			if b.URL != alt.URL {
				reordered = append(reordered, b)
			}
		}
		return reordered
	}
	return out
}

// isCanary retourne true si la requête doit être routée vers le backend canary.
func (h *Handler) isCanary(r *http.Request) bool {
	c := h.route.Canary
	if c.Header != "" {
		v := r.Header.Get(c.Header)
		if v != "" && (c.HeaderValue == "" || v == c.HeaderValue) {
			return true
		}
	}
	if c.CookieName != "" {
		if ck, err := r.Cookie(c.CookieName); err == nil && ck.Value != "" {
			return true
		}
	}
	if c.Weight > 0 && rand.Intn(100) < c.Weight {
		return true
	}
	return false
}

// matchCondition retourne l'URL de backend si une condition routage correspond, sinon "".
func (h *Handler) matchCondition(r *http.Request) string {
	for i, cond := range h.route.Conditions {
		var re *regexp.Regexp
		if i < len(h.conditionRes) {
			re = h.conditionRes[i]
		}
		if conditionMatches(cond, re, r) {
			return cond.Backend
		}
	}
	return ""
}

func conditionMatches(c router.Condition, re *regexp.Regexp, r *http.Request) bool {
	var actual string
	switch c.Type {
	case "header":
		actual = r.Header.Get(c.Name)
	case "cookie":
		if ck, err := r.Cookie(c.Name); err == nil {
			actual = ck.Value
		}
	case "query":
		actual = r.URL.Query().Get(c.Name)
	case "method":
		actual = r.Method
	default:
		return false
	}
	if c.Regex {
		if re == nil {
			return false
		}
		return re.MatchString(actual)
	}
	return actual == c.Value
}

// doURL envoie la requête vers une URL de backend spécifique.
func (h *Handler) doURL(w http.ResponseWriter, r *http.Request, backendURL string, attempt int) {
	b := &router.Backend{URL: backendURL}
	h.do(w, r, b, attempt, true) //nolint:errcheck
}

// fireShadow envoie une copie de la requête au backend miroir sans bloquer.
// method/uri/host/header/body sont déjà clonés — ne pas toucher à la requête principale.
func (h *Handler) fireShadow(method, requestURI, host string, header http.Header, body []byte) {
	target, err := url.Parse(h.route.Shadow.Backend)
	if err != nil {
		return
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target.String()+requestURI, bodyReader)
	if err != nil {
		return
	}
	if header != nil {
		req.Header = header.Clone()
	}
	req.Header.Set("X-Shadow-Origin", host)
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// do envoie la requête vers un backend. Retourne (succès, réponseÉcrite, erreurTransport).
// Si writeOnError est false, un échec transport n'écrit pas encore la page d'erreur (failover).
func (h *Handler) do(w http.ResponseWriter, r *http.Request, b *router.Backend, attempt int, writeOnError bool) (ok bool, responded bool, transportErr error) {
	target, err := url.Parse(b.URL)
	if err != nil {
		return false, false, err
	}

	// Limite la taille du corps si configurée (nginx: client_max_body_size)
	if h.route.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.route.MaxBodySize)
	}

	callStart := time.Now()
	att := &proxyAttempt{writeOnError: writeOnError, attempt: attempt, backend: b.URL}
	ctx := context.WithValue(r.Context(), proxyAttemptKey{}, att)
	ctx = context.WithValue(ctx, backendCallStartKey{}, callStart)
	r = r.WithContext(ctx)
	r, endSpan := h.traceBackend(r, target.Host, attempt)
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	rp := h.reverseProxyFor(b, target)
	rp.ServeHTTP(sr, r)
	endSpan(sr.status, att.err)
	dur := time.Since(callStart)
	backendHost := target.Host
	if att.failed {
		metrics.Backend.ErrorsTotal.WithLabelValues(h.route.Host, backendHost, backendErrorType(att.err)).Inc()
		return false, writeOnError, att.err // réponse écrite seulement si writeOnError
	}
	statusStr := fmt.Sprintf("%d", sr.status)
	metrics.Backend.RequestsTotal.WithLabelValues(h.route.Host, backendHost, statusStr).Inc()
	metrics.Backend.Duration.WithLabelValues(h.route.Host, backendHost, statusClass(sr.status)).Observe(dur.Seconds())
	return true, true, nil
}

// statusClass retourne la classe HTTP (2xx, 3xx, 4xx, 5xx) pour un label Prometheus.
func statusClass(code int) string {
	switch {
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// backendErrorType classifie une erreur transport pour le label Prometheus.
func backendErrorType(err error) string {
	if err == nil {
		return "other"
	}
	s := err.Error()
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "timeout") || strings.Contains(s, "deadline") {
		return "timeout"
	}
	if strings.Contains(s, "connection refused") || strings.Contains(s, "no such host") || strings.Contains(s, "dial") {
		return "connect"
	}
	if strings.Contains(s, "EOF") || strings.Contains(s, "reset") || strings.Contains(s, "broken pipe") {
		return "reset"
	}
	return "other"
}

func (h *Handler) reverseProxyFor(b *router.Backend, target *url.URL) *httputil.ReverseProxy {
	if v, ok := h.rpByBackend.Load(b.URL); ok {
		return v.(*httputil.ReverseProxy)
	}
	urlScheme, urlHost := target.Scheme, target.Host
	preserveHost := h.route.PreserveHost
	subFilterRes := h.subFilterRes
	transport := h.transportFor(b)
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			tracing.Inject(req.Context(), req.Header)
			xfHost := req.Host
			req.URL.Scheme = urlScheme
			req.URL.Host = urlHost
			if prefix := h.route.StripPrefix; prefix != "" {
				req.URL.Path = router.StripPathPrefix(req.URL.Path, prefix)
				req.URL.RawPath = ""
			}
			if h.route.PathRewrite != "" && h.route.PathRewritePattern != "" {
				req.URL.Path = router.ApplyPathRewrite(req.URL.Path, h.route.PathRewritePattern, h.route.PathRewrite)
				req.URL.RawPath = ""
			}
			if preserveHost != nil && !*preserveHost {
				req.Host = urlHost
			}
			applyForwardedHeaders(req, h.route, xfHost)
			applyRequestHeaderManipulation(req, h.route)
			if h.route.RequestID != nil && !*h.route.RequestID {
				req.Header.Del("X-Request-ID")
			}
		},
		Transport:  transport,
		BufferPool: bufferPoolFor(h.route.BufferSize),
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request != nil {
				if t, ok := resp.Request.Context().Value(backendCallStartKey{}).(time.Time); ok {
					metrics.Backend.TTFB.WithLabelValues(h.route.Host, urlHost).Observe(time.Since(t).Seconds())
				}
			}
			if len(h.route.CookieDomains) > 0 || len(h.route.CookiePaths) > 0 {
				rewriteSetCookieHeaders(resp, h.route.CookieDomains, h.route.CookiePaths)
			}
			if len(h.route.SubFilters) > 0 {
				if err := applySubFilters(resp, h.route.SubFilters, subFilterRes); err != nil {
					return err
				}
			}
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && len(h.route.ProxyRedirects) > 0 {
				for _, hdr := range []string{"Location", "Refresh"} {
					if v := resp.Header.Get(hdr); v != "" {
						if rewritten := applyProxyRedirects(v, h.route.ProxyRedirects); rewritten != v {
							resp.Header.Set(hdr, rewritten)
							break
						}
					}
				}
			}
			if resp.StatusCode < 400 || h.route.ErrorPages == nil {
				return nil
			}
			in := resp.Request
			if in == nil {
				return nil
			}
			reqID := in.Header.Get("X-Request-ID")
			body, redirect, ok := errorpages.ResolveCustom(h.route.ErrorPages, resp.StatusCode, in.Host, reqID, in.Header.Get("Accept-Language"), errorpages.DefaultStore())
			if !ok {
				return nil
			}
			resp.Body.Close()
			if redirect != "" {
				resp.Body = io.NopCloser(strings.NewReader(""))
				resp.ContentLength = 0
				resp.StatusCode = http.StatusFound
				resp.Status = "302 Found"
				resp.Header.Set("Location", redirect)
				return nil
			}
			b := []byte(body)
			resp.Body = io.NopCloser(bytes.NewReader(b))
			resp.ContentLength = int64(len(b))
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Header.Del("Content-Encoding")
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, e error) {
			att, _ := req.Context().Value(proxyAttemptKey{}).(*proxyAttempt)
			backend := b.URL
			attempt := 0
			writeOnError := true
			if att != nil {
				att.failed = true
				att.err = e
				backend = att.backend
				attempt = att.attempt
				writeOnError = att.writeOnError
			}
			h.logError("proxy error", "backend", backend, "attempt", attempt, "err", e)
			if writeOnError {
				h.writeError(rw, req, http.StatusBadGateway)
			}
		},
	}
	actual, _ := h.rpByBackend.LoadOrStore(b.URL, rp)
	return actual.(*httputil.ReverseProxy)
}

// transportFor retourne un RoundTripper qui dial via gateway si backend distant.
func (h *Handler) transportFor(b *router.Backend) http.RoundTripper {
	if b == nil || b.OwnerEdgeEndpoint == "" || h.peers == nil {
		return h.transport
	}
	base, _ := h.transport.(*http.Transport)
	if base == nil {
		if ht, ok := h.transport.(*hostSNITransport); ok {
			base = ht.base
		}
	}
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	timeout := 10 * time.Second
	if h.route.ConnectTimeout > 0 {
		timeout = h.route.ConnectTimeout
	}
	backend := *b
	peers := h.peers
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return DialBackend(ctx, &backend, peers, timeout)
	}
	if _, ok := h.transport.(*hostSNITransport); ok {
		return &hostSNITransport{base: t}
	}
	return t
}

// bufPool adapte middleware.BufPool pour httputil.ReverseProxy.
type bufPool struct {
	size int
}

func bufferPoolFor(size int) httputil.BufferPool {
	if size <= 0 {
		return &bufPool{size: 0} // utilise middleware.BufPool (pool global 32 KB)
	}
	return &bufPool{size: size}
}

func (bp *bufPool) Get() []byte {
	if bp.size <= 0 {
		return *middleware.GetBuf()
	}
	return make([]byte, bp.size)
}

func (bp *bufPool) Put(b []byte) {
	if bp.size <= 0 {
		middleware.PutBuf(&b)
	}
	// buffers custom size : pas de pool (évite la réutilisation de slices de tailles mixtes)
}

func isUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func isGRPC(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

func clientIP(r *http.Request) string {
	return edgelog.RealIP(r)
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// applySubFilters remplace des chaînes ou regex dans le body texte d'une réponse.
// Décompresse gzip si nécessaire, puis supprime Content-Encoding et met à jour Content-Length.
// Ne traite que les réponses dont le Content-Type commence par "text/" ou "application/json".
// res contient les regexes pré-compilées (parallèles à filters) ; nil signifie "pas regex".
func applySubFilters(resp *http.Response, filters []router.SubFilter, res []*regexp.Regexp) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/") && !strings.HasPrefix(ct, "application/json") {
		return nil
	}
	body := resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil // ignore — ne pas casser la réponse
		}
		defer gz.Close()
		body = gz
		resp.Header.Del("Content-Encoding")
	}
	raw, err := io.ReadAll(body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		return nil
	}
	result := string(raw)
	for i, f := range filters {
		if f.Regex {
			var re *regexp.Regexp
			if i < len(res) {
				re = res[i]
			}
			if re == nil {
				continue
			}
			result = re.ReplaceAllString(result, f.To)
		} else {
			result = strings.ReplaceAll(result, f.From, f.To)
		}
	}
	b := []byte(result)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	return nil
}

// rewriteSetCookieHeaders réécrit les attributs Domain= et Path= dans tous les
// headers Set-Cookie de la réponse selon les règles proxy_cookie_domain/path.
func rewriteSetCookieHeaders(resp *http.Response, domainRules, pathRules []router.CookieRewrite) {
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}
	changed := false
	for i, raw := range cookies {
		rewritten := rewriteCookieAttr(raw, "Domain", domainRules)
		rewritten = rewriteCookieAttr(rewritten, "Path", pathRules)
		if rewritten != raw {
			cookies[i] = rewritten
			changed = true
		}
	}
	if changed {
		resp.Header["Set-Cookie"] = cookies
	}
}

// rewriteCookieAttr remplace la valeur d'un attribut nommé attr dans un Set-Cookie brut.
func rewriteCookieAttr(raw, attr string, rules []router.CookieRewrite) string {
	if len(rules) == 0 {
		return raw
	}
	lower := strings.ToLower(raw)
	needle := strings.ToLower(attr) + "="
	idx := strings.Index(lower, "; "+needle)
	if idx < 0 {
		// peut être le premier attribut après le nom=valeur
		idx = strings.Index(lower, needle)
		if idx < 0 || idx == 0 {
			// idx==0 serait "Domain=..." sans nom de cookie en tête — on ignore
			return raw
		}
		// vérifier que c'est bien après un ";"
		before := strings.TrimRight(lower[:idx], " ")
		if !strings.HasSuffix(before, ";") {
			return raw
		}
		idx-- // recule sur le ";"
	}
	// trouver la fin de la valeur de l'attribut
	attrStart := idx + 2 + len(needle) // après "; Domain="
	end := strings.IndexByte(raw[attrStart:], ';')
	var attrVal string
	if end < 0 {
		attrVal = raw[attrStart:]
	} else {
		attrVal = raw[attrStart : attrStart+end]
	}
	newVal := applyCookieRewrites(attrVal, rules)
	if newVal == attrVal {
		return raw
	}
	if end < 0 {
		return raw[:attrStart] + newVal
	}
	return raw[:attrStart] + newVal + raw[attrStart+end:]
}

func applyCookieRewrites(value string, rules []router.CookieRewrite) string {
	for _, r := range rules {
		if r.Regex {
			re, err := regexp.Compile(r.From)
			if err != nil {
				continue
			}
			if re.MatchString(value) {
				return re.ReplaceAllString(value, r.To)
			}
		} else {
			if strings.EqualFold(value, r.From) {
				return r.To
			}
		}
	}
	return value
}

// applyProxyRedirects réécrit une valeur de header Location/Refresh selon les règles
// proxy_redirect de la route. Retourne la valeur originale si aucune règle ne correspond.
func applyProxyRedirects(value string, rules []router.ProxyRedirect) string {
	for _, r := range rules {
		if r.Regex {
			re, err := regexp.Compile(r.From)
			if err != nil {
				continue
			}
			if re.MatchString(value) {
				return re.ReplaceAllString(value, r.To)
			}
		} else {
			if strings.HasPrefix(value, r.From) {
				return r.To + value[len(r.From):]
			}
		}
	}
	return value
}

// applyForwardedHeaders injecte (ou retire) les en-têtes X-Forwarded-* / X-Real-IP
// selon headers_manipulation.forwarded_headers. Absent/nil = les 4 par défaut (iso nginx).
func applyForwardedHeaders(req *http.Request, route *router.Route, xfHost string) {
	setOrDel := func(name, value string) {
		if wantsForwardedHeader(route, name) {
			req.Header.Set(name, value)
		} else {
			req.Header.Del(name)
		}
	}
	ip := clientIP(req)
	setOrDel("X-Forwarded-For", ip)
	setOrDel("X-Forwarded-Proto", scheme(req))
	setOrDel("X-Forwarded-Host", xfHost)
	setOrDel("X-Real-IP", ip)
}

func wantsForwardedHeader(route *router.Route, name string) bool {
	if route == nil || route.HeadersManipulation == nil || route.HeadersManipulation.ForwardedHeaders == nil {
		return true
	}
	want := strings.ToLower(name)
	for _, h := range route.HeadersManipulation.ForwardedHeaders {
		if strings.ToLower(strings.TrimSpace(h)) == want {
			return true
		}
	}
	return false
}

func applyRequestHeaderManipulation(req *http.Request, route *router.Route) {
	if route == nil || route.HeadersManipulation == nil {
		return
	}
	hm := route.HeadersManipulation
	for _, name := range hm.RequestHideHeader {
		name = strings.TrimSpace(name)
		if name != "" {
			req.Header.Del(name)
		}
	}
	vars := middleware.GetRequestVars(req.Context())
	for k, v := range hm.RequestSetHeader {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		req.Header.Set(k, middleware.ExpandVars(v, vars))
	}
}

// traceBackend ouvre le span client de l'appel backend et le rattache à la requête sortante.
func (h *Handler) traceBackend(r *http.Request, backendHost string, attempt int) (*http.Request, func(status int, err error)) {
	ctx, end := tracing.StartBackend(r.Context(), backendHost, attempt)
	return r.WithContext(ctx), end
}
