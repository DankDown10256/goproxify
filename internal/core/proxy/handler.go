// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	"github.com/vincamok/goproxify/internal/core/errorpages"
	corelog "github.com/vincamok/goproxify/internal/core/logger"
	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/router"
)

// Handler est le reverse proxy HTTP pour une route donnée.
type Handler struct {
	route        *router.Route
	balancer     Balancer
	health       *BackendHealth
	peers        *PeerRegistry
	log          *slog.Logger
	transport    http.RoundTripper
	conditionRes []*regexp.Regexp // parallèle à route.Conditions ; nil si pas regex
	rpByBackend  sync.Map         // backend URL -> *httputil.ReverseProxy (revue P1 #4)
}

type proxyAttemptKey struct{}

type proxyAttempt struct {
	writeOnError bool
	attempt      int
	backend      string
	failed       bool
}

func NewHandler(route *router.Route, health *BackendHealth, metrics metricsScorer, peers *PeerRegistry, log *slog.Logger) *Handler {
	return &Handler{
		route:        route,
		balancer:     NewBalancer(route, metrics),
		health:       health,
		peers:        peers,
		log:          log,
		transport:    buildTransport(route),
		conditionRes: compileConditionRegexes(route),
	}
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
	// Délégation terminate (et backends HTTPS adressés par IP) : le SNI doit être
	// le Host virtuel (domaine client), pas l'IP de l'URL backend — sinon Core B
	// ne trouve pas de certificat (GetCertificate(SNI=192.168.x.x)).
	if route.TLSSkipVerify || strings.HasPrefix(route.ID, "deleg-") {
		return &hostSNITransport{base: t}
	}
	return t
}

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
	t.bySNI[sni] = tr
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

	// Shadow mirror : cloner le body sur la goroutine requête avant le miroir (revue P1 #9).
	if h.route.Shadow != nil && h.route.Shadow.Backend != "" {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		go h.fireShadow(r.Method, r.URL.RequestURI(), r.Host, r.Header.Clone(), append([]byte(nil), bodyBytes...))
	}

	// Routage conditionnel : si une condition correspond, court-circuit vers le backend dédié
	if override := h.matchCondition(r); override != "" {
		h.doURL(w, r, override, 0)
		return
	}

	// Canary : basculement header/cookie ou par pourcentage
	if h.route.Canary != nil && h.route.Canary.Backend != "" {
		if h.isCanary(r) {
			h.doURL(w, r, h.route.Canary.Backend, 0)
			return
		}
	}

	candidates := h.failoverCandidates(r)
	if len(candidates) == 0 {
		h.writeError(w, r, http.StatusServiceUnavailable)
		return
	}

	for i, backend := range candidates {
		if !h.health.IsHealthy(backend.URL) {
			continue
		}
		// Dernière chance d'écrire l'erreur : plus aucun candidat sain après celui-ci
		writeOnError := !h.hasHealthyAfter(candidates, i)
		ok, responded := h.do(w, r, backend, i, writeOnError)
		if ok {
			h.health.MarkUp(backend.URL)
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
		// Échec dial/proxy : quarantaine pour que adaptive ne le re-sélectionne pas
		h.health.MarkDown(backend.URL, 15*time.Second)
		if responded {
			return
		}
		if h.route.Retry != nil && i < len(candidates)-1 {
			wait := h.route.Retry.InitialWait * time.Duration(math.Pow(2, float64(i)))
			if wait > h.route.Retry.MaxWait {
				wait = h.route.Retry.MaxWait
			}
			if wait > 0 {
				time.Sleep(wait)
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
	return out
}

func (h *Handler) hasHealthyAfter(cands []*router.Backend, idx int) bool {
	for i := idx + 1; i < len(cands); i++ {
		if h.health.IsHealthy(cands[i].URL) {
			return true
		}
	}
	return false
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

// do envoie la requête vers un backend. Retourne (succès, réponseÉcrite).
// Si writeOnError est false, un échec transport n'écrit pas encore la page d'erreur (failover).
func (h *Handler) do(w http.ResponseWriter, r *http.Request, b *router.Backend, attempt int, writeOnError bool) (ok bool, responded bool) {
	target, err := url.Parse(b.URL)
	if err != nil {
		return false, false
	}

	// Limite la taille du corps si configurée (nginx: client_max_body_size)
	if h.route.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.route.MaxBodySize)
	}

	att := &proxyAttempt{writeOnError: writeOnError, attempt: attempt, backend: b.URL}
	r = r.WithContext(context.WithValue(r.Context(), proxyAttemptKey{}, att))
	rp := h.reverseProxyFor(b, target)
	rp.ServeHTTP(w, r)
	if att.failed {
		return false, writeOnError // réponse écrite seulement si writeOnError
	}
	return true, true
}

func (h *Handler) reverseProxyFor(b *router.Backend, target *url.URL) *httputil.ReverseProxy {
	if v, ok := h.rpByBackend.Load(b.URL); ok {
		return v.(*httputil.ReverseProxy)
	}
	urlScheme, urlHost := target.Scheme, target.Host
	preserveHost := h.route.PreserveHost
	transport := h.transportFor(b)
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			xfHost := req.Host
			req.URL.Scheme = urlScheme
			req.URL.Host = urlHost
			if preserveHost != nil && !*preserveHost {
				req.Host = urlHost
			}
			req.Header.Set("X-Forwarded-For", clientIP(req))
			req.Header.Set("X-Forwarded-Proto", scheme(req))
			req.Header.Set("X-Forwarded-Host", xfHost)
			req.Header.Set("X-Real-IP", clientIP(req))
		},
		Transport:  transport,
		BufferPool: bufferPoolFor(h.route.BufferSize),
		ModifyResponse: func(resp *http.Response) error {
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
	if b == nil || b.OwnerCoreEndpoint == "" || h.peers == nil {
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
	return corelog.RealIP(r)
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
