// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"os"
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/errorpages"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/grpctrans"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/static"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
	"github.com/vincamok/goproxify/internal/edge/tracing"
	"go.opentelemetry.io/otel/attribute"
)

type cachedDispatch struct {
	gen uint64
	h   http.Handler
}

// --- Mux HTTP ------------------------------------------------------------

func (s *Server) httpMux() http.Handler {
	return rejectTrace(s.newMux(metricsPublic()))
}

// metricsPublic : GPX_METRICS_PUBLIC=1 expose /metrics sur les ports publics. Par défaut les métriques ne sont
// servies que par l'API interne (GET /internal/v1/metrics, jeton de la passerelle) : sur le port public, elles
// livraient à n'importe quel client les hôtes, les URL de backends et les compteurs de sécurité, et le chemin
// /metrics masquait celui des applications derrière la passerelle.
func metricsPublic() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GPX_METRICS_PUBLIC"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func (s *Server) newMux(publicMetrics bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dispatch)
	if publicMetrics {
		mux.Handle("/metrics", promhttp.Handler())
	}
	return mux
}

// rejectTrace refuse TRACE/TRACK : aucun usage légitime derrière un reverse proxy (écho des en-têtes,
// risque de fuite de cookies/jetons), et un backend naïf le renverrait tel quel.
func rejectTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" || r.Method == "TRACK" {
			w.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
			http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveDefaultError écrit la page d'erreur par défaut Goproxify (sans contexte de route).
func serveDefaultError(w http.ResponseWriter, r *http.Request, status int) {
	html := errorpages.Render(status, r.Host, r.Header.Get("X-Request-ID"), r.Header.Get("Accept-Language"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(html)) //nolint:errcheck
}

// serveErrorPageAsset sert /_goproxify/error-pages/{id}/{filename} depuis le volume passerelle.
func (s *Server) serveErrorPageAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, errorpages.PublicPathPref)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	content, ct, ok := errorpages.DefaultStore().GetAsset(parts[0], parts[1])
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(content) //nolint:errcheck
	}
}

func (s *Server) handlePushErrorPages(w http.ResponseWriter, r *http.Request) {
	var tpls []errorpages.Template
	if err := json.NewDecoder(r.Body).Decode(&tpls); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := errorpages.DefaultStore().ReplaceAll(tpls); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("error pages mises à jour", "count", len(tpls))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	// Assets des pages d'erreur custom (images, CSS…) — avant le routage par host.
	if strings.HasPrefix(r.URL.Path, errorpages.PublicPathPref) {
		s.serveErrorPageAsset(w, r)
		return
	}

	host := r.Host
	// Enlever le port si présent
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Limite globale de req/s (protection DDoS volumétrique) — avant toute résolution.
	if s.threatEngine != nil && !s.threatEngine.CheckGlobal() {
		w.Header().Set("Retry-After", "1")
		serveDefaultError(w, r, http.StatusServiceUnavailable)
		return
	}

	// L'observation suit la requête : le WAF y note le score de ses règles, Ephor verse la requête au magasin comportemental
	// une fois la réponse connue.
	obsCtx, _ := behavior.WithObservation(r.Context())
	r = r.WithContext(obsCtx)

	// Vérification globale des profils IP (deny lists) avant le routage.
	// Utilise CF-Connecting-IP / X-Forwarded-For si disponible (Cloudflare, reverse proxy).
	remoteIP := edgelog.RealIP(r)
	s.lastUA.Note(remoteIP, r.UserAgent())
	if blocked, reason := s.profileStore.CheckBlocked(remoteIP); blocked {
		if ok, n := s.blockLog.Allow("profil|" + remoteIP); ok {
			s.log.Warn("ip bloquée par profil", blockedAttrs(n, "ip", remoteIP, "profile", reason)...)
		}
		tracing.Event(r.Context(), "ip_profile.blocked")
		serveDefaultError(w, r, http.StatusForbidden)
		return
	}
	// Bans Fail2Ban / CrowdSec / natifs — les profils allow (et IPs privées) passent outre.
	if !s.profileStore.IsAllowed(remoteIP) {
		if blocked, reason := s.banStore.CheckBlocked(remoteIP); blocked {
			if ok, n := s.blockLog.Allow("ban|" + remoteIP); ok {
				s.log.Warn("ip bloquée par ban", blockedAttrs(n, "ip", remoteIP, "reason", reason)...)
			}
			tracing.Event(r.Context(), "ban.blocked", attribute.String("source", banSource(reason)))
			if strings.HasPrefix(reason, "threat") {
				s.rejectThreat(w, r)
				return
			}
			serveDefaultError(w, r, http.StatusForbidden)
			return
		}
	}

	// Moteur de détection automatique (threat engine) — après les bans explicites. Les adresses de
	// la liste blanche des bans ne sont ni évaluées ni comptées.
	whitelisted := s.profileStore.IsWhitelisted(remoteIP)
	if s.threatEngine != nil && !whitelisted {
		if blocked, reason := s.threatEngine.Check(r, remoteIP); reason != "" {
			r = threat.WithSignal(r, reason)
			tracing.Event(r.Context(), "ephor.signal", attribute.String("reason", reason), attribute.Bool("blocked", blocked))
			if blocked {
				if ok, n := s.blockLog.Allow("moteur|" + remoteIP); ok {
					s.log.Warn("ip bloquée par moteur de détection", blockedAttrs(n, "ip", remoteIP, "reason", reason)...)
				}
				s.rejectThreat(w, r)
				return
			}
		}
	}

	route, ok := s.table.ByHost(host)
	if !ok {
		serveDefaultError(w, r, http.StatusNotFound)
		return
	}

	// Résoudre les snippets et le fournisseur d'auth avant de construire la chaîne.
	route = router.ResolveSnippets(route, s.snippetStore)
	route = router.ResolveAuthProvider(route, s.providerStore)
	if route.SnippetUnresolved != "" {
		s.log.Error("snippets de la route inutilisables, accès refusé", "route", route.ID, "snippets", route.SnippetUnresolved)
		serveDefaultError(w, r, http.StatusServiceUnavailable)
		return
	}
	tracing.Annotate(r.Context(), attribute.String("gpx.route.id", route.ID), attribute.String("gpx.route.host", route.Host))

	locPath := ""
	if loc := router.MatchLocation(route, r.URL.Path); loc != nil {
		locPath = loc.Path
		route = router.MergeLocation(route, loc)
	}

	h := s.handlerForRoute(route, locPath)

	// Métriques
	metricsOn := metrics.RequestMetricsOn()
	if metricsOn {
		metrics.Edge.ActiveRequests.WithLabelValues(host).Inc()
	}
	start := time.Now()
	rw := &statusCapture{ResponseWriter: w}
	learn := s.surface != nil && route.Surface != nil && surface.Learning(route.Surface.Mode)
	var reqPath, reqQuery string
	var verdict *middleware.OpenAPIOutcome
	if learn {
		reqPath, reqQuery = r.URL.Path, r.URL.RawQuery
		var ctx context.Context
		ctx, verdict = middleware.WithOpenAPIOutcome(r.Context())
		r = r.WithContext(ctx)
	}
	h.ServeHTTP(rw, r)
	if metricsOn {
		recordRequestMetrics(host, r, rw, time.Since(start))
	}

	// Avant Ephor : la note de l'IP ne doit pas contenir ce que cette requête vient d'y ajouter.
	if learn {
		obs := surface.Observed{
			Route: route.ID, Host: route.Host, Request: r, Path: reqPath, RawQuery: reqQuery, IP: remoteIP,
			Status: rw.status, ResponseType: rw.Header().Get("Content-Type"), Violation: verdict.Reason, Blocked: verdict.Blocked, Type: route.Surface.Type,
			Clean: s.surfaceClean(r, remoteIP),
		}
		if hits := surfaceWAFHits(behavior.ObservationFrom(r.Context())); len(hits) > 0 {
			obs.WAFHits, obs.WAFBlocked = hits, behavior.ObservationFrom(r.Context()).WAFBlocked()
			obs.CleanApartFromWAF = s.surfaceCleanApartFromWAF(r, remoteIP)
		}
		s.surface.Observe(obs)
		if verdict.Reason != "" && !whitelisted {
			s.surfaceNoteViolation(remoteIP, rw.status)
		}
	}
	if s.threatEngine != nil && !whitelisted {
		s.threatEngine.Observe(r, remoteIP, route.Host, rw.status)
	}
}

func recordRequestMetrics(host string, r *http.Request, rw *statusCapture, dur time.Duration) {
	metrics.Edge.ActiveRequests.WithLabelValues(host).Dec()
	metrics.Edge.RequestsTotal.WithLabelValues(host, r.Method, fmt.Sprintf("%d", rw.status)).Inc()
	// Un WebSocket dure autant que la connexion : l'inclure ferait de chaque session ouverte la
	// « requête la plus lente » du p95.
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		metrics.Edge.RequestDuration.WithLabelValues(host).Observe(dur.Seconds())
	}
	if rw.bytes > 0 {
		metrics.Edge.BytesOut.Add(float64(rw.bytes))
		metrics.Edge.BytesOutByHost.WithLabelValues(host).Add(float64(rw.bytes))
		metrics.Traffic.ResponseSizeBytes.WithLabelValues(host).Observe(float64(rw.bytes))
	}
	if r.ContentLength > 0 {
		metrics.Edge.BytesIn.Add(float64(r.ContentLength))
		metrics.Edge.BytesInByHost.WithLabelValues(host).Add(float64(r.ContentLength))
		metrics.Traffic.RequestSizeBytes.WithLabelValues(host).Observe(float64(r.ContentLength))
	}
}

func (s *Server) invalidateDispatchCache() {
	s.dispatchGen.Add(1)
}

// invalidateRouteCache supprime uniquement les entrées du cache dispatch appartenant
// à la route donnée, sans invalider les autres routes.
func (s *Server) invalidateRouteCache(routeID string) {
	prefix := routeID + "\x00"
	s.dispatchHandlers.Range(func(k, _ any) bool {
		if key, ok := k.(string); ok && strings.HasPrefix(key, prefix) {
			s.dispatchHandlers.Delete(key)
		}
		return true
	})
}

// routeCacheDir donne le répertoire de cache disque dédié à une route (un dir
// par route — voir DiskCache.Purge, qui vide ce répertoire en entier).
func routeCacheDir(route *router.Route) string {
	if route.Cache != nil && route.Cache.Dir != "" {
		return route.Cache.Dir
	}
	if route.CachePath != "" {
		return route.CachePath
	}
	return "/tmp/goproxify-cache/" + route.ID
}

func (s *Server) handlerForRoute(route *router.Route, locPath string) http.Handler {
	gen := s.dispatchGen.Load()
	key := route.ID + "\x00" + locPath
	if v, ok := s.dispatchHandlers.Load(key); ok {
		if c := v.(*cachedDispatch); c.gen == gen {
			return c.h
		}
	}

	s.dispatchBuildMu.Lock()
	defer s.dispatchBuildMu.Unlock()
	gen = s.dispatchGen.Load()
	if v, ok := s.dispatchHandlers.Load(key); ok {
		if c := v.(*cachedDispatch); c.gen == gen {
			return c.h
		}
	}

	var h http.Handler
	if route.Static != nil && route.Static.Enabled {
		h = static.Handler(route.Static)
	} else {
		ph := proxy.NewHandler(route, s.health, s.metrics, s.peers, s.log.Logger())
		if s.apps != nil {
			ph.SetResponseObserver(s.apps)
		}
		h = ph
		h = grpctrans.Middleware(route.Host, route.GRPCTranscode)(h)
	}
	if route.Cache != nil && route.Cache.Enabled {
		h = proxy.New(routeCacheDir(route)).MiddlewareWithConfig(route.Cache)(h)
	} else if route.CachePath != "" {
		h = proxy.New(route.CachePath).Middleware(h)
	}
	h = wrapStages(h, s.dispatchStages(route, key))

	s.dispatchHandlers.Store(key, &cachedDispatch{gen: gen, h: h})
	return h
}

// stripRequestIDResponse retire X-Request-ID de la réponse client (le middleware
// global l'a déjà posé). La requête backend est nettoyée dans le Director.
func stripRequestIDResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&stripHeaderWriter{ResponseWriter: w, header: "X-Request-ID"}, r)
	})
}

type stripHeaderWriter struct {
	http.ResponseWriter
	header string
	wrote  bool
}

func (w *stripHeaderWriter) WriteHeader(code int) {
	if !w.wrote {
		w.Header().Del(w.header)
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *stripHeaderWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *stripHeaderWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *stripHeaderWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *stripHeaderWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

type statusCapture struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.status = code
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *statusCapture) Write(b []byte) (int, error) {
	n, err := sc.ResponseWriter.Write(b)
	sc.bytes += n
	return n, err
}

func (sc *statusCapture) Flush() {
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sc *statusCapture) Unwrap() http.ResponseWriter { return sc.ResponseWriter }

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if reqID == "" {
			reqID = newRequestID()
			r.Header.Set("X-Request-ID", reqID)
		}
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("gpx-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}


// rejectThreat répond 403 à une IP bloquée ou bannie par Ephor, après l'avoir retenue
// si le tarpit est actif (et non saturé).
func (s *Server) rejectThreat(w http.ResponseWriter, r *http.Request) {
	if s.threatEngine != nil {
		s.threatEngine.TarpitWait(r.Context())
	}
	serveDefaultError(w, r, http.StatusForbidden)
}

// banSource extrait la source d'un motif de ban ("threat: rate" → "threat") : sans IP dans les traces.
func banSource(reason string) string {
	if i := strings.Index(reason, ":"); i > 0 {
		src := reason[:i]
		if strings.Trim(src, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-") == "" {
			return src
		}
	}
	return "other"
}

// serveACMEChallenge répond au challenge http-01 posé par l'Admin. Un token inconnu est
// laissé au backend (qui peut gérer ses propres challenges).
func (s *Server) serveACMEChallenge(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, edgetls.ACMEHTTPPathPrefix) {
		return false
	}
	resp, ok := s.certStore.Challenges.HTTPResponse(strings.TrimPrefix(r.URL.Path, edgetls.ACMEHTTPPathPrefix))
	if !ok {
		return false
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(resp)) //nolint:errcheck
	return true
}
