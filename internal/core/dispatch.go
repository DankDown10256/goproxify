// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	corelog "github.com/vincamok/goproxify/internal/core/logger"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	"github.com/vincamok/goproxify/internal/core/geoip"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/proxy"
	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/core/threat"
)

type cachedDispatch struct {
	gen uint64
	h   http.Handler
}

// --- Mux HTTP ------------------------------------------------------------

func (s *Server) httpMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dispatch)
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

// serveDefaultError écrit la page d'erreur par défaut Goproxify (sans contexte de route).
func serveDefaultError(w http.ResponseWriter, r *http.Request, status int) {
	html := errorpages.Render(status, r.Host, r.Header.Get("X-Request-ID"), r.Header.Get("Accept-Language"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(html)) //nolint:errcheck
}

// serveErrorPageAsset sert /_goproxify/error-pages/{id}/{filename} depuis le volume Core.
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

	// Vérification globale des profils IP (deny lists) avant le routage.
	// Utilise CF-Connecting-IP / X-Forwarded-For si disponible (Cloudflare, reverse proxy).
	remoteIP := corelog.RealIP(r)
	if blocked, reason := s.profileStore.CheckBlocked(remoteIP); blocked {
		s.log.Warn("ip bloquée par profil", "ip", remoteIP, "profile", reason)
		serveDefaultError(w, r, http.StatusForbidden)
		return
	}
	// Bans Fail2Ban / CrowdSec / natifs — les profils allow (et IPs privées) passent outre.
	if !s.profileStore.IsAllowed(remoteIP) {
		if blocked, reason := s.banStore.CheckBlocked(remoteIP); blocked {
			s.log.Warn("ip bloquée par ban", "ip", remoteIP, "reason", reason)
			serveDefaultError(w, r, http.StatusForbidden)
			return
		}
	}

	// Moteur de détection automatique (threat engine) — après les bans explicites.
	if s.threatEngine != nil {
		if blocked, reason := s.threatEngine.Check(r, remoteIP); reason != "" {
			r = threat.WithSignal(r, reason)
			if blocked {
				s.log.Warn("ip bloquée par moteur de détection", "ip", remoteIP, "reason", reason)
				serveDefaultError(w, r, http.StatusForbidden)
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

	locPath := ""
	if loc := router.MatchLocation(route, r.URL.Path); loc != nil {
		locPath = loc.Path
		route = router.MergeLocation(route, loc)
	}

	h := s.handlerForRoute(route, locPath)

	// Métriques
	start := time.Now()
	rw := &statusCapture{ResponseWriter: w}
	h.ServeHTTP(rw, r)
	metrics.Core.RequestsTotal.WithLabelValues(host, r.Method, fmt.Sprintf("%d", rw.status)).Inc()
	metrics.Core.RequestDuration.WithLabelValues(host).Observe(time.Since(start).Seconds())

	if s.threatEngine != nil {
		s.threatEngine.RecordStatus(remoteIP, rw.status)
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

func (s *Server) handlerForRoute(route *router.Route, locPath string) http.Handler {
	gen := s.dispatchGen.Load()
	key := route.ID + "\x00" + locPath
	if v, ok := s.dispatchHandlers.Load(key); ok {
		if c := v.(*cachedDispatch); c.gen == gen {
			return c.h
		}
	}

	h := http.Handler(proxy.NewHandler(route, s.health, s.metrics, s.peers, s.log.Logger()))
	if route.Cache != nil && route.Cache.Enabled {
		dir := route.Cache.Dir
		if dir == "" {
			dir = route.CachePath
		}
		if dir == "" {
			dir = "/tmp/goproxify-cache/" + route.ID
		}
		h = proxy.New(dir).MiddlewareWithConfig(route.Cache)(h)
	} else if route.CachePath != "" {
		h = proxy.New(route.CachePath).Middleware(h)
	}
	h = middleware.SSOAuth(route.SSO)(h)
	h = middleware.JWTValidation(route.JWT)(h)
	h = middleware.MTLSValidation(route.MTLS)(h)
	h = middleware.CORS(route.CORS)(h)
	h = middleware.SecurityHeaders(route.Headers)(h)
	var geoIPMW func(http.Handler) http.Handler
	if route.GeoIP != nil {
		dbPath := route.GeoIP.DBPath
		if dbPath == "" && s.cfg != nil {
			dbPath = s.cfg.GeoIP.DBPath
		}
		if dbPath == "" {
			dbPath = geoip.DefaultDBPath
		}
		geoIPMW = middleware.GeoIP(dbPath, route.GeoIP.Mode, route.GeoIP.Countries)
	} else {
		geoIPMW = middleware.GeoIP("", "", nil)
	}
	h = geoIPMW(h)
	h = middleware.IPFilter(route.IPFilter)(h)
	h = middleware.RateLimit(route.RateLimit)(h)
	h = middleware.LimitConn(route.LimitConn)(h)
	h = middleware.ResolveRequestVars(route.RequestVars)(h)
	h = middleware.BotProtection(route.Bot)(h)
	if route.WAF != nil && route.WAF.Enabled {
		h = s.wafEngine.Middleware(route.WAF, h)
	}
	if route.RequestID != nil && !*route.RequestID {
		h = stripRequestIDResponse(h)
	}

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
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.status = code
	sc.ResponseWriter.WriteHeader(code)
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

