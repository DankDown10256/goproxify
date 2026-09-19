// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/adminmetrics"
	"github.com/vincamok/goproxify/internal/admin/corews"
	"github.com/vincamok/goproxify/internal/admin/logs"
	corelog "github.com/vincamok/goproxify/internal/core/logger"
)

// --- Middleware & helpers -------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += int64(n)
	return n, err
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		elapsed := time.Since(start).Seconds()
		statusStr := fmt.Sprintf("%d", sw.status)
		adminmetrics.AdminHTTP.RequestsTotal.WithLabelValues(r.Method, statusStr).Inc()
		adminmetrics.AdminHTTP.Duration.WithLabelValues(r.Method).Observe(elapsed)

		if strings.HasPrefix(r.URL.Path, "/api/v1/health") ||
			strings.HasPrefix(r.URL.Path, "/api/v1/logs/live") ||
			strings.HasPrefix(r.URL.Path, "/internal/v1/") {
			return
		}
		latency := time.Since(start).Milliseconds()
		level := "info"
		if sw.status >= 500 {
			level = "error"
		} else if sw.status >= 400 {
			level = "warn"
		}
		ip := corelog.RealIP(r)
		s.logStore.Write(logs.Entry{
			Level:     level,
			Component: "admin",
			Domain:    r.Host,
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    sw.status,
			IP:        ip,
			LatencyMs: latency,
			Bytes:     sw.bytes,
			Referrer:  r.Header.Get("Referer"),
		})
	})
}

// runtimeSettings construit les settings runtime poussés aux Cores.
func (s *Server) runtimeSettings() corews.Settings {
	return corews.Settings{
		TracingEndpoint: s.cfg.App.TracingEndpoint,
		LogLevel:        s.cfg.CoreDefaults.LogLevel,
		LogFormat:       s.cfg.CoreDefaults.LogFormat,
		AccessLogPath:   s.cfg.CoreDefaults.AccessLogPath,
		AdminPublicURL:  s.resolveAdminPublicURL(),
	}
}

// resolveAdminPublicURL retourne l'origine publique de l'Admin (env > settings > webauthn).
func (s *Server) resolveAdminPublicURL() string {
	if u := strings.TrimRight(strings.TrimSpace(os.Getenv("GPX_ADMIN_PUBLIC_URL")), "/"); u != "" {
		return u
	}
	if u := strings.TrimRight(admindb.GetSetting(s.db, "admin.public_url", ""), "/"); u != "" {
		return u
	}
	return strings.TrimRight(admindb.GetSetting(s.db, "mfa.webauthn.origin", ""), "/")
}

// publicOriginFromRequest déduit http(s)://host depuis la requête navigateur.
func publicOriginFromRequest(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	origin := proto + "://" + host
	if _, err := url.ParseRequestURI(origin); err != nil {
		return ""
	}
	return strings.TrimRight(origin, "/")
}

// maybeRememberPublicURL mémorise l'origine vue par le navigateur et la pousse aux Cores.
// Ignoré si GPX_ADMIN_PUBLIC_URL est défini (override explicite).
func (s *Server) maybeRememberPublicURL(r *http.Request) {
	if os.Getenv("GPX_ADMIN_PUBLIC_URL") != "" {
		return
	}
	origin := publicOriginFromRequest(r)
	if origin == "" {
		return
	}
	cur := strings.TrimRight(admindb.GetSetting(s.db, "admin.public_url", ""), "/")
	if cur == origin {
		return
	}
	if err := admindb.SetSetting(s.db, "admin.public_url", origin); err != nil {
		s.log.Debug("admin.public_url: persistance échouée", "err", err)
		return
	}
	s.log.Info("admin.public_url mémorisée depuis la session UI", "url", origin)
	if s.wsManager != nil {
		settings := s.runtimeSettings()
		s.wsManager.PushSettings(context.Background(), settings)
	}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type notFoundError struct{ email string }

func (e *notFoundError) Error() string { return "utilisateur introuvable : " + e.email }
