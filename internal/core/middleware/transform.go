// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Transform applique le pipeline de transformation de requête/réponse défini
// dans RequestTransform : ajout/suppression de headers, réécriture de préfixe d'URL.
func Transform(cfg *router.RequestTransform) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Réécriture de préfixe d'URL avant transmission au backend.
			if cfg.RewriteFrom != "" && strings.HasPrefix(r.URL.Path, cfg.RewriteFrom) {
				r = r.Clone(r.Context())
				r.URL.Path = cfg.RewriteTo + r.URL.Path[len(cfg.RewriteFrom):]
				if r.URL.RawPath != "" && strings.HasPrefix(r.URL.RawPath, cfg.RewriteFrom) {
					r.URL.RawPath = cfg.RewriteTo + r.URL.RawPath[len(cfg.RewriteFrom):]
				}
			}
			// Headers de requête.
			for _, h := range cfg.RemoveRequestHeaders {
				r.Header.Del(h)
			}
			for k, v := range cfg.AddRequestHeaders {
				r.Header.Set(k, v)
			}
			// Headers de réponse (via ResponseWriter wrappé).
			if len(cfg.AddResponseHeaders) > 0 || len(cfg.RemoveResponseHeaders) > 0 {
				w = &transformWriter{ResponseWriter: w, add: cfg.AddResponseHeaders, remove: cfg.RemoveResponseHeaders}
			}
			next.ServeHTTP(w, r)
		})
	}
}

type transformWriter struct {
	http.ResponseWriter
	add        map[string]string
	remove     []string
	headerSent bool
}

func (tw *transformWriter) WriteHeader(code int) {
	if !tw.headerSent {
		tw.headerSent = true
		for _, h := range tw.remove {
			tw.ResponseWriter.Header().Del(h)
		}
		for k, v := range tw.add {
			tw.ResponseWriter.Header().Set(k, v)
		}
	}
	tw.ResponseWriter.WriteHeader(code)
}

func (tw *transformWriter) Write(b []byte) (int, error) {
	if !tw.headerSent {
		tw.WriteHeader(http.StatusOK)
	}
	return tw.ResponseWriter.Write(b)
}
