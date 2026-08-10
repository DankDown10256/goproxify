// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Match représente une règle déclenchée.
type Match struct {
	RuleID   int
	Category string
	Severity Severity
	Message  string
	Target   string
	Value    string
}

// Engine est le moteur WAF.
type Engine struct {
	rules   []Rule
	exclude map[int]bool
	log     *slog.Logger
}

// NewEngine crée un moteur WAF avec les règles par défaut.
func NewEngine(cfg *router.WAFConfig, log *slog.Logger) *Engine {
	exclude := make(map[int]bool)
	if cfg != nil {
		for _, id := range cfg.ExcludeIDs {
			exclude[id] = true
		}
	}
	return &Engine{
		rules:   DefaultRules(),
		exclude: exclude,
		log:     log,
	}
}

// Inspect analyse une requête et retourne les correspondances.
// excludeIDs additionnels (par route) sont fusionnés avec ceux du moteur.
func (e *Engine) Inspect(r *http.Request, maxBodyMB int, excludeIDs ...int) []Match {
	var matches []Match

	exclude := e.exclude
	if len(excludeIDs) > 0 {
		exclude = make(map[int]bool, len(e.exclude)+len(excludeIDs))
		for id := range e.exclude {
			exclude[id] = true
		}
		for _, id := range excludeIDs {
			exclude[id] = true
		}
	}

	// Préparer les valeurs à inspecter selon les targets
	uri := r.URL.RequestURI()
	args := extractArgs(r)
	headers := extractHeaders(r)
	cookies := extractCookies(r)
	body := readBody(r, maxBodyMB)

	targetValues := map[Target][]string{
		TargetURI:     {uri},
		TargetArgs:    args,
		TargetHeaders: headers,
		TargetCookies: cookies,
		TargetBody:    {body},
	}

	for _, rule := range e.rules {
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
						RuleID:   rule.ID,
						Category: rule.Category,
						Severity: rule.Severity,
						Message:  rule.Message,
						Target:   targetName(target),
						Value:    excerpt,
					})
					goto nextRule // une règle = un match max
				}
			}
		}
	nextRule:
	}
	return matches
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matches := e.Inspect(r, maxBody, excludeIDs...)
		if len(matches) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		top := matches[0]
		e.log.Warn("waf: règle déclenchée",
			"rule_id", top.RuleID,
			"category", top.Category,
			"severity", top.Severity.String(),
			"message", top.Message,
			"target", top.Target,
			"ip", r.RemoteAddr,
			"uri", r.URL.RequestURI(),
			"block", block,
		)

		if block {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		// Mode detect : ajoute un header de diagnostic et laisse passer
		w.Header().Set("X-WAF-Match", top.Category)
		next.ServeHTTP(w, r)
	})
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

func readBody(r *http.Request, maxMB int) string {
	if r.Body == nil || r.ContentLength == 0 {
		return ""
	}
	limit := int64(maxMB) * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return ""
	}
	// Réinjecte le body pour les handlers suivants
	r.Body = io.NopCloser(strings.NewReader(string(data)))
	return string(data)
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
	}
	return "unknown"
}
