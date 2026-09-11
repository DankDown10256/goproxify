// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/vincamok/goproxify/internal/core/router"
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
)

// Engine est le moteur WAF.
type Engine struct {
	mu      sync.RWMutex
	rules   []Rule   // règles par défaut + custom compilées
	exclude map[int]bool
	log     *slog.Logger
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

func (e *Engine) reload(cfg *router.WAFConfig) {
	exclude := make(map[int]bool)
	rules := DefaultRules()
	if cfg != nil {
		for _, id := range cfg.ExcludeIDs {
			exclude[id] = true
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
	if cfg != nil {
		anomalyThreshold = cfg.AnomalyThreshold
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		wafRequestsTotal.WithLabelValues(host).Inc()

		matches := e.Inspect(r, maxBody, excludeIDs...)
		if len(matches) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Décision : scoring anomalie ou premier match
		triggered := false
		if anomalyThreshold > 0 {
			total := 0
			for _, m := range matches {
				total += m.AnomalyScore
			}
			triggered = total >= anomalyThreshold
		} else {
			triggered = true
		}

		// Injecter les matches dans le contexte pour l'access log
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
				"ip", r.RemoteAddr,
				"uri", r.URL.RequestURI(),
				"block", triggered && block,
			)
		}

		if triggered && block {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		// Mode detect ou score insuffisant : ajoute un header de diagnostic
		top := matches[0]
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

// readBody lit le corps et retourne (raw string, valeurs extraites de JSON/form).
// Les valeurs extraites sont ajoutées aux TargetArgs pour inspecter le contenu décodé.
func readBody(r *http.Request, maxMB int) (raw string, extracted []string) {
	if r.Body == nil || r.ContentLength == 0 {
		return "", nil
	}
	limit := int64(maxMB) * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil || len(data) == 0 {
		return "", nil
	}
	r.Body = io.NopCloser(strings.NewReader(string(data)))
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
			r.Body = io.NopCloser(strings.NewReader(raw))
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
	}
	return "unknown"
}
