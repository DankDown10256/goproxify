// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package labels parse les labels Docker/K8s goproxify.* vers des configs route.
package labels

import (
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// ParseRateLimit interprète "100/s", "100/s:50", "100" ou un float.
func ParseRateLimit(s string) *router.RateLimitConfig {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	burst := 0
	if i := strings.LastIndex(s, ":"); i > 0 {
		// Éviter de couper "http://..." — ici le format est rps[/unit]:burst
		if b, err := strconv.Atoi(strings.TrimSpace(s[i+1:])); err == nil && b >= 0 {
			burst = b
			s = strings.TrimSpace(s[:i])
		}
	}
	s = strings.TrimSuffix(strings.ToLower(s), "/s")
	s = strings.TrimSuffix(s, "/sec")
	s = strings.TrimSpace(s)
	rps, err := strconv.ParseFloat(s, 64)
	if err != nil || rps <= 0 {
		return nil
	}
	return &router.RateLimitConfig{RequestsPerSecond: rps, Burst: burst}
}

// ParseRateLimitParts combine rps + burst optionnels (labels séparés).
func ParseRateLimitParts(rpsLabel, burstLabel string) *router.RateLimitConfig {
	if strings.TrimSpace(rpsLabel) == "" {
		return nil
	}
	cfg := ParseRateLimit(rpsLabel)
	if cfg == nil {
		return nil
	}
	if b, err := strconv.Atoi(strings.TrimSpace(burstLabel)); err == nil && b > 0 {
		cfg.Burst = b
	}
	return cfg
}

// ParseIPFilter interprète "allow:10.0.0.0/8,192.168.0.0/16" ou "deny:1.2.3.4/32".
// Si plusieurs modes apparaissent (legacy allow:…,deny:…), le premier mode gagne
// et seuls ses CIDR sont retenus.
func ParseIPFilter(s string) *router.IPFilterConfig {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	mode := ""
	var cidrs []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, ':'); i > 0 {
			prefix := strings.ToLower(strings.TrimSpace(part[:i]))
			rest := strings.TrimSpace(part[i+1:])
			if prefix == "allow" || prefix == "deny" {
				if mode == "" {
					mode = prefix
				}
				if mode == prefix && rest != "" {
					cidrs = append(cidrs, rest)
				}
				continue
			}
		}
		// CIDR nu : mode allow par défaut
		if mode == "" {
			mode = "allow"
		}
		cidrs = append(cidrs, part)
	}
	if mode == "" || len(cidrs) == 0 {
		return nil
	}
	return &router.IPFilterConfig{Mode: mode, CIDRs: cidrs}
}

// ParseCORS interprète une liste d'origins séparées par des virgules.
// "true" / "*" seuls ne sont plus acceptés (trop permissifs) — liste explicite requise.
func ParseCORS(s string) *router.CORSConfig {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "true") || s == "*" {
		return nil
	}
	origins := splitCSV(s)
	filtered := make([]string, 0, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "" || o == "*" {
			continue
		}
		filtered = append(filtered, o)
	}
	if len(filtered) == 0 {
		return nil
	}
	return &router.CORSConfig{
		AllowedOrigins: filtered,
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		MaxAge:         86400,
	}
}

// ParseGeoIP interprète "allow:FR,DE" ou "deny:CN,RU".
func ParseGeoIP(s string) *router.GeoIPConfig {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	mode := "allow"
	rest := s
	if i := strings.IndexByte(s, ':'); i > 0 {
		prefix := strings.ToLower(strings.TrimSpace(s[:i]))
		if prefix == "allow" || prefix == "deny" {
			mode = prefix
			rest = strings.TrimSpace(s[i+1:])
		}
	}
	countries := splitCSV(rest)
	if len(countries) == 0 {
		return nil
	}
	for i, c := range countries {
		countries[i] = strings.ToUpper(c)
	}
	return &router.GeoIPConfig{Mode: mode, Countries: countries}
}

// ParseCSVIDs découpe une liste d'identifiants (snippets, etc.).
func ParseCSVIDs(s string) []string {
	return splitCSV(s)
}

// ParseWAF interprète "true"|"block"|"detect".
func ParseWAF(s string) *router.WAFConfig {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "block", "1", "on":
		return &router.WAFConfig{Enabled: true, Mode: "block"}
	case "detect":
		return &router.WAFConfig{Enabled: true, Mode: "detect"}
	default:
		return nil
	}
}

// ParseWAFExtended enrichit une WAFConfig existante avec les labels avancés.
// cfg doit être non-nil (retour de ParseWAF).
func ParseWAFExtended(cfg *router.WAFConfig, anomalyThreshold, maxBodyMB, behaviorWindow, behaviorThreshold int, excludeIDs, trustedProxies string, behaviorEnabled bool) {
	if cfg == nil {
		return
	}
	if anomalyThreshold > 0 {
		cfg.AnomalyThreshold = anomalyThreshold
	}
	if maxBodyMB > 0 {
		cfg.MaxBodyMB = maxBodyMB
	}
	if ids := ParseCSVInts(excludeIDs); len(ids) > 0 {
		cfg.ExcludeIDs = ids
	}
	if behaviorEnabled {
		cfg.BehaviorEnabled = true
		if behaviorWindow > 0 {
			cfg.BehaviorWindowSec = behaviorWindow
		}
		if behaviorThreshold > 0 {
			cfg.BehaviorThreshold = behaviorThreshold
		}
	}
	if cidrs := splitCSV(trustedProxies); len(cidrs) > 0 {
		cfg.TrustedProxies = cidrs
	}
}

// ParseCSVInts découpe une liste d'entiers séparés par des virgules.
func ParseCSVInts(s string) []int {
	var out []int
	for _, p := range splitCSV(s) {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ParseBot interprète "true" pour activer la protection bot de base.
func ParseBot(s string) *router.BotConfig {
	if strings.EqualFold(strings.TrimSpace(s), "true") || strings.TrimSpace(s) == "1" {
		return &router.BotConfig{Enabled: true}
	}
	return nil
}

// ParseBotMode applique un mode sur une BotConfig existante.
func ParseBotMode(cfg *router.BotConfig, mode string) {
	if cfg == nil {
		return
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "block", "monitor", "log", "challenge":
		cfg.Mode = mode
	}
}

// ParseRetry interprète "3" ou "3:500ms" → RetryConfig.
func ParseRetry(s string) *router.RetryConfig {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.SplitN(s, ":", 2)
	attempts, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || attempts <= 0 {
		return nil
	}
	cfg := &router.RetryConfig{Attempts: attempts}
	if len(parts) == 2 {
		if d, err := time.ParseDuration(strings.TrimSpace(parts[1])); err == nil {
			cfg.InitialWait = d
		}
	}
	return cfg
}

// ParseCircuitBreaker interprète "5:30s" → CBConfig.
func ParseCircuitBreaker(s string) *router.CBConfig {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.SplitN(s, ":", 2)
	threshold, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || threshold <= 0 {
		return nil
	}
	cfg := &router.CBConfig{Threshold: threshold}
	if len(parts) == 2 {
		if d, err := time.ParseDuration(strings.TrimSpace(parts[1])); err == nil {
			cfg.Timeout = d
		}
	}
	return cfg
}

// ParseCache interprète "true" ou un TTL (ex: "60s", "10m") → CacheConfig.
func ParseCache(s string) *router.CacheConfig {
	s = strings.TrimSpace(s)
	if s == "" || s == "false" {
		return nil
	}
	cfg := &router.CacheConfig{Enabled: true}
	if s != "true" {
		cfg.ValidRules = []router.CacheValidRule{{TTL: s}}
	}
	return cfg
}

// ParseSize convertit un suffixe humain (10m, 1g) en octets int64.
// Valeurs sans suffixe traitées comme des octets.
func ParseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	multipliers := map[byte]int64{'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}
	if len(s) > 1 {
		if m, ok := multipliers[s[len(s)-1]]; ok {
			n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
			if err == nil {
				return n * m
			}
		}
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// ParseHeaderList interprète "X-Foo:bar,X-Baz:qux" → map[string]string.
func ParseHeaderList(s string) map[string]string {
	out := map[string]string{}
	for _, part := range splitCSV(s) {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseHeaderRemoveList interprète "X-Powered-By,Server" → []string.
func ParseHeaderRemoveList(s string) []string {
	return splitCSV(s)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseBackpressure interprète "200", "200:100" ou "200:100:2s" (max_inflight[:file[:attente max]]) → BackpressureConfig.
func ParseBackpressure(s string) *router.BackpressureConfig {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.SplitN(s, ":", 3)
	inflight, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || inflight <= 0 {
		return nil
	}
	cfg := &router.BackpressureConfig{MaxInflight: inflight}
	if len(parts) >= 2 {
		if q, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && q > 0 {
			cfg.Queue = q
		}
	}
	if len(parts) == 3 {
		if d, err := time.ParseDuration(strings.TrimSpace(parts[2])); err == nil && d > 0 {
			cfg.QueueTimeoutMs = int(d.Milliseconds())
		}
	}
	return cfg
}

// ParseSlowStart interprète "30" (secondes) ou une durée ("30s", "2m") → secondes ; 0 si invalide.
func ParseSlowStart(s string) int {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return max(n, 0)
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return int(d.Seconds())
	}
	return 0
}

// ParseJWT construit la validation JWT depuis l URL JWKS du fournisseur (https://.../jwks.json),
// avec issuer et audience optionnels. Le middleware ne sait valider que par JWKS : tout autre
// valeur (secret inline, "true") donne nil.
func ParseJWT(jwksURL, issuer, audience string) *router.JWTConfig {
	jwksURL = strings.TrimSpace(jwksURL)
	if !strings.HasPrefix(jwksURL, "https://") && !strings.HasPrefix(jwksURL, "http://") {
		return nil
	}
	return &router.JWTConfig{
		Enabled:  true,
		JWKSURL:  jwksURL,
		Issuer:   strings.TrimSpace(issuer),
		Audience: strings.TrimSpace(audience),
	}
}

// ParseMTLS construit la validation mTLS depuis le chemin du fichier CA (PEM) lisible par le Core.
// Les certificats clients sont exigés. "true" / "false" ou une valeur vide donnent nil.
func ParseMTLS(caFile string) *router.MTLSConfig {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" || strings.EqualFold(caFile, "true") || strings.EqualFold(caFile, "false") {
		return nil
	}
	return &router.MTLSConfig{Enabled: true, CACertFile: caFile, RequireClientCert: true}
}
