// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package labels parse les labels Docker/K8s goproxify.* vers des configs route.
package labels

import (
	"strconv"
	"strings"

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

// ParseIPFilter interprète "allow:10.0.0.0/8,203.0.113.10/16" ou "deny:1.2.3.4/32".
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

// ParseBot interprète "true" pour activer la protection bot de base.
func ParseBot(s string) *router.BotConfig {
	if strings.EqualFold(strings.TrimSpace(s), "true") || strings.TrimSpace(s) == "1" {
		return &router.BotConfig{Enabled: true}
	}
	return nil
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
