// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"

	"github.com/vincamok/goproxify/internal/core/geoip"
	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/labels"
)

// applyDiscoverySecurity pose sur la route les protections issues des labels Docker.
// Les champs absents du payload ne sont pas effacés (merge multi-backends).
// Les champs présents (y compris listes vides pour snippet_ids) remplacent la valeur.
func applyDiscoverySecurity(rt *router.Route, p *agentContainerPayload, defaultGeoDB string) {
	if rt == nil || p == nil {
		return
	}
	if cfg := decodeRateLimit(p.RateLimit); cfg != nil {
		rt.RateLimit = cfg
	}
	if cfg := decodeIPFilter(p.IPFilter); cfg != nil {
		rt.IPFilter = cfg
	}
	if cfg := decodeCORS(p.CORS); cfg != nil {
		rt.CORS = cfg
	}
	if cfg := decodeGeoIP(p.GeoIP, defaultGeoDB); cfg != nil {
		rt.GeoIP = cfg
	}
	if p.SnippetIDs != nil {
		rt.SnippetIDs = append([]string(nil), p.SnippetIDs...)
	}
	if p.AuthProviderID != "" {
		rt.AuthProviderID = p.AuthProviderID
	}
	if cfg := decodeWAF(p.WAF); cfg != nil {
		rt.WAF = cfg
	}
	if cfg := decodeBot(p.Bot); cfg != nil {
		rt.Bot = cfg
	}
}

func decodeRateLimit(raw json.RawMessage) *router.RateLimitConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.RateLimitConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && cfg.RequestsPerSecond > 0 {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseRateLimit(s)
	}
	return nil
}

func decodeIPFilter(raw json.RawMessage) *router.IPFilterConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.IPFilterConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && len(cfg.CIDRs) > 0 {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseIPFilter(s)
	}
	return nil
}

func decodeCORS(raw json.RawMessage) *router.CORSConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.CORSConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && len(cfg.AllowedOrigins) > 0 {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseCORS(s)
	}
	return nil
}

func decodeGeoIP(raw json.RawMessage, defaultDB string) *router.GeoIPConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.GeoIPConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && (len(cfg.Countries) > 0 || cfg.Mode != "") {
		if cfg.DBPath == "" {
			cfg.DBPath = defaultDB
		}
		if cfg.DBPath == "" {
			cfg.DBPath = geoip.DefaultDBPath
		}
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		g := labels.ParseGeoIP(s)
		if g == nil {
			return nil
		}
		if g.DBPath == "" {
			g.DBPath = defaultDB
		}
		if g.DBPath == "" {
			g.DBPath = geoip.DefaultDBPath
		}
		return g
	}
	return nil
}

func decodeWAF(raw json.RawMessage) *router.WAFConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.WAFConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && cfg.Enabled {
		return &cfg
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseWAF(s)
	}
	return nil
}

func decodeBot(raw json.RawMessage) *router.BotConfig {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var cfg router.BotConfig
	if err := json.Unmarshal(raw, &cfg); err == nil {
		router.NormalizeBotConfig(&cfg)
		if cfg.Enabled {
			return &cfg
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return labels.ParseBot(s)
	}
	return nil
}
