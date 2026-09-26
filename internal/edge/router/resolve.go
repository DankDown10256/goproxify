// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"strings"
)

// ResolveSnippets retourne une copie de la route avec les snippets fusionnés.
// La config propre de la route est prioritaire sur les snippets.
// L'ordre des SnippetIDs détermine la priorité entre snippets (le premier gagne).
func ResolveSnippets(route *Route, store *SnippetStore) *Route {
	if len(route.SnippetIDs) == 0 {
		return route
	}
	// Copie superficielle — on ne remplace que les champs nil.
	r := *route
	for _, id := range route.SnippetIDs {
		sn, ok := store.Get(id)
		if !ok {
			continue
		}
		switch sn.Type {
		case SnippetIPFilter:
			if r.IPFilter == nil {
				var cfg IPFilterConfig
				if json.Unmarshal(sn.Config, &cfg) == nil {
					r.IPFilter = &cfg
				}
			}
		case SnippetRateLimit:
			if r.RateLimit == nil {
				var cfg RateLimitConfig
				if json.Unmarshal(sn.Config, &cfg) == nil {
					r.RateLimit = &cfg
				}
			}
		case SnippetCORS:
			if r.CORS == nil {
				var cfg CORSConfig
				if json.Unmarshal(sn.Config, &cfg) == nil {
					r.CORS = &cfg
				}
			}
		case SnippetHeaders:
			{
				var cfg HeadersConfig
				if json.Unmarshal(sn.Config, &cfg) != nil {
					break
				}
				if r.Headers == nil {
					c := cfg
					r.Headers = &c
					break
				}
				// Inline prime : typés déjà définis conservés ; custom = snippet puis override inline
				h := *r.Headers
				if len(cfg.Custom) > 0 {
					merged := make(map[string]string, len(cfg.Custom)+len(h.Custom))
					for k, v := range cfg.Custom {
						merged[k] = v
					}
					for k, v := range h.Custom {
						merged[k] = v
					}
					h.Custom = merged
				}
				if !h.HSTS && cfg.HSTS {
					h.HSTS = true
					if cfg.HSTSMaxAge != 0 {
						h.HSTSMaxAge = cfg.HSTSMaxAge
					}
				}
				if h.XFrameOptions == "" && cfg.XFrameOptions != "" {
					h.XFrameOptions = cfg.XFrameOptions
				}
				if !h.HideServer && cfg.HideServer {
					h.HideServer = true
				}
				r.Headers = &h
			}
		case SnippetGeoIP:
			if r.GeoIP == nil {
				var cfg GeoIPConfig
				if json.Unmarshal(sn.Config, &cfg) == nil {
					// Alias legacy : blocked_countries → countries
					if len(cfg.Countries) == 0 {
						var alt struct {
							Blocked []string `json:"blocked_countries"`
						}
						if json.Unmarshal(sn.Config, &alt) == nil && len(alt.Blocked) > 0 {
							cfg.Countries = alt.Blocked
						}
					}
					r.GeoIP = &cfg
				}
			}
		case SnippetBot:
			if r.Bot == nil {
				var cfg BotConfig
				if json.Unmarshal(sn.Config, &cfg) == nil {
					NormalizeBotConfig(&cfg)
					r.Bot = &cfg
				}
			}
		case SnippetWAF:
			if r.WAF == nil {
				var cfg WAFConfig
				if json.Unmarshal(sn.Config, &cfg) == nil && cfg.Enabled {
					if cfg.Mode == "" {
						cfg.Mode = "block"
					}
					r.WAF = &cfg
				}
			}
		}
	}
	return &r
}

// NormalizeBotConfig aligne mode UI (challenge/monitor/log) sur js_challenge / enabled.
func NormalizeBotConfig(cfg *BotConfig) {
	if cfg == nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "challenge":
		cfg.JSChallenge = true
		if !cfg.Enabled {
			cfg.Enabled = true
		}
	case "monitor", "log", "block":
		if !cfg.Enabled {
			cfg.Enabled = true
		}
	case "off":
		cfg.Enabled = false
	}
}

// ResolveAuthProvider peuple route.SSO depuis l'AuthProviderStore si la route
// référence un fournisseur par ID et n'a pas déjà une config SSO inline.
func ResolveAuthProvider(route *Route, store *AuthProviderStore) *Route {
	if route.AuthProviderID == "" || route.SSO != nil {
		return route
	}
	p, ok := store.Get(route.AuthProviderID)
	if !ok {
		return route
	}
	// Le Config JSON du fournisseur EST directement un SSOConfig sérialisé.
	var sso SSOConfig
	if err := json.Unmarshal(p.Config, &sso); err != nil {
		return route
	}
	// Si le provider Admin ne renseigne pas le champ Provider, on utilise le Type.
	if sso.Provider == "" {
		sso.Provider = p.Type
	}
	r := *route
	r.SSO = &sso
	return &r
}
