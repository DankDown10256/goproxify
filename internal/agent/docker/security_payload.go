// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"log/slog"
	"strings"

	"github.com/vincamok/goproxify/internal/labels"
)

// AttachSecurityPayload ajoute les champs de sécurité et de comportement au payload Agent→Core.
func AttachSecurityPayload(payload map[string]any, spec *ProxySpec) {
	if spec == nil {
		return
	}

	// Sécurité réseau
	if rl := labels.ParseRateLimit(spec.RateLimit); rl != nil {
		payload["rate_limit"] = rl
	}
	if ipf := labels.ParseIPFilter(spec.IPFilter); ipf != nil {
		payload["ip_filter"] = ipf
	}
	if cors := labels.ParseCORS(spec.CORS); cors != nil {
		payload["cors"] = cors
	}
	if geo := labels.ParseGeoIP(spec.GeoIP); geo != nil {
		payload["geo_ip"] = geo
	}
	if waf := labels.ParseWAF(spec.WAF); waf != nil {
		labels.ParseWAFExtended(waf, spec.WAFAnomalyThreshold, spec.WAFMaxBodyMB,
			spec.WAFBehaviorWindow, spec.WAFBehaviorThreshold,
			spec.WAFExcludeIDs, spec.WAFTrustedProxies, spec.WAFBehavior)
		payload["waf"] = waf
	}
	if bot := labels.ParseBot(spec.Bot); bot != nil {
		labels.ParseBotMode(bot, spec.BotMode)
		payload["bot"] = bot
	}
	if spec.LimitConn > 0 {
		payload["limit_conn"] = map[string]any{"max_per_ip": spec.LimitConn}
	}
	if bp := labels.ParseBackpressure(spec.Backpressure); bp != nil {
		payload["backpressure"] = bp
	}

	// Authentification
	if ids := labels.ParseCSVIDs(spec.SnippetIDs); len(ids) > 0 {
		payload["snippet_ids"] = ids
	}
	if id := strings.TrimSpace(spec.AuthProviderID); id != "" {
		payload["auth_provider_id"] = id
	}
	if v := strings.TrimSpace(spec.JWT); v != "" {
		if jc := labels.ParseJWT(v, spec.JWTIssuer, spec.JWTAudience); jc != nil {
			payload["jwt"] = jc
		} else {
			slog.Warn("label goproxify.jwt ignoré : une URL JWKS (https://…) est attendue, la route n'est PAS protégée", "host", spec.Host)
		}
	}
	if v := strings.TrimSpace(spec.MTLS); v != "" {
		if mc := labels.ParseMTLS(v); mc != nil {
			payload["mtls"] = mc
		} else {
			slog.Warn("label goproxify.mtls ignoré : le chemin d'un fichier CA est attendu, la route n'est PAS protégée", "host", spec.Host)
		}
	}

	// Comportement HTTP
	if spec.PreserveHost {
		t := true
		payload["preserve_host"] = &t
	}
	if spec.Websocket {
		t := true
		payload["websocket"] = &t
	}
	if spec.RequestID {
		t := true
		payload["request_id"] = &t
	}
	if v := strings.TrimSpace(spec.HTTPVersion); v != "" {
		payload["http_version"] = v
	}

	// Réécriture d'URL
	if v := strings.TrimSpace(spec.StripPrefix); v != "" {
		payload["strip_prefix"] = v
	}
	if v := strings.TrimSpace(spec.PathRewrite); v != "" {
		payload["path_rewrite"] = v
	}

	// Timeouts & limites
	if v := strings.TrimSpace(spec.ConnectTimeout); v != "" {
		payload["connect_timeout"] = v
	}
	if v := strings.TrimSpace(spec.ResponseTimeout); v != "" {
		payload["response_timeout"] = v
	}
	if v := strings.TrimSpace(spec.SendTimeout); v != "" {
		payload["send_timeout"] = v
	}
	if v := strings.TrimSpace(spec.MaxBodySize); v != "" {
		payload["max_body_size"] = labels.ParseSize(v)
	}

	// Load balancing & résilience
	if v := strings.TrimSpace(spec.LB); v != "" {
		payload["lb"] = v
	}
	if v := strings.TrimSpace(spec.StickyCookie); v != "" {
		payload["sticky_cookie"] = v
	}
	if n := labels.ParseSlowStart(spec.SlowStart); n > 0 {
		payload["slow_start_sec"] = n
	}
	if v := strings.TrimSpace(spec.Retry); v != "" {
		payload["retry"] = labels.ParseRetry(v)
	}
	if v := strings.TrimSpace(spec.CircuitBreaker); v != "" {
		payload["circuit_breaker"] = labels.ParseCircuitBreaker(v)
	}

	// En-têtes
	if v := strings.TrimSpace(spec.AddHeaders); v != "" {
		payload["headers_add"] = labels.ParseHeaderList(v)
	}
	if v := strings.TrimSpace(spec.RemoveHeaders); v != "" {
		payload["headers_remove"] = labels.ParseHeaderRemoveList(v)
	}

	// Sentinel whitelist
	if cidrs := labels.ParseCSVIDs(spec.SentinelWhitelist); len(cidrs) > 0 {
		payload["sentinel_whitelist"] = cidrs
	}

	// Cache
	if v := strings.TrimSpace(spec.Cache); v != "" {
		payload["cache"] = labels.ParseCache(v)
	}

	// Logs
	if spec.LogForwarding || spec.LogFormat != "" || spec.LogLevel != "" {
		logging := map[string]any{"access_log": true}
		if spec.LogFormat != "" {
			logging["format"] = spec.LogFormat
		}
		if spec.LogLevel != "" {
			logging["level"] = spec.LogLevel
		}
		payload["logging"] = logging
	}
}
