// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"strings"

	"github.com/vincamok/goproxify/internal/labels"
)

// AttachSecurityPayload ajoute les champs de sécurité parsés au payload Agent→Core.
func AttachSecurityPayload(payload map[string]any, spec *ProxySpec) {
	if spec == nil {
		return
	}
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
	if ids := labels.ParseCSVIDs(spec.SnippetIDs); len(ids) > 0 {
		payload["snippet_ids"] = ids
	}
	if id := strings.TrimSpace(spec.AuthProviderID); id != "" {
		payload["auth_provider_id"] = id
	}
	if waf := labels.ParseWAF(spec.WAF); waf != nil {
		payload["waf"] = waf
	}
	if bot := labels.ParseBot(spec.Bot); bot != nil {
		payload["bot"] = bot
	}
}
