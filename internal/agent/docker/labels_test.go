// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import "testing"

func TestParseLabelsMultiCanaryRole(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable:       "true",
		LabelHost:         "app.example.fr",
		LabelCanary:       "true",
		LabelCanaryWeight: "25",
	}, nil, "10.0.0.5")
	if len(specs) != 1 {
		t.Fatalf("len = %d", len(specs))
	}
	if specs[0].Role != RoleCanary {
		t.Fatalf("Role = %q, want canary", specs[0].Role)
	}
	if specs[0].CanaryWeight != 25 {
		t.Fatalf("CanaryWeight = %d, want 25", specs[0].CanaryWeight)
	}
}

func TestParseLabelsMultiCanaryDefaultWeight(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
		LabelCanary: "true",
	}, nil, "10.0.0.5")
	if specs[0].CanaryWeight != 10 {
		t.Fatalf("CanaryWeight = %d, want 10", specs[0].CanaryWeight)
	}
}

func TestParseLabelsMultiShadowRole(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
		LabelShadow: "true",
	}, nil, "10.0.0.5")
	if specs[0].Role != RoleShadow {
		t.Fatalf("Role = %q, want shadow", specs[0].Role)
	}
}

func TestParseLabelsMultiCanaryWinsOverShadow(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
		LabelCanary: "true",
		LabelShadow: "true",
	}, nil, "10.0.0.5")
	if specs[0].Role != RoleCanary {
		t.Fatalf("Role = %q, want canary (priority)", specs[0].Role)
	}
}

func TestParseLabelsMultiNormalRole(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
	}, nil, "10.0.0.5")
	if specs[0].Role != RoleNormal {
		t.Fatalf("Role = %q, want normal", specs[0].Role)
	}
}

func TestParseLabelsMultiSecurityFields(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable:       "true",
		LabelHost:         "app.example.fr",
		LabelRateLimitRPS: "80",
		LabelRateLimitBurst: "40",
		LabelIPFilter:     "allow:10.0.0.0/8",
		LabelSnippets:     "waf-default, headers-secure",
		LabelAuthProvider: "oidc-1",
		LabelWAF:          "detect",
		LabelBot:          "true",
	}, nil, "10.0.0.5")
	if len(specs) != 1 {
		t.Fatalf("len = %d", len(specs))
	}
	s := specs[0]
	if s.RateLimit != "80/s:40" {
		t.Fatalf("RateLimit = %q", s.RateLimit)
	}
	if s.IPFilter != "allow:10.0.0.0/8" {
		t.Fatalf("IPFilter = %q", s.IPFilter)
	}
	if s.SnippetIDs != "waf-default, headers-secure" || s.AuthProviderID != "oidc-1" {
		t.Fatalf("snippets/auth = %q / %q", s.SnippetIDs, s.AuthProviderID)
	}
	if s.WAF != "detect" || s.Bot != "true" {
		t.Fatalf("waf/bot = %q / %q", s.WAF, s.Bot)
	}
}

func TestParseLabelsMultiCanaryWeightClamp(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable:       "true",
		LabelHost:         "app.example.fr",
		LabelCanary:       "true",
		LabelCanaryWeight: "150",
	}, nil, "10.0.0.5")
	if specs[0].CanaryWeight != 100 {
		t.Fatalf("CanaryWeight = %d, want 100", specs[0].CanaryWeight)
	}
}
