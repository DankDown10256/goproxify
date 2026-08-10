// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package labels

import "testing"

func TestParseRateLimit(t *testing.T) {
	cases := []struct {
		in    string
		rps   float64
		burst int
		nil   bool
	}{
		{"100/s", 100, 0, false},
		{"50/s:20", 50, 20, false},
		{"10", 10, 0, false},
		{"", 0, 0, true},
		{"abc", 0, 0, true},
	}
	for _, tc := range cases {
		got := ParseRateLimit(tc.in)
		if tc.nil {
			if got != nil {
				t.Fatalf("%q: want nil, got %#v", tc.in, got)
			}
			continue
		}
		if got == nil || got.RequestsPerSecond != tc.rps || got.Burst != tc.burst {
			t.Fatalf("%q: got %#v, want rps=%v burst=%d", tc.in, got, tc.rps, tc.burst)
		}
	}
}

func TestParseIPFilter(t *testing.T) {
	got := ParseIPFilter("allow:10.0.0.0/8,203.0.113.10/16")
	if got == nil || got.Mode != "allow" || len(got.CIDRs) != 2 {
		t.Fatalf("got %#v", got)
	}
	got = ParseIPFilter("allow:10.0.0.0/8,deny:0.0.0.0/0")
	if got == nil || got.Mode != "allow" || len(got.CIDRs) != 1 || got.CIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("legacy dual-mode: %#v", got)
	}
	got = ParseIPFilter("deny:1.2.3.4/32")
	if got == nil || got.Mode != "deny" {
		t.Fatalf("deny: %#v", got)
	}
}

func TestParseCORS(t *testing.T) {
	if got := ParseCORS("true"); got != nil {
		t.Fatalf("true ne doit plus activer *: %#v", got)
	}
	if got := ParseCORS("*"); got != nil {
		t.Fatalf("* seul refusé: %#v", got)
	}
	got := ParseCORS("https://a.com,https://b.com")
	if got == nil || len(got.AllowedOrigins) != 2 {
		t.Fatalf("list: %#v", got)
	}
}

func TestParseGeoIP(t *testing.T) {
	got := ParseGeoIP("allow:FR,de")
	if got == nil || got.Mode != "allow" || len(got.Countries) != 2 || got.Countries[1] != "DE" {
		t.Fatalf("%#v", got)
	}
	got = ParseGeoIP("deny:CN")
	if got == nil || got.Mode != "deny" {
		t.Fatalf("%#v", got)
	}
}

func TestParseWAFBot(t *testing.T) {
	if w := ParseWAF("block"); w == nil || !w.Enabled || w.Mode != "block" {
		t.Fatalf("waf block: %#v", w)
	}
	if w := ParseWAF("detect"); w == nil || w.Mode != "detect" {
		t.Fatalf("waf detect: %#v", w)
	}
	if b := ParseBot("true"); b == nil || !b.Enabled {
		t.Fatalf("bot: %#v", b)
	}
}
