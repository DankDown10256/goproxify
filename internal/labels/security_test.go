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
	got := ParseIPFilter("allow:10.0.0.0/8,192.168.0.0/16")
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

func TestParseWAFExtended(t *testing.T) {
	w := ParseWAF("block")
	ParseWAFExtended(w, 10, 5, 60, 8, "942100,941100", "10.0.0.0/8,172.16.0.0/12", true)
	if w.AnomalyThreshold != 10 {
		t.Fatalf("AnomalyThreshold = %d", w.AnomalyThreshold)
	}
	if w.MaxBodyMB != 5 {
		t.Fatalf("MaxBodyMB = %d", w.MaxBodyMB)
	}
	if len(w.ExcludeIDs) != 2 || w.ExcludeIDs[0] != 942100 || w.ExcludeIDs[1] != 941100 {
		t.Fatalf("ExcludeIDs = %v", w.ExcludeIDs)
	}
	if !w.BehaviorEnabled || w.BehaviorWindowSec != 60 || w.BehaviorThreshold != 8 {
		t.Fatalf("behavior = %v/%d/%d", w.BehaviorEnabled, w.BehaviorWindowSec, w.BehaviorThreshold)
	}
	if len(w.TrustedProxies) != 2 {
		t.Fatalf("TrustedProxies = %v", w.TrustedProxies)
	}
}

func TestParseCSVInts(t *testing.T) {
	got := ParseCSVInts("942100, 941100, abc, 933100")
	if len(got) != 3 || got[0] != 942100 || got[2] != 933100 {
		t.Fatalf("ParseCSVInts = %v", got)
	}
	if ParseCSVInts("") != nil {
		t.Fatal("empty should return nil")
	}
}

func TestParseBotMode(t *testing.T) {
	b := ParseBot("true")
	ParseBotMode(b, "monitor")
	if b.Mode != "monitor" {
		t.Fatalf("BotMode = %q", b.Mode)
	}
	ParseBotMode(b, "invalid")
	if b.Mode != "monitor" {
		t.Fatalf("invalid mode should be ignored, got %q", b.Mode)
	}
}

func TestParseBackpressure(t *testing.T) {
	if ParseBackpressure("") != nil || ParseBackpressure("abc") != nil || ParseBackpressure("0") != nil {
		t.Fatal("valeur vide/invalide/nulle : désactivé")
	}
	if c := ParseBackpressure("200"); c == nil || c.MaxInflight != 200 || c.Queue != 0 || c.QueueTimeoutMs != 0 {
		t.Fatalf("%+v", c)
	}
	if c := ParseBackpressure("200:100"); c == nil || c.Queue != 100 {
		t.Fatalf("%+v", c)
	}
	if c := ParseBackpressure(" 200 : 100 : 2s "); c == nil || c.MaxInflight != 200 || c.Queue != 100 || c.QueueTimeoutMs != 2000 {
		t.Fatalf("%+v", c)
	}
}

func TestParseSlowStart(t *testing.T) {
	for in, want := range map[string]int{"30": 30, "30s": 30, "2m": 120, "": 0, "abc": 0, "-5": 0, "0": 0} {
		if got := ParseSlowStart(in); got != want {
			t.Errorf("ParseSlowStart(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseJWT(t *testing.T) {
	for _, bad := range []string{"", "true", "s3cr3t", "ftp://x"} {
		if ParseJWT(bad, "", "") != nil {
			t.Errorf("%q ne doit pas activer la validation", bad)
		}
	}
	c := ParseJWT(" https://idp.example.com/jwks.json ", "https://idp.example.com", "my-api")
	if c == nil || !c.Enabled || c.JWKSURL != "https://idp.example.com/jwks.json" || c.Issuer != "https://idp.example.com" || c.Audience != "my-api" {
		t.Fatalf("%+v", c)
	}
}

func TestParseMTLS(t *testing.T) {
	for _, bad := range []string{"", "true", "FALSE"} {
		if ParseMTLS(bad) != nil {
			t.Errorf("%q ne doit pas activer mTLS", bad)
		}
	}
	c := ParseMTLS("/etc/goproxify/ca.pem")
	if c == nil || !c.Enabled || !c.RequireClientCert || c.CACertFile != "/etc/goproxify/ca.pem" {
		t.Fatalf("%+v", c)
	}
}
