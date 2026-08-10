// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import "testing"

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"8.8.8.8", "8.8.8.8"},
		{"8.8.8.8:443", "8.8.8.8"},
		{" 1.2.3.4 ", "1.2.3.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"", ""},
		{"not-an-ip", ""},
		{"1.2.3", ""},
	}
	for _, c := range cases {
		if got := normalizeIP(c.in); got != c.want {
			t.Errorf("normalizeIP(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestIsPrivate(t *testing.T) {
	priv := []string{"10.0.0.1", "172.17.0.2", "203.0.113.10", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1"}
	for _, ip := range priv {
		if !isPrivate(ip) {
			t.Errorf("isPrivate(%q)=false want true", ip)
		}
	}
	pub := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	for _, ip := range pub {
		if isPrivate(ip) {
			t.Errorf("isPrivate(%q)=true want false", ip)
		}
	}
	if !isPrivate("") || !isPrivate("garbage") {
		t.Error("invalid IPs should be treated as private")
	}
}
