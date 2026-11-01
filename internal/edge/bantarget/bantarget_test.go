// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package bantarget

import "testing"

func TestBanTarget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ip        string
		whitelist []string
		want      string
		ok        bool
	}{
		{"IPv4", "203.0.113.7", nil, "203.0.113.7", true},
		{"IPv4 avec port", "203.0.113.7:4000", nil, "203.0.113.7", true},
		{"IPv6 ramenée à son /64", "2a01:e0a:1:2::5", nil, "2a01:e0a:1:2::/64", true},
		{"IPv6 avec port", "[2a01:e0a:1:2::5]:443", nil, "2a01:e0a:1:2::/64", true},
		{"deux adresses d'un même /64", "2a01:e0a:1:2:abcd::7", nil, "2a01:e0a:1:2::/64", true},
		{"IPv6 dont le /64 recoupe la liste blanche : l'adresse seule", "2a01:e0a:1:4::6", []string{"2a01:e0a:1:4::5"}, "2a01:e0a:1:4::6", true},
		{"IPv6 exemptée", "2a01:e0a:1:4::5", []string{"2a01:e0a:1:4::5"}, "", false},
		{"IPv6 couverte par un CIDR exempté", "[2a01:e0a:1:7::9]:443", []string{"2a01:e0a:1::/48"}, "", false},
		{"IPv4 exemptée", "203.0.113.7", []string{"203.0.113.0/24"}, "", false},
		{"réseau privé", "10.0.0.5", nil, "", false},
		{"IPv6 privée", "fd00::5", nil, "", false},
		{"boucle locale", "[::1]:8080", nil, "", false},
		{"Cloudflare", "2606:4700::1", nil, "", false},
		{"IPv4 Cloudflare", "104.16.0.1", nil, "", false},
		{"pseudonymisée", "[pseudonymisé]", nil, "", false},
		{"vide", "", nil, "", false},
	} {
		got, ok := BanTarget(tc.ip, tc.whitelist)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s : BanTarget(%q) = %q, %v ; attendu %q, %v", tc.name, tc.ip, got, ok, tc.want, tc.ok)
		}
	}
}
