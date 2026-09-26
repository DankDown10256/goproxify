// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import "testing"

func TestControlEndpointFromRaft(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"http://192.0.2.20:8002", "http://192.0.2.20:8000", true},
		{"http://backup:8002", "http://backup:8000", true},
		{"https://edge-b.example.com:8002", "https://edge-b.example.com:8000", true},
		{"192.0.2.20:8002", "http://192.0.2.20:8000", true},
		{"http://[2001:db8::1]:8002", "http://[2001:db8::1]:8000", true},
		{"", "", false},
		{"   ", "", false},
		{"http://:8002", "", false},
	}
	for _, tc := range cases {
		got, ok := controlEndpointFromRaft(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("controlEndpointFromRaft(%q) = %q, %v ; attendu %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
