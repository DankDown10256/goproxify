// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import "testing"

func TestMatchesFilterKindAccessSystem(t *testing.T) {
	access := Entry{Status: 200, Component: "core", NodeName: "core-1", Level: "info", Domain: "a.example", Method: "GET", Path: "/"}
	sysCore := Entry{Status: 0, Component: "core", NodeName: "core-1", Level: "info", Message: "started"}
	sysAdmin := Entry{Status: 0, Component: "admin", NodeName: "admin", Level: "warn", Message: "reload"}
	sysAgent := Entry{Status: 0, Component: "agent", NodeName: "agent-1", Level: "info", Message: "line"}

	cases := []struct {
		name string
		e    Entry
		p    SearchParams
		want bool
	}{
		{"access accepts http", access, SearchParams{Kind: "access"}, true},
		{"access rejects system", sysCore, SearchParams{Kind: "access"}, false},
		{"system accepts core", sysCore, SearchParams{Kind: "system"}, true},
		{"system accepts admin", sysAdmin, SearchParams{Kind: "system"}, true},
		{"system accepts agent", sysAgent, SearchParams{Kind: "system"}, true},
		{"system rejects access", access, SearchParams{Kind: "system"}, false},
		{"core access scoped", access, SearchParams{Kind: "access", Component: "core", NodeName: "core-1"}, true},
		{"core access wrong node", access, SearchParams{Kind: "access", Component: "core", NodeName: "other"}, false},
		{"admin system all comps", sysAgent, SearchParams{Kind: "system"}, true},
		{"admin system filter admin", sysAdmin, SearchParams{Kind: "system", Component: "admin"}, true},
		{"admin system filter admin rejects agent", sysAgent, SearchParams{Kind: "system", Component: "admin"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesFilter(tc.e, tc.p); got != tc.want {
				t.Fatalf("matchesFilter=%v want %v", got, tc.want)
			}
		})
	}
}
