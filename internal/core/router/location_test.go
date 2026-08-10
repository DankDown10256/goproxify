// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import "testing"

func TestMatchLocation_Priority(t *testing.T) {
	route := &Route{
		Locations: []Location{
			{Path: "/api", PathType: "prefix", Backends: []Backend{{URL: "http://prefix"}}},
			{Path: "/api/v1", PathType: "prefix", Backends: []Backend{{URL: "http://long"}}},
			{Path: "/api/exact", PathType: "exact", Backends: []Backend{{URL: "http://exact"}}},
			{Path: `^/re/\d+$`, PathType: "regex", Backends: []Backend{{URL: "http://regex"}}},
		},
	}

	cases := []struct {
		path string
		want string
	}{
		{"/api/exact", "http://exact"},
		{"/api/v1/users", "http://long"},
		{"/api/other", "http://prefix"},
		{"/re/42", "http://regex"},
		{"/nope", ""},
	}
	for _, c := range cases {
		loc := MatchLocation(route, c.path)
		got := ""
		if loc != nil && len(loc.Backends) > 0 {
			got = loc.Backends[0].URL
		}
		if got != c.want {
			t.Fatalf("path %q: got %q want %q", c.path, got, c.want)
		}
	}
}

func TestMatchLocation_EmptyPathSkipped(t *testing.T) {
	route := &Route{
		Locations: []Location{
			{Path: "", PathType: "prefix", Backends: []Backend{{URL: "http://bad"}}},
			{Path: "/ok", PathType: "prefix", Backends: []Backend{{URL: "http://ok"}}},
		},
	}
	loc := MatchLocation(route, "/ok/x")
	if loc == nil || loc.Backends[0].URL != "http://ok" {
		t.Fatalf("expected /ok location, got %#v", loc)
	}
	if MatchLocation(route, "/elsewhere") != nil {
		t.Fatal("empty path must not match everything")
	}
}

func TestMergeLocation_Backends(t *testing.T) {
	route := &Route{
		ID:       "r1",
		Backends: []Backend{{URL: "http://main"}},
	}
	loc := &Location{
		Path:     "/api",
		Backends: []Backend{{URL: "http://loc"}},
	}
	merged := MergeLocation(route, loc)
	if len(merged.Backends) != 1 || merged.Backends[0].URL != "http://loc" {
		t.Fatalf("backends = %#v", merged.Backends)
	}
	if len(route.Backends) != 1 || route.Backends[0].URL != "http://main" {
		t.Fatal("original route mutated")
	}
	if merged.ID != "r1" {
		t.Fatalf("id = %q", merged.ID)
	}
}
