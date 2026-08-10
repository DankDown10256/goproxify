// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package delegation

import (
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestHostCoveredByDomain(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"api.dankdown.fr", "*.dankdown.fr", true},
		{"hvi.dankdown.fr", "*.dankdown.fr", true},
		{"dankdown.fr", "*.dankdown.fr", false},
		{"api.other.fr", "*.dankdown.fr", false},
		{"api.dankdown.fr", "api.dankdown.fr", true},
		{"x.api.dankdown.fr", "api.dankdown.fr", false},
		{"*.dankdown.fr", "*.dankdown.fr", true},
		{"app.dev.example.com", "*.example.com", false}, // un seul label
		{"portal.example.com", "*.example.com", true},
		{"app.dev.example.com", "*.dev.example.com", true},
	}
	for _, c := range cases {
		if got := HostCoveredByDomain(c.host, c.pattern); got != c.want {
			t.Errorf("HostCoveredByDomain(%q,%q)=%v want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestFilterRoutesForCore(t *testing.T) {
	bindings := []Binding{{
		Domain:            "*.dankdown.fr",
		ResponsibleCoreID: "front-uuid",
		TargetCoreID:      "lucas-uuid",
	}}
	routes := []router.Route{
		{ID: "1", Host: "api.dankdown.fr"},
		{ID: "2", Host: "other.example.fr"},
		{ID: "3", Host: "hvi.dankdown.fr"},
	}

	front := FilterRoutesForCore("front-uuid", "goproxify-core", routes, bindings)
	if len(front) != 1 || front[0].Host != "other.example.fr" {
		t.Fatalf("front got %#v", front)
	}

	lucas := FilterRoutesForCore("lucas-uuid", "core-lucas", routes, bindings)
	if len(lucas) != 3 {
		t.Fatalf("lucas got %d routes, want 3", len(lucas))
	}

	other := FilterRoutesForCore("dev-uuid", "core-dev", routes, bindings)
	if len(other) != 1 || other[0].Host != "other.example.fr" {
		t.Fatalf("other got %#v", other)
	}
}
