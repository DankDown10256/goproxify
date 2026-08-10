// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestFilterRoutesByScopes_AdminSansScope_Tout(t *testing.T) {
	routes := []router.Route{
		{ID: "1", Host: "api.dankdown.fr"},
		{ID: "2", Host: "app.dev.example.com"},
	}
	got := FilterRoutesByScopes("admin", nil, routes)
	if len(got) != 2 {
		t.Fatalf("admin sans scope doit tout voir, got %d", len(got))
	}
}

func TestFilterRoutesByScopes_AdminAvecDomain(t *testing.T) {
	routes := []router.Route{
		{ID: "1", Host: "api.dankdown.fr"},
		{ID: "2", Host: "app.dev.example.com"},
		{ID: "3", Host: "portal.example.com"},
	}
	scopes := []Scope{{Type: "domain", Value: "*.dankdown.fr"}}
	got := FilterRoutesByScopes("admin", scopes, routes)
	if len(got) != 1 || got[0].Host != "api.dankdown.fr" {
		t.Fatalf("attendu uniquement dankdown, got %#v", got)
	}
}

func TestFilterRoutesByScopes_WildcardSingleLabel(t *testing.T) {
	routes := []router.Route{
		{ID: "1", Host: "app.dev.example.com"},
		{ID: "2", Host: "portal.example.com"},
	}
	// *.example.com ne doit PAS englober *.dev.example.com (un seul label DNS).
	got := FilterRoutesByScopes("admin", []Scope{{Type: "domain", Value: "*.example.com"}}, routes)
	if len(got) != 1 || got[0].Host != "portal.example.com" {
		t.Fatalf("wildcard 1 label : got %#v", got)
	}
	got = FilterRoutesByScopes("admin", []Scope{{Type: "domain", Value: "*.dev.example.com"}}, routes)
	if len(got) != 1 || got[0].Host != "app.dev.example.com" {
		t.Fatalf("scope dev : got %#v", got)
	}
}

func TestFilterRoutesByScopes_DomainViaAlias(t *testing.T) {
	routes := []router.Route{
		{ID: "1", Host: "primary.internal", Aliases: []string{"api.dankdown.fr"}},
		{ID: "2", Host: "other.example.fr"},
	}
	scopes := []Scope{{Type: "domain", Value: "*.dankdown.fr"}}
	got := FilterRoutesByScopes("admin", scopes, routes)
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("alias doit matcher le scope domaine, got %#v", got)
	}
}

func TestFilterRoutesByScopes_ViewerSansScope_Rien(t *testing.T) {
	routes := []router.Route{{ID: "1", Host: "api.dankdown.fr"}}
	got := FilterRoutesByScopes("viewer", nil, routes)
	if len(got) != 0 {
		t.Fatalf("viewer sans scope ne doit rien voir, got %d", len(got))
	}
}

func TestRouteAllowedByToken_CoreScope_Tout(t *testing.T) {
	route := &router.Route{ID: "1", Host: "anywhere.fr"}
	scopes := []Scope{{Type: "core", Value: "core-lucas"}}
	if !RouteAllowedByToken("admin", scopes, route) {
		t.Fatal("scope core doit autoriser toutes les routes")
	}
}
