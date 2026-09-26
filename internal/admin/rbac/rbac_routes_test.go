// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
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

func TestRouteAllowedByToken_EdgeScope_Tout(t *testing.T) {
	route := &router.Route{ID: "1", Host: "anywhere.fr"}
	scopes := []Scope{{Type: "edge", Value: "edge-lucas"}}
	if !RouteAllowedByToken("admin", scopes, route) {
		t.Fatal("scope edge doit autoriser toutes les routes")
	}
}

func TestRouteAllowedByToken_AdminDomainScopes_L4Visible(t *testing.T) {
	scopes := []Scope{{Type: "domain", Value: "*.dankdown.fr"}}
	stream := &router.Route{ID: "s1", Host: "Minecraft", Type: router.RouteTCP, ListenPort: 25565}
	httpRoute := &router.Route{ID: "h1", Host: "other.example.fr", Type: router.RouteHTTP}
	if !RouteAllowedByToken("admin", scopes, stream) {
		t.Fatal("admin + scopes domain doit voir les streams L4")
	}
	if !RouteAllowedByToken("viewer", scopes, stream) {
		t.Fatal("L4 n'est pas filtré par scopes domain (viewer inclus)")
	}
	if RouteAllowedByToken("admin", scopes, httpRoute) {
		t.Fatal("admin + scopes domain ne doit pas voir un HTTP hors scope")
	}
}

func TestFilterRoutesByScopes_AdminDomain_IncludesL4(t *testing.T) {
	scopes := []Scope{{Type: "domain", Value: "*.dankdown.fr"}}
	routes := []router.Route{
		{ID: "1", Host: "api.dankdown.fr", Type: router.RouteHTTP},
		{ID: "2", Host: "Minecraft", Type: router.RouteTCP, ListenPort: 25565},
		{ID: "3", Host: "other.example.fr", Type: router.RouteHTTP},
	}
	got := FilterRoutesByScopes("admin", scopes, routes)
	if len(got) != 2 {
		t.Fatalf("attendu HTTP in-scope + L4, got %#v", got)
	}
}
