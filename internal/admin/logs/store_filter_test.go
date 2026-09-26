// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"strings"
	"testing"
)

func TestMatchesFilterKindAccessSystem(t *testing.T) {
	access := Entry{Status: 200, Component: "edge", NodeName: "edge-1", Level: "info", Domain: "a.example", Method: "GET", Path: "/"}
	sysEdge := Entry{Status: 0, Component: "edge", NodeName: "edge-1", Level: "info", Message: "started"}
	sysAdmin := Entry{Status: 0, Component: "admin", NodeName: "admin", Level: "warn", Message: "reload"}
	sysAgent := Entry{Status: 0, Component: "agent", NodeName: "agent-1", Level: "info", Message: "line"}

	cases := []struct {
		name string
		e    Entry
		p    SearchParams
		want bool
	}{
		{"access accepts http", access, SearchParams{Kind: "access"}, true},
		{"access rejects system", sysEdge, SearchParams{Kind: "access"}, false},
		{"system accepts edge", sysEdge, SearchParams{Kind: "system"}, true},
		{"system accepts admin", sysAdmin, SearchParams{Kind: "system"}, true},
		{"system accepts agent", sysAgent, SearchParams{Kind: "system"}, true},
		{"system rejects access", access, SearchParams{Kind: "system"}, false},
		{"edge access scoped", access, SearchParams{Kind: "access", Component: "edge", NodeName: "edge-1"}, true},
		{"edge access wrong node", access, SearchParams{Kind: "access", Component: "edge", NodeName: "other"}, false},
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

// TestMatchesFilterNodeIDStableAcrossRename vérifie que le filtre par NodeID
// (identifiant stable du nœud) continue de matcher une entrée même quand
// NodeName a changé — c'est tout l'intérêt de NodeID face à un renommage
// (ex. re-pairing après régénération de edge.json).
func TestMatchesFilterNodeIDStableAcrossRename(t *testing.T) {
	oldEntry := Entry{Status: 200, NodeID: "token-abc", NodeName: "Frontal"}
	newEntry := Entry{Status: 200, NodeID: "token-abc", NodeName: "goproxify-edge"}
	other := Entry{Status: 200, NodeID: "token-xyz", NodeName: "goproxify-edge"}

	p := SearchParams{NodeID: "token-abc"}
	if !matchesFilter(oldEntry, p) {
		t.Fatal("l'entrée avec l'ancien nom devrait matcher par node_id")
	}
	if !matchesFilter(newEntry, p) {
		t.Fatal("l'entrée avec le nouveau nom devrait matcher par node_id")
	}
	if matchesFilter(other, p) {
		t.Fatal("une entrée d'un autre nœud ne devrait pas matcher")
	}

	// Quand NodeID est fourni, NodeName ne doit plus être pris en compte
	// (sinon un nœud reconfiguré perdrait son propre historique).
	pBoth := SearchParams{NodeID: "token-abc", NodeName: "goproxify-edge"}
	if !matchesFilter(oldEntry, pBoth) {
		t.Fatal("node_id devrait primer sur node_name dans le filtre")
	}
}

// TestMatchesFilterSearchIncludesNodeName vérifie que la recherche libre
// (p.Search) retrouve une entrée par son ancien node_name — c'est le
// mécanisme de récupération manuelle de l'historique d'un nœud renommé,
// indépendant du nœud "actuellement sélectionné" dans l'UI.
func TestMatchesFilterSearchIncludesNodeName(t *testing.T) {
	e := Entry{Status: 200, NodeName: "Frontal", Message: "ok", Path: "/", Domain: "a.example"}
	if !matchesFilter(e, SearchParams{Search: "frontal"}) {
		t.Fatal("la recherche libre devrait matcher node_name (insensible à la casse)")
	}
	if matchesFilter(e, SearchParams{Search: "backup"}) {
		t.Fatal("ne devrait pas matcher un nom absent")
	}
}

// TestBuildWhereNodeIDPrimeOverNodeName vérifie que la clause SQL générée
// filtre sur node_id (et pas node_name) dès que NodeID est fourni.
func TestBuildWhereNodeIDPrimeOverNodeName(t *testing.T) {
	where, args := buildWhere(SearchParams{NodeID: "token-abc", NodeName: "goproxify-edge"})
	if !strings.Contains(where, "node_id=?") {
		t.Fatalf("clause attendue sur node_id, got %q", where)
	}
	if strings.Contains(where, "node_name=?") {
		t.Fatalf("node_name ne devrait pas apparaître quand node_id est fourni, got %q", where)
	}
	if len(args) != 1 || args[0] != "token-abc" {
		t.Fatalf("args = %#v", args)
	}
}

// TestBuildWhereSearchIncludesNodeName vérifie que la clause SQL de
// recherche libre inclut node_name.
func TestBuildWhereSearchIncludesNodeName(t *testing.T) {
	where, _ := buildWhere(SearchParams{Search: "frontal"})
	if !strings.Contains(where, "node_name LIKE ?") {
		t.Fatalf("clause de recherche libre devrait inclure node_name, got %q", where)
	}
}
