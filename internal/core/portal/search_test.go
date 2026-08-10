// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"path/filepath"
	"testing"
)

func TestMatchTargetQuery(t *testing.T) {
	f := TargetSearchFields{Name: "Prod DB", Kind: "ssh", Host: "10.0.0.5", Source: "catalog"}
	if !MatchTargetQuery(f, "") {
		t.Fatal("empty")
	}
	if !MatchTargetQuery(f, "prod") {
		t.Fatal("name")
	}
	if !MatchTargetQuery(f, "10.0") {
		t.Fatal("host")
	}
	if MatchTargetQuery(f, "staging") {
		t.Fatal("no match")
	}
}

func TestSortTargetsFavorites(t *testing.T) {
	type item struct{ ID, Name string }
	items := []item{{"a", "A"}, {"b", "B"}, {"c", "C"}}
	got := SortTargetsFavorites(items, func(i item) string { return i.ID }, []string{"c", "a"})
	if len(got) != 3 || got[0].ID != "c" || got[1].ID != "a" || got[2].ID != "b" {
		t.Fatalf("%+v", got)
	}
}

func TestFavoritesPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portal.gpx")
	s := NewStore(path, "fav-key")
	if err := s.SetFavorites("u1", []string{"t1", "t2", "t1", ""}); err != nil {
		t.Fatal(err)
	}
	got := s.Favorites("u1")
	if len(got) != 2 || got[0] != "t1" || got[1] != "t2" {
		t.Fatalf("%v", got)
	}
	on, err := s.ToggleFavorite("u1", "t1")
	if err != nil || on {
		t.Fatalf("toggle off: on=%v err=%v", on, err)
	}
	on, err = s.ToggleFavorite("u1", "t3")
	if err != nil || !on {
		t.Fatalf("toggle on: on=%v err=%v", on, err)
	}
	s2 := NewStore(path, "fav-key")
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	got = s2.Favorites("u1")
	if len(got) != 2 || got[0] != "t2" || got[1] != "t3" {
		t.Fatalf("reload %v", got)
	}
}
