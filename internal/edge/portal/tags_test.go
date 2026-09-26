// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import "testing"

func TestCatalogVisible(t *testing.T) {
	cases := []struct {
		name     string
		user     []string
		dest     []string
		want     bool
	}{
		{"untagged dest any user", []string{"prod"}, nil, true},
		{"untagged dest empty user", nil, []string{}, true},
		{"tagged dest matching", []string{"dev", "ops"}, []string{"prod", "ops"}, true},
		{"tagged dest no match", []string{"dev"}, []string{"prod"}, false},
		{"user no tags tagged dest", nil, []string{"prod"}, false},
		{"user empty tags tagged dest", []string{}, []string{"prod"}, false},
		{"both empty tags", []string{}, []string{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CatalogVisible(tc.user, tc.dest); got != tc.want {
				t.Fatalf("CatalogVisible(%v,%v)=%v want %v", tc.user, tc.dest, got, tc.want)
			}
		})
	}
}

func TestFilterCatalog(t *testing.T) {
	items := []CatalogTarget{
		{ID: "1", Name: "public", Tags: nil},
		{ID: "2", Name: "prod", Tags: []string{"prod"}},
		{ID: "3", Name: "dev", Tags: []string{"dev"}},
	}
	got := FilterCatalog(items, []string{"prod"})
	if len(got) != 2 || got[0].ID != "1" || got[1].ID != "2" {
		t.Fatalf("%+v", got)
	}
	got = FilterCatalog(items, nil)
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("user sans tags: %+v", got)
	}
}
