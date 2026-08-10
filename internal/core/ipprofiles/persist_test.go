// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipprofiles_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/core/ipprofiles"
	"github.com/vincamok/goproxify/internal/core/router"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := []*router.IPProfile{
		{ID: "a", Name: "deny-bad", Mode: "deny", CIDRs: []string{"1.2.3.0/24", "10.0.0.1/32"}},
		{ID: "b", Name: "allow-office", Mode: "allow", CIDRs: []string{"203.0.113.0/24"}},
	}
	if err := ipprofiles.Save(dir, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatalf("fichier absent: %v", err)
	}
	out, err := ipprofiles.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d want 2", len(out))
	}
	if out[0].ID != "a" || out[0].Mode != "deny" || len(out[0].CIDRs) != 2 {
		t.Fatalf("profil 0 incorrect: %+v", out[0])
	}
	if out[1].Name != "allow-office" {
		t.Fatalf("profil 1 incorrect: %+v", out[1])
	}
}

func TestLoadMissing(t *testing.T) {
	dir := t.TempDir()
	out, err := ipprofiles.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out != nil {
		t.Fatalf("want nil, got %+v", out)
	}
}

func TestSaveNil(t *testing.T) {
	dir := t.TempDir()
	if err := ipprofiles.Save(dir, nil); err != nil {
		t.Fatalf("Save nil: %v", err)
	}
	out, err := ipprofiles.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want empty, got %d", len(out))
	}
}
