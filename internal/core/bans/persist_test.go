// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package bans_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/bans"
	"github.com/vincamok/goproxify/internal/core/router"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	in := []*router.RuntimeBan{
		{ID: "crowdsec:1.2.3.4", IP: "1.2.3.4", Reason: "http-probe", Source: "crowdsec", ExpiresAt: &exp},
		{ID: "native-x", IP: "9.9.9.9", Reason: "manual", Source: "native"},
	}
	if err := bans.Save(dir, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bans.json")); err != nil {
		t.Fatalf("fichier absent: %v", err)
	}
	out, err := bans.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d want 2", len(out))
	}
	if out[0].IP != "1.2.3.4" || out[0].Source != "crowdsec" || out[0].ExpiresAt == nil {
		t.Fatalf("ban 0 incorrect: %+v", out[0])
	}
	if out[1].ExpiresAt != nil {
		t.Fatalf("ban 1 should be permanent: %+v", out[1])
	}
}

func TestLoadMissing(t *testing.T) {
	dir := t.TempDir()
	out, err := bans.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out != nil {
		t.Fatalf("want nil, got %+v", out)
	}
}
