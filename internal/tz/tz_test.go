// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tz_test

import (
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/vincamok/goproxify/internal/tz"
)

func TestLoadLocationEmbedded(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatalf("LoadLocation Europe/Paris: %v (time/tzdata manquant ?)", err)
	}
	prev := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = prev })

	if got := tz.Name(); got != "Europe/Paris" {
		t.Fatalf("Name() = %q, want Europe/Paris", got)
	}
	if tz.NowRFC3339() == "" {
		t.Fatal("NowRFC3339 vide")
	}
}
