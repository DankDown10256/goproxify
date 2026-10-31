// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package lastua

import (
	"fmt"
	"strings"
	"testing"
)

func TestNoteGet(t *testing.T) {
	tr := New()
	if tr.Get("203.0.113.7") != "" {
		t.Fatal("IP inconnue : User-Agent vide attendu")
	}
	tr.Note("203.0.113.7", "sqlmap/1.7")
	tr.Note("203.0.113.7", "")
	if got := tr.Get("203.0.113.7"); got != "sqlmap/1.7" {
		t.Fatalf("got %q", got)
	}
	tr.Note("203.0.113.7", "curl/8.0")
	if got := tr.Get("203.0.113.7"); got != "curl/8.0" {
		t.Fatalf("le dernier User-Agent l'emporte, got %q", got)
	}
}

func TestClip(t *testing.T) {
	if got := Clip("a\r\nb\x00"); got != "a??b?" {
		t.Fatalf("got %q", got)
	}
	got := Clip(strings.Repeat("x", 1000))
	if r := []rune(got); len(r) != maxLen+1 || r[maxLen] != '…' {
		t.Fatalf("longueur %d", len(r))
	}
}

func TestBounded(t *testing.T) {
	tr := New()
	for i := 0; i < shards*perShardCap*3; i++ {
		tr.Note(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "ua")
	}
	total := 0
	for i := range tr.s {
		total += len(tr.s[i].m)
	}
	if total > shards*perShardCap {
		t.Fatalf("suivi non borné : %d entrées", total)
	}
}

func TestNilTracker(t *testing.T) {
	var tr *Tracker
	tr.Note("203.0.113.7", "x")
	if tr.Get("203.0.113.7") != "" {
		t.Fatal("tracker nil : vide attendu")
	}
}
