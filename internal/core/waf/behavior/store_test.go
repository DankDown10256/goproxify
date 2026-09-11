// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"fmt"
	"testing"
	"time"
)

func TestNoSignalCleanRequest(t *testing.T) {
	s := NewStore(60 * time.Second)
	score, sigs := s.Record("1.2.3.4", Event{
		At:     time.Now(),
		Status: 200,
		Method: "GET",
		Path:   "/",
		UA:     "Mozilla/5.0",
	})
	if score != 0 || len(sigs) != 0 {
		t.Fatalf("clean request should score 0, got %d signals=%v", score, sigs)
	}
}

func TestHigh4xxRate(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 8 requêtes dont 5 en 4xx (62 %)
	for i := 0; i < 3; i++ {
		s.Record("1.1.1.1", Event{At: now, Status: 200, Method: "GET", Path: fmt.Sprintf("/ok%d", i), UA: "bot"})
	}
	var score int
	for i := 0; i < 5; i++ {
		score, _ = s.Record("1.1.1.1", Event{At: now, Status: 404, Method: "GET", Path: fmt.Sprintf("/miss%d", i), UA: "bot"})
	}
	if score == 0 {
		t.Fatal("high 4xx rate should produce a score")
	}
}

func TestPathScanning(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	var score int
	for i := 0; i < 20; i++ {
		score, _ = s.Record("2.2.2.2", Event{At: now, Status: 404, Method: "GET", Path: fmt.Sprintf("/probe/%d", i), UA: "scanner"})
	}
	if score == 0 {
		t.Fatal("path scanning should produce a score")
	}
}

func TestWAFScoreAccumulation(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	var score int
	// 4 requêtes avec score WAF=3 chacune → cumul=12 ≥ seuil 8
	for i := 0; i < 4; i++ {
		score, _ = s.Record("3.3.3.3", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x", WafScore: 3})
	}
	if score == 0 {
		t.Fatal("accumulated WAF score should produce a signal")
	}
}

func TestUARotation(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	uas := []string{"Mozilla/5.0", "curl/7.0", "python-requests/2.0"}
	var score int
	for _, ua := range uas {
		score, _ = s.Record("4.4.4.4", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: ua})
	}
	if score == 0 {
		t.Fatal("UA rotation should produce a signal")
	}
}

func TestRequestBurst(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	var score int
	for i := 0; i < 35; i++ {
		score, _ = s.Record("5.5.5.5", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "bot"})
	}
	if score == 0 {
		t.Fatal("burst should produce a signal")
	}
}

func TestWindowPurge(t *testing.T) {
	s := NewStore(5 * time.Second)
	old := time.Now().Add(-10 * time.Second)
	now := time.Now()
	// Événements anciens (hors fenêtre)
	for i := 0; i < 20; i++ {
		s.Record("6.6.6.6", Event{At: old, Status: 404, Method: "GET", Path: fmt.Sprintf("/old%d", i), UA: "x"})
	}
	// Un seul événement récent propre
	score, _ := s.Record("6.6.6.6", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	if score != 0 {
		t.Fatalf("old events should be purged, got score %d", score)
	}
}
