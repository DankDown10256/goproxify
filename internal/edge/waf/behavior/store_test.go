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

func TestScorePreRequest(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// Pas encore de profil → Score doit retourner 0
	score, sigs := s.Score("7.7.7.7")
	if score != 0 || len(sigs) != 0 {
		t.Fatal("unknown IP should score 0")
	}
	// Créer un profil avec scan de chemins
	for i := 0; i < 20; i++ {
		s.Record("7.7.7.7", Event{At: now, Status: 404, Method: "GET", Path: fmt.Sprintf("/x/%d", i), UA: "bot"})
	}
	// Score en lecture seule doit refléter le profil
	score, _ = s.Score("7.7.7.7")
	if score == 0 {
		t.Fatal("Score() should reflect existing profile")
	}
}

func TestHAPayload(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// Créer un profil avec path scanning (>15 paths) → score > 0
	for i := 0; i < 20; i++ {
		s.Record("8.8.8.8", Event{At: now, Status: 404, Method: "GET", Path: fmt.Sprintf("/scan/%d", i), UA: "bot"})
	}
	origScore, _ := s.Score("8.8.8.8")
	if origScore == 0 {
		t.Fatal("source store should have a non-zero score before export")
	}

	payload := s.BuildHAPayload()
	if _, ok := payload.Entries["8.8.8.8"]; !ok {
		t.Fatal("BuildHAPayload should include active scored IPs")
	}

	// Appliquer sur un store vide → doit injecter un profil synthétique
	s2 := NewStore(60 * time.Second)
	s2.ApplyHAPayload(payload)
	score2, _ := s2.Score("8.8.8.8")
	if score2 == 0 {
		t.Fatal("ApplyHAPayload should populate the target store with a non-zero score")
	}
}

// ── Tests sous le seuil (non-régression) ─────────────────────────────────────

func TestHigh4xxRateBelowThreshold(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 5 requêtes : 1 en 4xx (20 % < 40 %) → pas de signal
	for i := 0; i < 4; i++ {
		s.Record("10.0.0.1", Event{At: now, Status: 200, Method: "GET", Path: fmt.Sprintf("/ok%d", i), UA: "x"})
	}
	score, _ := s.Record("10.0.0.1", Event{At: now, Status: 404, Method: "GET", Path: "/miss", UA: "x"})
	if score != 0 {
		t.Fatalf("20%% 4xx should not trigger high_4xx_rate, got score %d", score)
	}
}

func TestPathScanningBelowThreshold(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 14 paths uniques avec status 200 (seuil path_scanning = 15) → pas de signal
	var score int
	for i := 0; i < 14; i++ {
		score, _ = s.Record("10.0.0.2", Event{At: now, Status: 200, Method: "GET", Path: fmt.Sprintf("/p%d", i), UA: "x"})
	}
	_, sigs := s.Score("10.0.0.2")
	for _, sig := range sigs {
		if sig.Name == "path_scanning" {
			t.Fatalf("14 paths should not trigger path_scanning, score=%d sigs=%v", score, sigs)
		}
	}
}

func TestRequestBurstBelowThreshold(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 29 requêtes (seuil burst = 30) → pas de signal burst
	var score int
	for i := 0; i < 29; i++ {
		score, _ = s.Record("10.0.0.3", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	}
	if score != 0 {
		t.Fatalf("29 req burst should not trigger request_burst, got score %d", score)
	}
}

func TestUARotationBelowThreshold(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 2 UAs distincts (seuil = 3) → pas de signal
	score, _ := s.Record("10.0.0.4", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "A"})
	score, _ = s.Record("10.0.0.4", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "B"})
	if score != 0 {
		t.Fatalf("2 UAs should not trigger ua_rotation, got score %d", score)
	}
}

// ── high_post_ratio ───────────────────────────────────────────────────────────

func TestHighPostRatio(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 10 requêtes dont 8 POST (80 % > 70 %) → signal
	var score int
	for i := 0; i < 8; i++ {
		score, _ = s.Record("20.0.0.1", Event{At: now, Status: 200, Method: "POST", Path: "/api", UA: "x"})
	}
	for i := 0; i < 2; i++ {
		score, _ = s.Record("20.0.0.1", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	}
	if score == 0 {
		t.Fatal("high POST ratio should produce a signal")
	}
}

func TestHighPostRatioBelowThreshold(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 10 requêtes dont 5 POST (50 % < 70 %) → pas de signal
	var score int
	for i := 0; i < 5; i++ {
		score, _ = s.Record("20.0.0.2", Event{At: now, Status: 200, Method: "POST", Path: "/api", UA: "x"})
	}
	for i := 0; i < 5; i++ {
		score, _ = s.Record("20.0.0.2", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	}
	if score != 0 {
		t.Fatalf("50%% POST should not trigger high_post_ratio, got score %d", score)
	}
}

func TestHighPostRatioRequiresMinRequests(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 9 requêtes POST seulement (< 10 min) → pas de signal post_ratio même à 100 %
	var score int
	for i := 0; i < 9; i++ {
		score, _ = s.Record("20.0.0.3", Event{At: now, Status: 200, Method: "POST", Path: "/api", UA: "x"})
	}
	// Vérifier que le signal post_ratio n'est pas déclenché (score peut être 0 ou non-nul à cause d'autres signaux,
	// on vérifie l'absence du signal spécifique)
	_, sigs := s.Score("20.0.0.3")
	for _, sig := range sigs {
		if sig.Name == "high_post_ratio" {
			t.Fatal("high_post_ratio should not fire with fewer than 10 requests")
		}
	}
	_ = score
}

// ── high_path_entropy ─────────────────────────────────────────────────────────

func TestHighPathEntropy(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 20 requêtes, toutes vers des paths différents → entropie maximale
	var score int
	for i := 0; i < 20; i++ {
		score, _ = s.Record("30.0.0.1", Event{At: now, Status: 200, Method: "GET", Path: fmt.Sprintf("/unique/%d", i), UA: "x"})
	}
	if score == 0 {
		t.Fatal("all-unique paths over 20 requests should trigger high_path_entropy")
	}
}

func TestHighPathEntropyBelowThreshold(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 20 requêtes toutes vers le même path → entropie 0
	var score int
	for i := 0; i < 20; i++ {
		score, _ = s.Record("30.0.0.2", Event{At: now, Status: 200, Method: "GET", Path: "/same", UA: "x"})
	}
	_, sigs := s.Score("30.0.0.2")
	for _, sig := range sigs {
		if sig.Name == "high_path_entropy" {
			t.Fatalf("single path should not trigger high_path_entropy, score=%d", score)
		}
	}
}

func TestHighPathEntropyRequiresMinRequests(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 19 requêtes uniques (< 20 min) → pas de signal high_path_entropy
	for i := 0; i < 19; i++ {
		s.Record("30.0.0.3", Event{At: now, Status: 200, Method: "GET", Path: fmt.Sprintf("/u%d", i), UA: "x"})
	}
	_, sigs := s.Score("30.0.0.3")
	for _, sig := range sigs {
		if sig.Name == "high_path_entropy" {
			t.Fatal("high_path_entropy should not fire with fewer than 20 requests")
		}
	}
}

// ── WAF score accumulation — tier haut (≥15 → score 5) ───────────────────────

func TestWAFScoreAccumulationHighTier(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 5 requêtes à WafScore=4 → cumul=20 ≥ 15 → score signal = 5
	for i := 0; i < 5; i++ {
		s.Record("40.0.0.1", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x", WafScore: 4})
	}
	_, sigs := s.Score("40.0.0.1")
	var wafSig *Signal
	for i := range sigs {
		if sigs[i].Name == "waf_score_accumulation" {
			wafSig = &sigs[i]
			break
		}
	}
	if wafSig == nil {
		t.Fatal("waf_score_accumulation signal should be present")
	}
	if wafSig.Score != 5 {
		t.Fatalf("high tier waf_score_accumulation should have score 5, got %d", wafSig.Score)
	}
}

func TestWAFScoreAccumulationLowTier(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// Cumul = 10 (8 ≤ 10 < 15) → score signal = 3
	for i := 0; i < 2; i++ {
		s.Record("40.0.0.2", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x", WafScore: 5})
	}
	_, sigs := s.Score("40.0.0.2")
	var wafSig *Signal
	for i := range sigs {
		if sigs[i].Name == "waf_score_accumulation" {
			wafSig = &sigs[i]
			break
		}
	}
	if wafSig == nil {
		t.Fatal("waf_score_accumulation signal should be present for cumul=10")
	}
	if wafSig.Score != 3 {
		t.Fatalf("low tier waf_score_accumulation should have score 3, got %d", wafSig.Score)
	}
}

// ── TrustBonus ────────────────────────────────────────────────────────────────

func TestTrustBonusGrowth(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()

	// Pas encore de profil → bonus 0
	if b := s.TrustBonus("50.0.0.1"); b != 0 {
		t.Fatalf("unknown IP trust bonus should be 0, got %d", b)
	}

	// 99 requêtes propres → toujours 0
	for i := 0; i < 99; i++ {
		s.Record("50.0.0.1", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	}
	if b := s.TrustBonus("50.0.0.1"); b != 0 {
		t.Fatalf("99 clean requests should give bonus 0, got %d", b)
	}

	// 100e requête propre → bonus passe à 1
	s.Record("50.0.0.1", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	if b := s.TrustBonus("50.0.0.1"); b != 1 {
		t.Fatalf("100 clean requests should give bonus 1, got %d", b)
	}
}

func TestTrustBonusCappedAt5(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// 600 requêtes propres → bonus plafonné à 5
	for i := 0; i < 600; i++ {
		s.Record("50.0.0.2", Event{At: now, Status: 200, Method: "GET", Path: "/", UA: "x"})
	}
	if b := s.TrustBonus("50.0.0.2"); b != 5 {
		t.Fatalf("600 clean requests should give bonus 5 (cap), got %d", b)
	}
}

// ── HA edge cases ─────────────────────────────────────────────────────────────

func TestHAPayloadExpiredIgnored(t *testing.T) {
	s := NewStore(60 * time.Second)
	// Payload avec ExpiresAt dans le passé → ignoré
	expired := HAPayload{Entries: map[string]HAEntry{
		"9.9.9.9": {Score: 10, ExpiresAt: time.Now().Add(-1 * time.Second)},
	}}
	s.ApplyHAPayload(expired)
	score, _ := s.Score("9.9.9.9")
	if score != 0 {
		t.Fatalf("expired HA entry should be ignored, got score %d", score)
	}
}

func TestHAPayloadLocalScoreWins(t *testing.T) {
	s := NewStore(60 * time.Second)
	now := time.Now()
	// Créer un profil local avec un score élevé
	for i := 0; i < 20; i++ {
		s.Record("9.9.9.8", Event{At: now, Status: 404, Method: "GET", Path: fmt.Sprintf("/scan%d", i), UA: "bot"})
	}
	localScore, _ := s.Score("9.9.9.8")

	// Payload pair avec score plus faible → score local inchangé
	lower := HAPayload{Entries: map[string]HAEntry{
		"9.9.9.8": {Score: 1, ExpiresAt: time.Now().Add(60 * time.Second)},
	}}
	s.ApplyHAPayload(lower)
	scoreAfter, _ := s.Score("9.9.9.8")
	if scoreAfter < localScore {
		t.Fatalf("local score should not decrease after applying lower peer score: local=%d after=%d", localScore, scoreAfter)
	}
}
