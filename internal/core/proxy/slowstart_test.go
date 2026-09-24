// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestRampFactor(t *testing.T) {
	h := NewBackendHealth(nil)
	window := 100 * time.Second

	if f := h.RampFactor("http://unknown", window); f != 1 {
		t.Fatalf("backend inconnu: %v", f)
	}
	h.mu.Lock()
	h.getOrCreateLocked("http://a").upSince = time.Now()
	h.getOrCreateLocked("http://b").upSince = time.Now().Add(-50 * time.Second)
	h.getOrCreateLocked("http://c").upSince = time.Now().Add(-200 * time.Second)
	h.mu.Unlock()

	if f := h.RampFactor("http://a", window); f < slowStartFloor || f > 0.1 {
		t.Fatalf("début de rampe: %v", f)
	}
	if f := h.RampFactor("http://b", window); f < 0.45 || f > 0.6 {
		t.Fatalf("mi-rampe: %v", f)
	}
	if f := h.RampFactor("http://c", window); f != 1 {
		t.Fatalf("rampe terminée: %v", f)
	}
	if f := h.RampFactor("http://a", 0); f != 1 {
		t.Fatalf("sans fenêtre: %v", f)
	}
}

func TestMarkUpRestartsRampOnlyOnRecovery(t *testing.T) {
	h := NewBackendHealth(nil)
	h.MarkUp("http://a") // création : état neuf
	h.mu.Lock()
	h.states["http://a"].upSince = time.Now().Add(-time.Hour)
	h.mu.Unlock()

	h.MarkUp("http://a") // succès courant : pas de nouvelle rampe
	if f := h.RampFactor("http://a", time.Minute); f != 1 {
		t.Fatalf("un succès ordinaire ne doit pas relancer la rampe: %v", f)
	}
	h.MarkDown("http://a", time.Second)
	h.MarkUp("http://a") // reprise après quarantaine
	if f := h.RampFactor("http://a", time.Minute); f >= 1 {
		t.Fatalf("la reprise doit relancer la rampe: %v", f)
	}
}

func slowStartHandler(sec int, urls ...string) *Handler {
	bs := make([]router.Backend, len(urls))
	for i, u := range urls {
		bs[i] = router.Backend{URL: u}
	}
	route := &router.Route{Host: "ss.test", Backends: bs, SlowStartSec: sec}
	return &Handler{route: route, health: NewBackendHealth(nil), balancer: newRoundRobin(bs)}
}

func firstShare(h *Handler, n int) (ramping int) {
	for i := 0; i < n; i++ {
		c := h.failoverCandidates(httptest.NewRequest("GET", "/", nil))
		if c[0].URL == "http://new" {
			ramping++
		}
	}
	return ramping
}

func TestSlowStartShiftsTrafficAwayFromNewBackend(t *testing.T) {
	h := slowStartHandler(60, "http://new", "http://old")
	h.health.mu.Lock()
	h.health.getOrCreateLocked("http://new").upSince = time.Now()
	h.health.getOrCreateLocked("http://old").upSince = time.Now().Add(-time.Hour)
	h.health.mu.Unlock()

	const n = 4000
	got := firstShare(h, n)
	// RR donne 50 % au nouveau ; à f≈5 % il n'en garde que ~2,5 %.
	if got > n/10 {
		t.Fatalf("le backend en rampe reçoit trop de trafic en premier choix: %d/%d", got, n)
	}
	if got == 0 {
		t.Fatalf("le backend en rampe doit garder un filet de trafic")
	}
}

func TestSlowStartDisabledKeepsRoundRobin(t *testing.T) {
	h := slowStartHandler(0, "http://new", "http://old")
	h.health.mu.Lock()
	h.health.getOrCreateLocked("http://new").upSince = time.Now()
	h.health.mu.Unlock()
	if got := firstShare(h, 1000); got != 500 {
		t.Fatalf("round-robin attendu 500/1000, got %d", got)
	}
}

func TestSlowStartNoAlternativeKeepsOrder(t *testing.T) {
	h := slowStartHandler(60, "http://a", "http://b")
	h.health.mu.Lock()
	h.health.getOrCreateLocked("http://a").upSince = time.Now()
	h.health.getOrCreateLocked("http://b").upSince = time.Now()
	h.health.mu.Unlock()
	// Tous en montée au même instant : aucun détournement possible.
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		seen[h.failoverCandidates(httptest.NewRequest("GET", "/", nil))[0].URL]++
	}
	if seen["http://a"] != 100 || seen["http://b"] != 100 {
		t.Fatalf("répartition inchangée attendue: %v", seen)
	}
}

func TestSlowStartRespectsStickySession(t *testing.T) {
	h := slowStartHandler(60, "http://new", "http://old")
	h.route.StickyCookie = "S"
	h.balancer = newSticky(h.balancer, h.route.Backends, "S")
	h.health.mu.Lock()
	h.health.getOrCreateLocked("http://new").upSince = time.Now()
	h.health.getOrCreateLocked("http://old").upSince = time.Now().Add(-time.Hour)
	h.health.mu.Unlock()

	for i := 0; i < 200; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "S", Value: "http://new"})
		if c := h.failoverCandidates(req); c[0].URL != "http://new" {
			t.Fatal("une session collante doit garder son backend")
		}
	}
}
