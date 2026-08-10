// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestFailoverSkipsDeadBackend(t *testing.T) {
	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer alive.Close()

	// Port ouvert puis fermé = connexion refusée
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	route := &router.Route{
		Host: "app.test",
		LB:   router.LBAdaptive,
		Backends: []router.Backend{
			{URL: "http://" + deadAddr},
			{URL: alive.URL},
		},
	}
	store := NewAgentMetricsStore()
	// Dead backend « moins chargé » → adaptive le préfère en premier
	store.MergeScores(map[string]float64{
		"127.0.0.1": 1, // both share 127.0.0.1 — force via different handling
	})
	// Use distinct IPs via hosts - both are 127.0.0.1 so adaptive can't distinguish.
	// Prefer dead first by putting it first in backends and using round_robin with Next
	// that returns first — for adaptive with same IP score, order of iteration picks lowest index among equal... 
	// Actually same IP same score: first in loop wins if score equal (< bestScore only).
	// So put dead first with score 0, alive with score 50.
	deadURL := "http://" + deadAddr
	aliveURL := alive.URL
	route.Backends = []router.Backend{
		{URL: deadURL},
		{URL: aliveURL},
	}
	// Clear scores → fallback RR; first Next returns index 0 (dead) after Add
	route.LB = router.LBRoundRobin

	h := NewHandler(route, NewBackendHealth(slog.Default()), store, NewPeerRegistry(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200 failover to alive", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestMarkDownQuarantine(t *testing.T) {
	h := NewBackendHealth(nil)
	h.MarkDown("http://x", 50*time.Millisecond)
	if h.IsHealthy("http://x") {
		t.Fatal("should be down")
	}
	time.Sleep(60 * time.Millisecond)
	if !h.IsHealthy("http://x") {
		t.Fatal("quarantine should expire")
	}
}

func TestBackendHealthSnapshot(t *testing.T) {
	h := NewBackendHealth(nil)
	if got := h.Status("http://never"); got != "unknown" {
		t.Fatalf("Status unknown = %q", got)
	}
	h.MarkUp("http://up")
	h.MarkDown("http://down", time.Minute)
	snap := h.Snapshot()
	if snap["http://up"] != "up" {
		t.Fatalf("up = %q", snap["http://up"])
	}
	if snap["http://down"] != "down" {
		t.Fatalf("down = %q", snap["http://down"])
	}
	if h.Status("http://down") != "down" {
		t.Fatal("Status down")
	}
}
