// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func tarpitEngine(cfg TarpitConfig) *Engine {
	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	e.UpdateConfig(Config{Tarpit: cfg})
	return e
}

func TestTarpit_DisabledReturnsImmediately(t *testing.T) {
	e := tarpitEngine(TarpitConfig{DelayMs: 500})
	start := time.Now()
	if e.TarpitWait(context.Background()) || time.Since(start) > 100*time.Millisecond {
		t.Fatal("tarpit désactivé : pas de retenue attendue")
	}
}

func TestTarpit_HoldsForDelay(t *testing.T) {
	e := tarpitEngine(TarpitConfig{Enabled: true, DelayMs: 80})
	start := time.Now()
	if !e.TarpitWait(context.Background()) {
		t.Fatal("requête non retenue")
	}
	if d := time.Since(start); d < 70*time.Millisecond {
		t.Fatalf("retenue trop courte: %v", d)
	}
}

func TestTarpit_ClientDisconnectReleasesSlot(t *testing.T) {
	e := tarpitEngine(TarpitConfig{Enabled: true, DelayMs: 10_000, MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.TarpitWait(ctx); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("la déconnexion du client doit libérer la requête")
	}
	if len(e.tarpitSlots) != 0 {
		t.Fatal("slot non libéré")
	}
}

func TestTarpit_SaturationFallsBackToImmediateReject(t *testing.T) {
	e := tarpitEngine(TarpitConfig{Enabled: true, DelayMs: 10_000, MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.TarpitWait(ctx)
	time.Sleep(30 * time.Millisecond)

	start := time.Now()
	if e.TarpitWait(context.Background()) || time.Since(start) > 100*time.Millisecond {
		t.Fatal("tarpit saturé : refus immédiat attendu")
	}
}

func TestTarpitConfig_Bounds(t *testing.T) {
	if d := (TarpitConfig{}).delay(); d != defaultTarpitDelay {
		t.Fatalf("défaut: %v", d)
	}
	if d := (TarpitConfig{DelayMs: 10 * 60_000}).delay(); d != maxTarpitDelay {
		t.Fatalf("plafond: %v", d)
	}
	if n := (TarpitConfig{}).slots(); n != defaultTarpitSlots {
		t.Fatalf("slots: %d", n)
	}
}
