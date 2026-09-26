// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJoinTokenStoreConsumeOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "join.json")
	s := NewJoinTokenStore(path)

	tok := "gpx_join_abc123"
	if err := s.Consume(tok); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := s.Consume(tok); err == nil {
		t.Fatal("second consume should fail")
	}
	if !s.IsUsed(tok) {
		t.Fatal("expected token used")
	}

	// Persistance
	s2 := NewJoinTokenStore(path)
	if !s2.IsUsed(tok) {
		t.Fatal("expected persisted used token")
	}
	if err := s2.Consume(tok); err == nil {
		t.Fatal("persisted token should still be rejected")
	}
}

func TestHubRevokeAgentClearsHMAC(t *testing.T) {
	dir := t.TempDir()
	h := NewHub("", slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	h.SetHMACStore(NewAgentHMACStore(filepath.Join(dir, "hmac.json")))
	h.SetJoinTokenStore(NewJoinTokenStore(filepath.Join(dir, "join.json")))

	h.hmacStore.Set("agent-1", "deadbeef") //nolint:errcheck
	if err := h.RevokeAgent("agent-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.hmacStore.Get("agent-1"); ok {
		t.Fatal("HMAC should be deleted after revoke")
	}
}

func TestHubJoinTokenConsumedOnPending(t *testing.T) {
	dir := t.TempDir()
	store := NewJoinTokenStore(filepath.Join(dir, "join.json"))
	tok := "gpx_join_once"
	if err := store.Consume(tok); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := store.Consume(tok)
	if err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("should be fast")
	}
}

func TestHubPreApproveBeforeConnect(t *testing.T) {
	dir := t.TempDir()
	h := NewHub("", slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	h.SetHMACStore(NewAgentHMACStore(filepath.Join(dir, "hmac.json")))
	h.SetJoinTokenStore(NewJoinTokenStore(filepath.Join(dir, "join.json")))

	if err := h.ApproveAgent("future-agent"); err != nil {
		t.Fatal(err)
	}
	h.preApprovedMu.Lock()
	_, ok := h.preApproved["future-agent"]
	h.preApprovedMu.Unlock()
	if !ok {
		t.Fatal("expected pre-approval stored")
	}

	if !h.consumePreApproval("future-agent") {
		t.Fatal("expected consume true")
	}
	if h.consumePreApproval("future-agent") {
		t.Fatal("second consume should be false")
	}
}
