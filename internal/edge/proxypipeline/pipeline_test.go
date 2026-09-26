// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxystore"
)

func cfg(id, host, backend string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"id":   id,
		"host": host,
		"type": "http",
		"backends": []map[string]any{
			{"url": backend, "weight": 1},
		},
		"lb": "round_robin",
	})
	return raw
}

func TestPendingToValidated(t *testing.T) {
	st := proxystore.New(t.TempDir())
	p := New(st)
	now := time.Now().UTC()
	env := &proxystore.Envelope{
		ID:        "p1",
		Revision:  "r1",
		Host:      "app.example.fr",
		Enabled:   true,
		CreatedAt: &now,
		Config:    cfg("p1", "app.example.fr", "http://127.0.0.1:8080"),
	}
	if err := p.CreateRevision(env); err != nil {
		t.Fatal(err)
	}
	got, err := p.DryRun("p1", "r1", DryRunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != proxystore.StatusValidated {
		t.Fatalf("status=%s", got.Status)
	}
	if got.DryRun == nil || !got.DryRun.OK {
		t.Fatalf("dry_run=%v", got.DryRun)
	}
}

func TestDryRunHostCollision(t *testing.T) {
	st := proxystore.New(t.TempDir())
	p := New(st)
	now := time.Now().UTC()
	if err := st.WriteProd(&proxystore.Envelope{
		SchemaVersion: 1,
		ID:            "existing",
		Host:          "app.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        cfg("existing", "app.example.fr", "http://127.0.0.1:1"),
	}); err != nil {
		t.Fatal(err)
	}
	env := &proxystore.Envelope{
		ID:       "p2",
		Revision: "r1",
		Host:     "app.example.fr",
		Enabled:  true,
		Config:   cfg("p2", "app.example.fr", "http://127.0.0.1:8080"),
	}
	if err := p.CreateRevision(env); err != nil {
		t.Fatal(err)
	}
	got, err := p.DryRun("p2", "r1", DryRunOptions{})
	if !errors.Is(err, ErrDryRunFailed) {
		t.Fatalf("want ErrDryRunFailed, got %v", err)
	}
	if got.Status != proxystore.StatusPending {
		t.Fatalf("status=%s", got.Status)
	}
}

func TestRejectBlocksPromote(t *testing.T) {
	st := proxystore.New(t.TempDir())
	p := New(st)
	env := &proxystore.Envelope{
		ID:       "p1",
		Revision: "r1",
		Host:     "app.example.fr",
		Enabled:  true,
		Config:   cfg("p1", "app.example.fr", "http://127.0.0.1:8080"),
	}
	if err := p.CreateRevision(env); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reject("p1", "r1", "nope"); err != nil {
		t.Fatal(err)
	}
	_, err := p.Promote("p1", "r1")
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("want ErrInvalidTransition, got %v", err)
	}
}

func TestValidatedToProduction(t *testing.T) {
	st := proxystore.New(t.TempDir())
	p := New(st)
	env := &proxystore.Envelope{
		ID:       "p1",
		Revision: "r1",
		Host:     "app.example.fr",
		Enabled:  true,
		Config:   cfg("p1", "app.example.fr", "http://127.0.0.1:8080"),
	}
	if err := p.CreateRevision(env); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DryRun("p1", "r1", DryRunOptions{}); err != nil {
		t.Fatal(err)
	}
	prod, err := p.Promote("p1", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if prod.Status != proxystore.StatusProduction {
		t.Fatalf("prod status=%s", prod.Status)
	}
	list, err := st.ListProd()
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%d err=%v", len(list), err)
	}
	if list[0].Host != "app.example.fr" {
		t.Fatalf("host=%s", list[0].Host)
	}

	// Promote without validation should fail for a new pending rev.
	env2 := &proxystore.Envelope{
		ID:       "p1",
		Revision: "r2",
		Host:     "app.example.fr",
		Enabled:  true,
		Config:   cfg("p1", "app.example.fr", "http://127.0.0.1:9090"),
	}
	if err := p.CreateRevision(env2); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Promote("p1", "r2"); !errors.Is(err, ErrNotValidated) {
		t.Fatalf("want ErrNotValidated, got %v", err)
	}
}

func TestDryRunUnknownCert(t *testing.T) {
	st := proxystore.New(t.TempDir())
	p := New(st)
	raw, _ := json.Marshal(map[string]any{
		"id": "p1", "host": "app.example.fr", "type": "http",
		"tls_enabled": true, "cert_name": "missing.crt",
		"backends": []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lb":       "round_robin",
	})
	env := &proxystore.Envelope{
		ID: "p1", Revision: "r1", Host: "app.example.fr", Enabled: true, Config: raw,
	}
	if err := p.CreateRevision(env); err != nil {
		t.Fatal(err)
	}
	_, err := p.DryRun("p1", "r1", DryRunOptions{
		KnownCertNames: map[string]bool{"other": true},
	})
	if !errors.Is(err, ErrDryRunFailed) {
		t.Fatalf("want ErrDryRunFailed, got %v", err)
	}
}
