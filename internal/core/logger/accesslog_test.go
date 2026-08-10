// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestStripHostPort(t *testing.T) {
	cases := map[string]string{
		"example.com":          "example.com",
		"example.com:443":      "example.com",
		"127.0.0.1:8080":       "127.0.0.1",
		"[2001:db8::1]:443":    "2001:db8::1",
		"[2001:db8::1]":        "2001:db8::1",
	}
	for in, want := range cases {
		if got := stripHostPort(in); got != want {
			t.Errorf("stripHostPort(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAccessLoggerForwarder(t *testing.T) {
	al := NewAccessLogger("")
	var (
		mu   sync.Mutex
		got  []ShipEntry
		done = make(chan struct{})
	)
	al.SetForwarder(func(batch []ShipEntry) {
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		select {
		case <-done:
		default:
			close(done)
		}
	})

	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com:443/api/ping", nil)
	req.Host = "app.example.com:443"
	req.Header.Set("Referer", "https://ref.example/")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for forwarder flush")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("expected at least one shipped entry")
	}
	e := got[0]
	if e.Domain != "app.example.com" {
		t.Errorf("domain=%q want app.example.com", e.Domain)
	}
	if e.Status != 200 {
		t.Errorf("status=%d want 200", e.Status)
	}
	if e.Component != "core" {
		t.Errorf("component=%q want core", e.Component)
	}
	if e.Path != "/api/ping" {
		t.Errorf("path=%q want /api/ping", e.Path)
	}
	if e.Referrer != "https://ref.example/" {
		t.Errorf("referrer=%q", e.Referrer)
	}
}

func TestAccessLoggerSkipsInternal(t *testing.T) {
	al := NewAccessLogger("")
	var got int
	al.SetForwarder(func(batch []ShipEntry) {
		got += len(batch)
	})
	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://core/internal/v1/health", nil)
	req.Host = "core"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	time.Sleep(200 * time.Millisecond)
	if got != 0 {
		t.Errorf("internal path should not ship, got %d", got)
	}
}
