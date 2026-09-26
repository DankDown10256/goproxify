// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func blockingHandler(entered chan struct{}, release chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func get() *http.Request { return httptest.NewRequest("GET", "/", nil) }

func TestBackpressure_DisabledPassesThrough(t *testing.T) {
	h := Backpressure("h", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if rec := serve(h, get()); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestBackpressure_RejectsWhenQueueFull(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	h := Backpressure("bp-full", &router.BackpressureConfig{MaxInflight: 1})(blockingHandler(entered, release))

	done := make(chan int)
	go func() { done <- serve(h, get()).Code }()
	<-entered

	rec := serve(h, get())
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 503 + Retry-After, got %d", rec.Code)
	}
	close(release)
	if c := <-done; c != http.StatusOK {
		t.Fatalf("first request: %d", c)
	}
}

func TestBackpressure_QueuedRequestServedWhenSlotFrees(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	h := Backpressure("bp-queue", &router.BackpressureConfig{MaxInflight: 1, Queue: 1, QueueTimeoutMs: 2000})(blockingHandler(entered, release))

	first, second := make(chan int), make(chan int)
	go func() { first <- serve(h, get()).Code }()
	<-entered
	go func() { second <- serve(h, get()).Code }()
	time.Sleep(50 * time.Millisecond)

	release <- struct{}{}
	<-entered
	close(release)
	if a, b := <-first, <-second; a != http.StatusOK || b != http.StatusOK {
		t.Fatalf("got %d, %d", a, b)
	}
}

func TestBackpressure_QueueTimeout(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	h := Backpressure("bp-timeout", &router.BackpressureConfig{MaxInflight: 1, Queue: 1, QueueTimeoutMs: 50})(blockingHandler(entered, release))

	done := make(chan int)
	go func() { done <- serve(h, get()).Code }()
	<-entered

	if rec := serve(h, get()); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after queue timeout, got %d", rec.Code)
	}
	close(release)
	<-done
}

func TestBackpressure_WebsocketBypass(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	h := Backpressure("bp-ws", &router.BackpressureConfig{MaxInflight: 1})(blockingHandler(entered, release))

	done := make(chan int, 2)
	go func() { done <- serve(h, get()).Code }()
	<-entered

	ws := get()
	ws.Header.Set("Upgrade", "websocket")
	go func() { done <- serve(h, ws).Code }()
	<-entered
	close(release)
	<-done
	<-done
}
