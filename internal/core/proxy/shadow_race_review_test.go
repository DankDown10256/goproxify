// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Revue P1 #9 — Shadow ne doit pas lire le body en parallèle de la requête principale.
// À lancer avec -race (cible Makefile test-prebuild).

func TestReviewP1_ShadowDoesNotRaceRequestBody(t *testing.T) {
	var (
		mu         sync.Mutex
		mainBody   []byte
		shadowBody []byte
		shadowSeen bool
		mainDone   = make(chan struct{})
		shadowDone = make(chan struct{})
	)

	mainBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		mainBody = append([]byte(nil), b...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		close(mainDone)
	}))
	t.Cleanup(mainBackend.Close)

	shadowBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		shadowBody = append([]byte(nil), b...)
		shadowSeen = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		close(shadowDone)
	}))
	t.Cleanup(shadowBackend.Close)

	route := &router.Route{
		ID:       "shadow-race",
		Host:     "app.example.fr",
		Type:     router.RouteHTTP,
		Backends: []router.Backend{{URL: mainBackend.URL}},
		Shadow:   &router.ShadowConfig{Backend: shadowBackend.URL},
	}
	h := NewHandler(route, NewBackendHealth(slog.Default()), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())

	payload := bytes.Repeat([]byte("x"), 64*1024)
	req := httptest.NewRequest(http.MethodPost, "http://app.example.fr/upload", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	select {
	case <-mainDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout backend principal")
	}
	select {
	case <-shadowDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout backend shadow")
	}

	mu.Lock()
	defer mu.Unlock()
	if !shadowSeen {
		t.Fatal("shadow non appelé")
	}
	if !bytes.Equal(mainBody, payload) {
		t.Fatalf("body principal tronqué/corrompu: got %d want %d", len(mainBody), len(payload))
	}
	if !bytes.Equal(shadowBody, payload) {
		t.Fatalf("body shadow tronqué/corrompu: got %d want %d", len(shadowBody), len(payload))
	}
}
