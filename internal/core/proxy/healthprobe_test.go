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

	"github.com/vincamok/goproxify/internal/core/router"
)

// Un backend sans endpoint /health répond 404 : il sert du trafic, il est up.
func TestProbeMissingHealthEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if !probe(srv.URL) {
		t.Fatal("un backend qui répond 404 sur /health doit être up")
	}
}

// Catch-all qui répond 500 sur les routes inconnues : le backend fonctionne.
func TestProbeCatchAll500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if !probe(srv.URL) {
		t.Fatal("un 500 sur une route inconnue ne doit pas sortir le backend du pool")
	}
}

// 503 = indisponibilité signalée explicitement par le backend.
func TestProbeExplicitUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if probe(srv.URL) {
		t.Fatal("503 doit marquer le backend down")
	}
}

// Backend HTTPS auto-signé : la sonde ne valide pas le certificat.
func TestProbeSelfSignedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if !probe(srv.URL) {
		t.Fatal("un certificat auto-signé ne doit pas marquer le backend down")
	}
}

// Backend L4 (« host:port » sans schéma) : testé par dial TCP, pas par HTTP.
func TestProbeL4Backend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if !probe(ln.Addr().String()) {
		t.Fatalf("backend L4 %s doit être up", ln.Addr())
	}
}

// Un service TCP qui ne parle pas HTTP reste up grâce au repli dial.
func TestProbeNonHTTPService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("+OK ready\r\n")) //nolint:errcheck
			c.Close()
		}
	}()

	if !probe("http://" + ln.Addr().String()) {
		t.Fatal("repli TCP attendu quand le backend ne répond pas en HTTP")
	}
}

// Port fermé : réellement down.
func TestProbeDeadBackend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if probe("http://" + addr) {
		t.Fatal("port fermé doit être down")
	}
	if probe(addr) {
		t.Fatal("port fermé (L4) doit être down")
	}
}

// Régression : un pool entièrement marqué down par la sonde ne doit pas
// produire un 502 sans même tenter le backend.
func TestServeHTTPFailsOpenWhenAllUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer srv.Close()

	route := &router.Route{
		Host:     "app.test",
		LB:       router.LBRoundRobin,
		Backends: []router.Backend{{URL: srv.URL}},
	}

	health := NewBackendHealth(slog.Default())
	health.mu.Lock()
	health.getOrCreateLocked(srv.URL).healthy = false
	health.mu.Unlock()

	h := NewHandler(route, health, NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open sur backend joignable)", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body = %q", rr.Body.String())
	}
}
