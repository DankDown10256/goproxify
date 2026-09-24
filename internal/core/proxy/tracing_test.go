// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/core/tracing"
)

// Un traceparent entrant traverse le vrai reverse proxy : le backend reçoit la même trace,
// avec le span de l'appel backend pour parent.
func TestTraceparentReachesBackendThroughHandler(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prevTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(prevTP)
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	shutdown, err := tracing.Init("", 1) // installe le propagateur W3C, sans exporteur
	if err != nil {
		t.Fatal(err)
	}
	defer shutdown(t.Context()) //nolint:errcheck
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))

	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("traceparent")
	}))
	defer backend.Close()

	route := &router.Route{ID: "r", Host: "t.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}}
	h := tracing.Middleware(NewHandler(route, NewBackendHealth(slog.Default()), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default()))

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "t.test"
	req.Header.Set("traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	var backendSpanID string
	for _, s := range rec.Ended() {
		if s.SpanKind().String() == "client" {
			backendSpanID = s.SpanContext().SpanID().String()
		}
	}
	if backendSpanID == "" {
		t.Fatal("span client vers le backend absent")
	}
	if want := "00-" + traceID + "-" + backendSpanID + "-01"; got != want {
		t.Fatalf("traceparent reçu par le backend = %q, want %q", got, want)
	}
}
