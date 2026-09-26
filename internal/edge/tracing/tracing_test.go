// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func setup(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() { otel.SetTracerProvider(prevTP); otel.SetTextMapPropagator(prevProp) })
	return rec
}

const parentTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
const parentHeader = "00-" + parentTraceID + "-00f067aa0ba902b7-01"

// La passerelle reprend la trace de l'appelant, la prolonge vers le backend et l'expose au client.
func TestTraceparentPropagatesThroughProxy(t *testing.T) {
	rec := setup(t)

	var backendTraceparent string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendTraceparent = r.Header.Get("traceparent")
	})
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, end := StartBackend(r.Context(), "backend:8080", 0)
		out := r.Clone(ctx)
		out.Header = r.Header.Clone()
		Inject(ctx, out.Header)
		backend.ServeHTTP(w, out)
		end(200, nil)
	}))

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("traceparent", parentHeader)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if got := rw.Header().Get("X-Trace-Id"); got != parentTraceID {
		t.Fatalf("X-Trace-Id = %q, want la trace de l'appelant", got)
	}
	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("attendu span backend + span serveur, got %d", len(spans))
	}
	backendSpan, serverSpan := spans[0], spans[1]
	if serverSpan.SpanKind() != trace.SpanKindServer || backendSpan.SpanKind() != trace.SpanKindClient {
		t.Fatal("kinds inattendus")
	}
	if serverSpan.Parent().SpanID().String() != "00f067aa0ba902b7" {
		t.Fatalf("le span serveur doit avoir l'appelant pour parent: %s", serverSpan.Parent().SpanID())
	}
	if backendSpan.Parent().SpanID() != serverSpan.SpanContext().SpanID() {
		t.Fatal("le span backend doit être enfant du span serveur")
	}
	wantParent := "00-" + parentTraceID + "-" + backendSpan.SpanContext().SpanID().String() + "-01"
	if backendTraceparent != wantParent {
		t.Fatalf("traceparent vers le backend = %q, want %q", backendTraceparent, wantParent)
	}
}

func TestNewTraceWithoutIncomingHeader(t *testing.T) {
	setup(t)
	rw := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rw, httptest.NewRequest("GET", "/", nil))
	if len(rw.Header().Get("X-Trace-Id")) != 32 {
		t.Fatalf("X-Trace-Id attendu, got %q", rw.Header().Get("X-Trace-Id"))
	}
}

// X-Trace-Id doit être posé avant l'écriture : un handler qui écrit tout de suite l'expose quand même.
func TestTraceIDHeaderSentWhenHandlerWritesImmediately(t *testing.T) {
	setup(t)
	rw := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("x")) //nolint:errcheck
	})).ServeHTTP(rw, httptest.NewRequest("GET", "/", nil))
	if rw.Result().Header.Get("X-Trace-Id") == "" {
		t.Fatal("X-Trace-Id absent de la réponse effectivement envoyée")
	}
}

func TestMetricsEndpointNotTraced(t *testing.T) {
	rec := setup(t)
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/metrics", nil))
	if len(rec.Ended()) != 0 {
		t.Fatal("/metrics ne doit pas produire de span")
	}
}

func TestServerErrorMarksSpanAndEvents(t *testing.T) {
	rec := setup(t)
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Event(r.Context(), "sentinel.signal")
		w.WriteHeader(http.StatusBadGateway)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	s := rec.Ended()[0]
	if s.Status().Code.String() != "Error" {
		t.Fatalf("status span: %v", s.Status())
	}
	if len(s.Events()) != 1 || s.Events()[0].Name != "sentinel.signal" {
		t.Fatalf("événement manquant: %v", s.Events())
	}
}

// Sans exporteur, un traceparent entrant reste transmis tel quel : la passerelle est transparent.
func TestInitWithoutEndpointStillPropagates(t *testing.T) {
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	defer func() { otel.SetTracerProvider(prevTP); otel.SetTextMapPropagator(prevProp) }()
	if _, err := Init("", 1); err != nil {
		t.Fatal(err)
	}
	var seen string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := http.Header{}
		Inject(r.Context(), out)
		seen = out.Get("traceparent")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("traceparent", parentHeader)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen == "" || seen[3:35] != parentTraceID {
		t.Fatalf("traceparent perdu sans exporteur: %q", seen)
	}
}

func TestInitAcceptsURLEndpoint(t *testing.T) {
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	defer func() { otel.SetTracerProvider(prevTP); otel.SetTextMapPropagator(prevProp) }()
	for _, ep := range []string{"localhost:4318", "https://collector.example:4318", "http://localhost:4318"} {
		shutdown, err := Init(ep, 0.1)
		if err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
		shutdown(t.Context()) //nolint:errcheck
	}
}
