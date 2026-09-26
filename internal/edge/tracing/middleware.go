// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "goproxify-edge"

// statusWriter capture le code HTTP pour l'enregistrer dans le span.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

// Middleware crée un span serveur par requête. Il reprend la trace d'un `traceparent` entrant
// (W3C Trace Context) et expose le TraceID au client dans X-Trace-Id.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Le scrape Prometheus ne doit pas noyer les traces.
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer(tracerName).Start(ctx, r.Method+" "+r.URL.Path,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
				attribute.String("server.address", r.Host),
			))
		defer span.End()

		// Avant next : les en-têtes sont figés dès la première écriture de la réponse.
		if sc := span.SpanContext(); sc.IsValid() {
			w.Header().Set("X-Trace-Id", sc.TraceID().String())
		}

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))

		span.SetAttributes(
			attribute.Int("http.response.status_code", sw.status),
			attribute.Int("http.status_code", sw.status),
		)
		if sw.status >= 500 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", sw.status))
		}
	})
}

// Inject écrit le contexte de trace courant dans les en-têtes d'une requête sortante (`traceparent`).
func Inject(ctx context.Context, h http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(h))
}

// StartBackend ouvre un span client pour un appel vers un backend. Le contexte retourné doit
// être celui de la requête sortante (pour Inject) ; end clôt le span avec le résultat.
func StartBackend(ctx context.Context, backendHost string, attempt int) (context.Context, func(status int, err error)) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "proxy "+backendHost,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("server.address", backendHost),
			attribute.Int("gpx.backend.attempt", attempt),
		))
	return ctx, func(status int, err error) {
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else if status >= 500 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", status))
		}
		span.End()
	}
}

// Annotate ajoute des attributs au span courant (no-op sans span).
func Annotate(ctx context.Context, kv ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).SetAttributes(kv...)
}

// Event enregistre un événement daté sur le span courant (no-op sans span).
func Event(ctx context.Context, name string, kv ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).AddEvent(name, trace.WithAttributes(kv...))
}
