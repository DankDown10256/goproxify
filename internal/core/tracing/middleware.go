// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

const tracerName = "goproxify-core"

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

// Middleware crée un span OpenTelemetry par requête et propage le TraceID.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracer := otel.Tracer(tracerName)
		ctx, span := tracer.Start(r.Context(), r.Method+" "+r.URL.Path)
		defer span.End()

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(sw, r.WithContext(ctx))

		span.SetAttributes(attribute.Int("http.status_code", sw.status))
		if sw.status >= 500 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", sw.status))
		}

		// Propager le TraceID dans la réponse
		traceID := span.SpanContext().TraceID().String()
		w.Header().Set("X-Trace-Id", traceID)
	})
}
