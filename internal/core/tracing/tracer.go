// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Init configure le propagateur W3C et le TracerProvider global.
// Le propagateur est toujours installé : sans endpoint, un `traceparent` entrant reste transmis
// au backend (le Core est transparent pour la trace) mais rien n'est exporté.
//
// endpoint : "host:port" (OTLP/HTTP en clair) ou URL complète ("https://collector.example.com:4318").
// sampleRatio : part des nouvelles traces échantillonnées ; hors ]0,1[ = toutes.
// Une trace déjà décidée par l'appelant (bit sampled du traceparent) est respectée.
// Retourne une fonction shutdown à appeler à l'arrêt.
func Init(endpoint string, sampleRatio float64) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if endpoint == "" {
		return func(ctx context.Context) error { return nil }, nil
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure()}
	if strings.Contains(endpoint, "://") {
		opts = []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint)}
	}
	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName("goproxify-core"),
		),
	)
	if err != nil {
		res = resource.Default()
	}

	root := sdktrace.AlwaysSample()
	if sampleRatio > 0 && sampleRatio < 1 {
		root = sdktrace.TraceIDRatioBased(sampleRatio)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(root)),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}
