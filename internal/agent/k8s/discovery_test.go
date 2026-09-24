// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
)

func testDiscovery(t *testing.T, adminURL string) *Discovery {
	t.Helper()
	cfg := &config.AgentConfig{}
	cfg.Identity.NodeName = "agent-k8s"
	return &Discovery{
		cfg:         cfg,
		adminURL:    adminURL,
		authToken:   "tok",
		labelPrefix: "goproxify.",
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		client:      http.DefaultClient,
		hostByKey:   map[string]string{},
	}
}

// Les annotations d'un Ingress suivent la sémantique des labels Docker : elles atteignent le payload.
func TestUpsertIngressAnnotationsReachPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := testDiscovery(t, srv.URL)

	var ing k8sIngress
	ing.Metadata = k8sMeta{Name: "web", Namespace: "prod", Annotations: map[string]string{
		"goproxify.waf":          "block",
		"goproxify.rate_limit":   "100/s:50",
		"goproxify.limit_conn":   "25",
		"goproxify.backpressure": "200:100:2s",
		"goproxify.slow_start":   "30s",
		"goproxify.jwt":          "https://idp.example.com/jwks.json",
		"goproxify.headers.remove": "X-Powered-By",
		"other.io/ignored":       "x",
	}}
	ing.Spec.Rules = []ingressRule{{Host: "app.example.fr"}}
	ing.Spec.TLS = []ingressTLS{{Hosts: []string{"app.example.fr"}}}
	ing.Metadata.Annotations["goproxify.backend"] = "http://web.prod.svc.cluster.local:8080"
	d.upsertIngress(context.Background(), ing)

	if got == nil {
		t.Fatal("aucune route poussée")
	}
	if got["host"] != "app.example.fr" || got["tls_enabled"] != true || got["source"] != "k8s" {
		t.Fatalf("base: %v", got)
	}
	for _, key := range []string{"waf", "rate_limit", "limit_conn", "backpressure", "slow_start_sec", "jwt", "headers_remove"} {
		if got[key] == nil {
			t.Errorf("annotation non transmise au payload : %s", key)
		}
	}
	if lc, _ := got["limit_conn"].(map[string]any); lc["max_per_ip"] != float64(25) {
		t.Errorf("limit_conn = %v", got["limit_conn"])
	}
	if d.hostByKey["ing:prod/web:app.example.fr"] != "app.example.fr" {
		t.Errorf("hostByKey = %v", d.hostByKey)
	}
}

// Une annotation host en CSV (Service) donne un host principal et des alias, comme les labels Docker.
func TestUpsertServiceHostCSVAndPrefix(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := testDiscovery(t, srv.URL)
	d.labelPrefix = "gpx.example.io/"

	var svc k8sService
	svc.Metadata = k8sMeta{Name: "api", Namespace: "prod", Annotations: map[string]string{
		"gpx.example.io/host":  "api.example.fr, api2.example.fr",
		"gpx.example.io/port":  "9000",
		"gpx.example.io/cache": "60s",
	}}
	svc.Spec.ClusterIP = "10.1.2.3"
	d.upsertService(context.Background(), svc)

	if got["host"] != "api.example.fr" {
		t.Fatalf("host = %v", got["host"])
	}
	if a, _ := got["aliases"].([]any); len(a) != 1 || a[0] != "api2.example.fr" {
		t.Fatalf("aliases = %v", got["aliases"])
	}
	if b, _ := got["backends"].([]any); len(b) != 1 || b[0] != "http://10.1.2.3:9000" {
		t.Fatalf("backends = %v", got["backends"])
	}
	if got["cache"] == nil {
		t.Fatal("annotation cache (préfixe personnalisé) non transmise")
	}
}

// Une annotation ne peut pas détourner le backend ni l hôte déduits de la ressource K8s.
func TestAnnotationsCannotOverrideResourceHost(t *testing.T) {
	d := testDiscovery(t, "http://unused")
	payload, _ := d.routePayload("k", map[string]string{"goproxify.host": "evil.example.fr", "goproxify.enable": "false"},
		"real.example.fr", "http://svc:80", false)
	if payload == nil || payload["host"] != "real.example.fr" {
		t.Fatalf("payload = %v", payload)
	}
}
