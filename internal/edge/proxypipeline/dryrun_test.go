// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"encoding/json"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestValidateBackendURLHTTP(t *testing.T) {
	if err := validateBackendURL(router.RouteHTTP, "http://10.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := validateBackendURL(router.RouteHTTP, "not-a-url"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateBackendURLL4(t *testing.T) {
	if err := validateBackendURL(router.RouteTCP, "10.0.0.5:5432"); err != nil {
		t.Fatal(err)
	}
	if err := validateBackendURL(router.RouteTCP, "10.0.0.5"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunDryRunTCPListenPortConflict(t *testing.T) {
	peerCfg, _ := json.Marshal(map[string]any{
		"id": "a", "type": "tcp", "listen_port": 5432,
		"backends": []map[string]any{{"url": "10.0.0.1:5432", "weight": 1}},
		"lb":       "round_robin",
	})
	candCfg, _ := json.Marshal(map[string]any{
		"id": "b", "type": "tcp", "listen_port": 5432,
		"backends": []map[string]any{{"url": "10.0.0.2:5432", "weight": 1}},
		"lb":       "round_robin",
	})
	peer := &proxystore.Envelope{ID: "a", Status: proxystore.StatusProduction, Config: peerCfg}
	cand := &proxystore.Envelope{ID: "b", Revision: "r1", Status: proxystore.StatusPending, Config: candCfg}
	res := RunDryRun(cand, []*proxystore.Envelope{peer}, DryRunOptions{})
	if res.OK {
		t.Fatalf("expected conflict, errors=%v", res.Errors)
	}
}

func TestRunDryRunAcceptsHTTPSType(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"id": "p1", "host": "auth.example.fr", "type": "https",
		"tls_enabled": true,
		"backends":    []map[string]any{{"url": "http://127.0.0.1:1411", "weight": 1}},
		"lb":          "round_robin",
	})
	cand := &proxystore.Envelope{ID: "p1", Revision: "r1", Host: "auth.example.fr", Status: proxystore.StatusPending, Config: cfg}
	res := RunDryRun(cand, nil, DryRunOptions{})
	if !res.OK {
		t.Fatalf("https alias should pass, errors=%v", res.Errors)
	}
}

func TestRunDryRunTCPAndUDPSamePortOK(t *testing.T) {
	tcpCfg, _ := json.Marshal(map[string]any{
		"id": "tcp", "host": "Minecraft", "type": "tcp", "listen_port": 25565,
		"backends": []map[string]any{{"url": "203.0.113.10:25565", "weight": 1}},
		"lb":       "round_robin",
	})
	udpCfg, _ := json.Marshal(map[string]any{
		"id": "udp", "host": "Minecraft", "type": "udp", "listen_port": 25565,
		"backends": []map[string]any{{"url": "203.0.113.10:25566", "weight": 1}},
		"lb":       "round_robin",
	})
	peer := &proxystore.Envelope{ID: "tcp", Status: proxystore.StatusProduction, Config: tcpCfg}
	cand := &proxystore.Envelope{ID: "udp", Revision: "r1", Status: proxystore.StatusPending, Config: udpCfg}
	res := RunDryRun(cand, []*proxystore.Envelope{peer}, DryRunOptions{})
	if !res.OK {
		t.Fatalf("tcp+udp same port should pass, errors=%v", res.Errors)
	}
}

func TestRewriteHTTPSTypeInConfig(t *testing.T) {
	in := []byte(`{"host":"auth.example.fr","type":"https","tls_enabled":true,"extra":1}`)
	out := rewriteHTTPSTypeInConfig(in)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "http" {
		t.Fatalf("type=%v", m["type"])
	}
	if m["tls_enabled"] != true {
		t.Fatalf("tls_enabled=%v", m["tls_enabled"])
	}
	if m["extra"] != float64(1) {
		t.Fatalf("extra field lost: %v", m["extra"])
	}
}
