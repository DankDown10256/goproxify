// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/logapi"
)

func TestRejectionsAreReadFromEachGateway(t *testing.T) {
	h, paris, lyon := surfaceHandler(t)
	paris.Rejections = logapi.RejectionsResponse{
		Since:   "2026-11-01T09:00:00Z",
		Reasons: map[string]int64{"unknown_sni": 40, "no_sni": 7},
		Names:   []logapi.RejectionName{{Name: "oublie.example.fr", Count: 30, Sources: 12}},
		Sources: []logapi.RejectionSource{{IP: "203.0.113.9", Count: 30, LastReason: "unknown_sni", JA4: "t13d1516h2_x"}},
		JA4:     []logapi.RejectionJA4{{JA4: "t13d1516h2_x", Count: 30}},
	}
	lyon.Rejections = logapi.RejectionsResponse{Reasons: map[string]int64{}, Names: []logapi.RejectionName{}, Sources: []logapi.RejectionSource{}, JA4: []logapi.RejectionJA4{}}

	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/rejections")
	if code != http.StatusOK {
		t.Fatalf("liste : %d %v", code, out)
	}
	gws := out["gateways"].([]any)
	if len(gws) != 2 {
		t.Fatalf("une entrée par passerelle : %v", gws)
	}
	byNode := map[string]map[string]any{}
	for _, g := range gws {
		gw := g.(map[string]any)
		byNode[gw["node_name"].(string)] = gw["rejections"].(map[string]any)
	}
	reasons := byNode["paris"]["reasons"].(map[string]any)
	if reasons["unknown_sni"] != float64(40) || reasons["no_sni"] != float64(7) {
		t.Fatalf("totaux par raison de paris : %v", reasons)
	}
	names := byNode["paris"]["names"].([]any)
	if len(names) != 1 || names[0].(map[string]any)["name"] != "oublie.example.fr" || names[0].(map[string]any)["sources"] != float64(12) {
		t.Fatalf("noms demandés : %v", names)
	}
	if len(byNode["lyon"]["reasons"].(map[string]any)) != 0 {
		t.Fatalf("lyon n'a rien refusé : %v", byNode["lyon"])
	}

	code, out = surfCall(t, h, http.MethodGet, "/api/v1/security/rejections?edge=paris")
	if gws = out["gateways"].([]any); code != http.StatusOK || len(gws) != 1 || gws[0].(map[string]any)["node_name"] != "paris" {
		t.Fatalf("edge=paris : %d %v", code, out)
	}
}

func TestRejectionsWithoutGatewayIsABadGateway(t *testing.T) {
	h, _, _ := surfaceHandler(t)
	h.Edge = nil
	if code, _ := surfCall(t, h, http.MethodGet, "/api/v1/security/rejections"); code != http.StatusBadGateway {
		t.Fatalf("sans passerelle : %d, attendu 502", code)
	}
}

func TestRejectionsCarryTheProbeSuggestions(t *testing.T) {
	h, paris, lyon := surfaceHandler(t)
	paris.Rejections = logapi.RejectionsResponse{
		Reasons: map[string]int64{"unknown_host": 12},
		Probes:  []logapi.RejectionProbe{{IP: "198.51.100.9", Hits: 40, IntervalSeconds: 30}},
	}
	lyon.Rejections = logapi.RejectionsResponse{Reasons: map[string]int64{}}

	_, out := surfCall(t, h, http.MethodGet, "/api/v1/security/rejections?edge=paris")
	gw := out["gateways"].([]any)[0].(map[string]any)["rejections"].(map[string]any)
	probes := gw["probes"].([]any)
	if len(probes) != 1 || probes[0].(map[string]any)["ip"] != "198.51.100.9" || probes[0].(map[string]any)["interval_seconds"] != float64(30) {
		t.Fatalf("les sondes probables doivent traverser l'Admin : %v", probes)
	}
}
