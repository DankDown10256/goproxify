// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/seasonal"
)

func TestTrafficReferenceIsReadFromEachGateway(t *testing.T) {
	h, paris, lyon := surfaceHandler(t)
	paris.Seasonal = logapi.SeasonalResponse{
		Mode:   "detect",
		Routes: []seasonal.RouteStatus{{Route: "app.example.fr", Warm: true, Level: "warning", RPS: 240, Expected: 12, Upper: 60}},
		Active: []seasonal.Event{{Route: "app.example.fr", Kind: "active", Level: "warning", RPS: 240, Expected: 12}},
		Events: []seasonal.Event{},
	}
	lyon.Seasonal = logapi.SeasonalResponse{Mode: "off", Routes: []seasonal.RouteStatus{}, Active: []seasonal.Event{}, Events: []seasonal.Event{}}

	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/traffic-reference")
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
		byNode[gw["node_name"].(string)] = gw["traffic"].(map[string]any)
	}
	routes := byNode["paris"]["routes"].([]any)
	if byNode["paris"]["mode"] != "detect" || len(routes) != 1 || routes[0].(map[string]any)["level"] != "warning" || routes[0].(map[string]any)["expected"] != float64(12) {
		t.Fatalf("référence de paris : %v", byNode["paris"])
	}
	if len(byNode["lyon"]["routes"].([]any)) != 0 || byNode["lyon"]["mode"] != "off" {
		t.Fatalf("lyon n'apprend rien : %v", byNode["lyon"])
	}

	code, out = surfCall(t, h, http.MethodGet, "/api/v1/security/traffic-reference?edge=lyon")
	if gws = out["gateways"].([]any); code != http.StatusOK || len(gws) != 1 || gws[0].(map[string]any)["node_name"] != "lyon" {
		t.Fatalf("edge=lyon : %d %v", code, out)
	}
}

func TestTrafficReferenceWithoutGatewayIsABadGateway(t *testing.T) {
	h, _, _ := surfaceHandler(t)
	h.Edge = nil
	if code, _ := surfCall(t, h, http.MethodGet, "/api/v1/security/traffic-reference"); code != http.StatusBadGateway {
		t.Fatalf("sans passerelle : %d, attendu 502", code)
	}
}
