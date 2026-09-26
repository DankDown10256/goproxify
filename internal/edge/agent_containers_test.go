// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/docker"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func testEdgeServer() *Server {
	return &Server{
		log:   edgelog.New("error", "text", ""),
		table: &router.Table{},
	}
}

func TestHandleAgentContainerStartStoresAgentName(t *testing.T) {
	s := testEdgeServer()
	body := `{"id":"docker:abc123:app.example.fr","host":"app.example.fr","backends":["http://10.0.0.1:80"],"agent_name":"agent-alpha","container_id":"abc123def456"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.handleAgentContainerStart(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok || rt == nil {
		t.Fatal("route not stored")
	}
	if rt.AgentName != "agent-alpha" {
		t.Fatalf("AgentName = %q, want agent-alpha", rt.AgentName)
	}
	if rt.ID != "docker-host:app.example.fr" {
		t.Fatalf("ID = %q, want docker-host:app.example.fr", rt.ID)
	}
	if rt.LB != router.LBAdaptive {
		t.Fatalf("LB = %q, want adaptive", rt.LB)
	}
}

func TestHandleAgentContainerStartMergesSameHost(t *testing.T) {
	s := testEdgeServer()
	post := func(cid, backend string) {
		body := map[string]any{
			"id": "docker:" + cid[:12] + ":app.example.fr", "host": "app.example.fr",
			"backends": []string{backend}, "container_id": cid, "agent_name": "ag",
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(b))
		rr := httptest.NewRecorder()
		s.handleAgentContainerStart(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d", rr.Code)
		}
	}
	post("aaaaaaaaaaaa1111", "http://10.0.0.1:80")
	post("bbbbbbbbbbbb2222", "http://10.0.0.2:80")
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok {
		t.Fatal("missing route")
	}
	if len(rt.Backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(rt.Backends))
	}
	// stop first container
	stopBody := `{"container_id":"aaaaaaaaaaaa1111","name":"c1"}`
	req := httptest.NewRequest(http.MethodDelete, "/internal/v1/agent/containers", bytes.NewBufferString(stopBody))
	rr := httptest.NewRecorder()
	s.handleAgentContainerStop(rr, req)
	rt, ok = s.table.ByHost("app.example.fr")
	if !ok {
		t.Fatal("route should remain")
	}
	if len(rt.Backends) != 1 || rt.Backends[0].URL != "http://10.0.0.2:80" {
		t.Fatalf("backends after stop = %#v", rt.Backends)
	}
}


func TestHandleListAgentContainersFiltersByAgent(t *testing.T) {
	s := testEdgeServer()
	s.table.Upsert(&router.Route{
		ID: "docker:aaa:one.example.fr", Host: "one.example.fr",
		Backends: []router.Backend{{URL: "http://1:80"}}, AgentName: "agent-a",
	})
	s.table.Upsert(&router.Route{
		ID: "docker:bbb:two.example.fr", Host: "two.example.fr",
		Backends: []router.Backend{{URL: "http://2:80"}}, AgentName: "agent-b",
	})
	s.table.Upsert(&router.Route{
		ID: "manual-route", Host: "manual.example.fr",
		Backends: []router.Backend{{URL: "http://3:80"}},
	})

	// Sans filtre : les deux routes agent
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers", nil)
	rr := httptest.NewRecorder()
	s.handleListAgentContainers(rr, req)
	var all []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered len = %d, want 2", len(all))
	}

	// Filtre agent-a
	req = httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers?agent=agent-a", nil)
	rr = httptest.NewRecorder()
	s.handleListAgentContainers(rr, req)
	var filtered []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered len = %d, want 1", len(filtered))
	}
	if filtered[0]["agent_name"] != "agent-a" {
		t.Fatalf("agent_name = %v, want agent-a", filtered[0]["agent_name"])
	}
	if filtered[0]["host"] != "one.example.fr" {
		t.Fatalf("host = %v, want one.example.fr", filtered[0]["host"])
	}
}

func TestHandleListAgentContainersExposesConfigBadges(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "sec.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "dddddddddddd1111", "agent_name": "ag",
		"tls_enabled": true, "auth_provider_id": "oidc-1",
		"waf": map[string]any{"enabled": true, "mode": "block"},
		"rate_limit": map[string]any{"rps": 10.0, "burst": 20},
	})
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers", nil)
	rr := httptest.NewRecorder()
	s.handleListAgentContainers(rr, req)
	var all []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("len = %d, want 1", len(all))
	}
	cfg, _ := all[0]["config"].(map[string]any)
	if cfg == nil {
		t.Fatal("config missing")
	}
	// Un seul backend : pas de badge LB Adaptatif
	if _, ok := cfg["lb"]; ok {
		t.Fatalf("lb = %v, want absent for single backend", cfg["lb"])
	}
	if cfg["tls_enabled"] != true {
		t.Fatalf("tls_enabled = %v", cfg["tls_enabled"])
	}
	if cfg["auth_provider_id"] != "oidc-1" {
		t.Fatalf("auth_provider_id = %v", cfg["auth_provider_id"])
	}
	if cfg["waf"] == nil || cfg["rate_limit"] == nil {
		t.Fatalf("security fields missing: %#v", cfg)
	}
	ids, _ := all[0]["container_ids"].([]any)
	if len(ids) != 1 || ids[0] != "dddddddddddd1111" {
		t.Fatalf("container_ids = %#v, want [dddddddddddd1111]", ids)
	}
}

func TestHandleListAgentContainersLBBadgeOnlyWhenMultiBackend(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111", "agent_name": "ag",
	})
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.2:80"},
		"container_id": "bbbbbbbbbbbb2222", "agent_name": "ag",
	})
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers", nil)
	rr := httptest.NewRecorder()
	s.handleListAgentContainers(rr, req)
	var all []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("len = %d, want 1", len(all))
	}
	cfg, _ := all[0]["config"].(map[string]any)
	if cfg["lb"] != "adaptive" {
		t.Fatalf("lb = %v, want adaptive for multi-backend pool", cfg["lb"])
	}
	backends, _ := all[0]["backends"].([]any)
	if len(backends) != 2 {
		t.Fatalf("backends = %#v, want 2", backends)
	}
	ids, _ := all[0]["container_ids"].([]any)
	if len(ids) != 2 {
		t.Fatalf("container_ids = %#v, want 2", ids)
	}
}

func postAgentContainer(t *testing.T, s *Server, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	s.handleAgentContainerStart(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleAgentContainerStartCanaryOutsidePool(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111", "agent_name": "ag", "role": "normal",
	})
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.9:80"},
		"container_id": "cccccccccccc9999", "agent_name": "ag",
		"role": "canary", "canary_weight": 15,
	})
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok {
		t.Fatal("missing route")
	}
	if len(rt.Backends) != 1 || rt.Backends[0].URL != "http://10.0.0.1:80" {
		t.Fatalf("backends = %#v, want only normal", rt.Backends)
	}
	if rt.Canary == nil || rt.Canary.Backend != "http://10.0.0.9:80" {
		t.Fatalf("Canary = %#v", rt.Canary)
	}
	if rt.Canary.Weight != 15 {
		t.Fatalf("Canary.Weight = %d, want 15", rt.Canary.Weight)
	}
	if rt.Canary.ContainerID != "cccccccccccc9999" {
		t.Fatalf("Canary.ContainerID = %q", rt.Canary.ContainerID)
	}
}

func TestHandleAgentContainerStartShadowOutsidePool(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111", "role": "normal",
	})
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.8:80"},
		"container_id": "ssssssssssss8888", "role": "shadow",
	})
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok {
		t.Fatal("missing route")
	}
	if len(rt.Backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(rt.Backends))
	}
	if rt.Shadow == nil || rt.Shadow.Backend != "http://10.0.0.8:80" {
		t.Fatalf("Shadow = %#v", rt.Shadow)
	}
}

func TestHandleAgentContainerStopClearsCanary(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111", "role": "normal",
	})
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.9:80"},
		"container_id": "cccccccccccc9999", "role": "canary", "canary_weight": 10,
	})
	req := httptest.NewRequest(http.MethodDelete, "/internal/v1/agent/containers",
		bytes.NewBufferString(`{"container_id":"cccccccccccc9999","name":"canary"}`))
	rr := httptest.NewRecorder()
	s.handleAgentContainerStop(rr, req)
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok {
		t.Fatal("route should remain (normal backend)")
	}
	if rt.Canary != nil {
		t.Fatalf("Canary should be cleared, got %#v", rt.Canary)
	}
	if len(rt.Backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(rt.Backends))
	}
}

func TestHandleAgentContainerStopCanaryOnlyDeletesRoute(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.9:80"},
		"container_id": "cccccccccccc9999", "role": "canary", "canary_weight": 10,
	})
	req := httptest.NewRequest(http.MethodDelete, "/internal/v1/agent/containers",
		bytes.NewBufferString(`{"container_id":"cccccccccccc9999","name":"canary"}`))
	rr := httptest.NewRecorder()
	s.handleAgentContainerStop(rr, req)
	if _, ok := s.table.ByHost("app.example.fr"); ok {
		t.Fatal("route should be deleted when no backends and no canary/shadow")
	}
}

func TestHandleAgentContainerStartAppliesSecurityLabels(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "secure.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "sec111111111111", "agent_name": "ag",
		"rate_limit":       map[string]any{"rps": 50.0, "burst": 10},
		"ip_filter":        map[string]any{"mode": "allow", "cidrs": []string{"10.0.0.0/8"}},
		"cors":             map[string]any{"allowed_origins": []string{"https://app.example.fr"}},
		"geo_ip":           map[string]any{"mode": "allow", "countries": []string{"FR"}},
		"snippet_ids":      []string{"waf-default", "headers-secure"},
		"auth_provider_id": "authentik-prod",
		"waf":              map[string]any{"enabled": true, "mode": "block"},
		"bot":              map[string]any{"enabled": true},
	})
	rt, ok := s.table.ByHost("secure.example.fr")
	if !ok {
		t.Fatal("missing route")
	}
	if rt.RateLimit == nil || rt.RateLimit.RequestsPerSecond != 50 {
		t.Fatalf("RateLimit = %#v", rt.RateLimit)
	}
	if rt.IPFilter == nil || rt.IPFilter.Mode != "allow" || len(rt.IPFilter.CIDRs) != 1 {
		t.Fatalf("IPFilter = %#v", rt.IPFilter)
	}
	if rt.CORS == nil || len(rt.CORS.AllowedOrigins) != 1 {
		t.Fatalf("CORS = %#v", rt.CORS)
	}
	if rt.GeoIP == nil || rt.GeoIP.Mode != "allow" {
		t.Fatalf("GeoIP = %#v", rt.GeoIP)
	}
	if len(rt.SnippetIDs) != 2 || rt.AuthProviderID != "authentik-prod" {
		t.Fatalf("snippets/auth = %v / %q", rt.SnippetIDs, rt.AuthProviderID)
	}
	if rt.WAF == nil || !rt.WAF.Enabled || rt.Bot == nil || !rt.Bot.Enabled {
		t.Fatalf("WAF/Bot = %#v / %#v", rt.WAF, rt.Bot)
	}
}

func TestHandleAgentContainerStartSecurityStringLegacy(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "legacy.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "leg111111111111",
		"rate_limit":   "100/s:20",
		"ip_filter":    "deny:1.2.3.4/32",
		"geo_ip":       "deny:CN,RU",
		"cors":         "https://app.example.fr",
	})
	rt, ok := s.table.ByHost("legacy.example.fr")
	if !ok {
		t.Fatal("missing route")
	}
	if rt.RateLimit == nil || rt.RateLimit.RequestsPerSecond != 100 || rt.RateLimit.Burst != 20 {
		t.Fatalf("RateLimit = %#v", rt.RateLimit)
	}
	if rt.IPFilter == nil || rt.IPFilter.Mode != "deny" {
		t.Fatalf("IPFilter = %#v", rt.IPFilter)
	}
	if rt.GeoIP == nil || len(rt.GeoIP.Countries) != 2 {
		t.Fatalf("GeoIP = %#v", rt.GeoIP)
	}
	if rt.CORS == nil || rt.CORS.AllowedOrigins[0] != "https://app.example.fr" {
		t.Fatalf("CORS = %#v", rt.CORS)
	}
}

func TestHandleAgentContainerRelabelCanaryToNormal(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111", "role": "normal",
	})
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.9:80"},
		"container_id": "cccccccccccc9999", "role": "canary", "canary_weight": 10,
	})
	// Re-report same container as normal
	postAgentContainer(t, s, map[string]any{
		"host": "app.example.fr", "backends": []string{"http://10.0.0.9:80"},
		"container_id": "cccccccccccc9999", "role": "normal",
	})
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok {
		t.Fatal("missing route")
	}
	if rt.Canary != nil {
		t.Fatalf("Canary should be cleared after re-label, got %#v", rt.Canary)
	}
	if len(rt.Backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(rt.Backends))
	}
}

func TestHandleAgentContainerStartFoldsHostCSVAsAliases(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "https://a.example.fr/admin", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111", "agent_name": "ag",
		"aliases": []string{"b.example.fr"}, "paths": []string{"/admin"},
	})
	rt, ok := s.table.ByHost("a.example.fr")
	if !ok {
		t.Fatal("missing primary host")
	}
	if _, ok := s.table.ByHost("b.example.fr"); !ok {
		t.Fatal("alias not routed")
	}
	if rt.ID != "docker-host:a.example.fr" {
		t.Fatalf("ID = %q", rt.ID)
	}
	if len(rt.Aliases) != 1 || rt.Aliases[0] != "b.example.fr" {
		t.Fatalf("Aliases = %#v", rt.Aliases)
	}
	if len(rt.Locations) != 1 || rt.Locations[0].Path != "/admin" || !rt.Locations[0].StripPrefix {
		t.Fatalf("Locations = %#v", rt.Locations)
	}
}

func TestHandleAgentContainerStartFoldsLegacyPerHostRoutes(t *testing.T) {
	s := testEdgeServer()
	postAgentContainer(t, s, map[string]any{
		"host": "a.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111",
	})
	postAgentContainer(t, s, map[string]any{
		"host": "b.example.fr", "backends": []string{"http://10.0.0.1:80"},
		"container_id": "aaaaaaaaaaaa1111",
	})
	if s.table.Len() != 1 {
		t.Fatalf("len = %d, want 1 folded route", s.table.Len())
	}
	rt, ok := s.table.ByHost("a.example.fr")
	if !ok {
		t.Fatal("primary missing")
	}
	if _, ok := s.table.ByHost("b.example.fr"); !ok {
		t.Fatal("folded alias missing")
	}
	if _, ok := s.table.ByHost("b.example.fr"); ok && rt.ID != "docker-host:a.example.fr" {
		got, _ := s.table.ByHost("b.example.fr")
		if got.ID != rt.ID {
			t.Fatalf("alias points to %q, want %q", got.ID, rt.ID)
		}
	}
}

// Chaîne complète : labels Docker → ProxySpec → payload Agent → route de la passerelle.
func TestDockerLabelsReachRoute(t *testing.T) {
	spec := docker.ParseLabels("abcdef123456", "web", "img", "net", map[string]string{
		"goproxify.enable":       "true",
		"goproxify.host":         "labels.example.fr",
		"goproxify.limit_conn":   "25",
		"goproxify.backpressure": "200:100:2s",
		"goproxify.slow_start":   "30s",
	}, map[string]struct{}{"80/tcp": {}}, "10.0.0.9")
	if spec == nil {
		t.Fatal("spec nil")
	}
	payload := map[string]any{
		"host": "labels.example.fr", "backends": []string{"http://10.0.0.9:80"},
		"container_id": "abcdef123456", "agent_name": "ag",
	}
	docker.AttachSecurityPayload(payload, spec)

	s := testEdgeServer()
	postAgentContainer(t, s, payload)
	rt, ok := s.table.ByHost("labels.example.fr")
	if !ok {
		t.Fatal("route absente")
	}
	if rt.LimitConn == nil || rt.LimitConn.MaxPerIP != 25 {
		t.Fatalf("limit_conn = %+v, want max_per_ip 25", rt.LimitConn)
	}
	if bp := rt.Backpressure; bp == nil || bp.MaxInflight != 200 || bp.Queue != 100 || bp.QueueTimeoutMs != 2000 {
		t.Fatalf("backpressure = %+v", bp)
	}
	if rt.SlowStartSec != 30 {
		t.Fatalf("slow_start_sec = %d", rt.SlowStartSec)
	}
}
