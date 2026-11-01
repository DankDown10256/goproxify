// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

func decoyGateway(t *testing.T, mode string, routes ...*router.Route) *Server {
	t.Helper()
	s := newEphorGateway(t, t.TempDir(), routes...)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	s.surface = surface.NewCollector(surface.Options{})
	s.threatEngine.SetDecoyGuard(s.decoyIsLegit)
	s.threatEngine.UpdateConfig(threat.Config{Enabled: true, Mode: "block", Decoys: threat.DecoyConfig{Mode: mode}})
	return s
}

func decoyRequest(s *Server, host, ip, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	s.dispatch(rec, req)
	return rec
}

func TestDecoyIsLegit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "app", Host: "app.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		Locations: []router.Location{{Path: "/.git/"}, {Path: "/"}}}
	plain := &router.Route{ID: "plain", Host: "plain.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}}
	s := decoyGateway(t, threat.DecoyBlock, route, plain)

	// Le profil appris de « plain » a vu servir /backup.sql à un client propre.
	r := httptest.NewRequest(http.MethodGet, "http://plain.example.test/backup.sql", nil)
	r.ContentLength = -1
	s.surface.Observe(surface.Observed{Route: "plain", Host: "plain.example.test", Request: r, Path: "/backup.sql", IP: "10.0.0.1", Status: 200, ResponseType: "text/plain", Clean: true})

	for name, tc := range map[string]struct {
		host, path string
		want       bool
	}{
		"hôte sans route":                      {"inconnu.test", "/.git/config", false},
		"route sans rien de déclaré":           {"plain.example.test", "/.git/config", false},
		"location déclarée sur le préfixe":     {"app.example.test:443", "/.git/config", true},
		"la location racine ne protège pas":    {"app.example.test", "/backup.sql", false},
		"chemin vu servi par le profil appris": {"plain.example.test", "/backup.sql", true},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+tc.path, nil)
		if got := s.decoyIsLegit(req); got != tc.want {
			t.Errorf("%s : %v, attendu %v", name, got, tc.want)
		}
	}
}

func TestDecoyThroughTheDispatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "app", Host: "app.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		Locations: []router.Location{{Path: "/.git/"}}}
	s := decoyGateway(t, threat.DecoyBlock, route)

	if rec := decoyRequest(s, "inconnu.test", "203.0.113.70", "/.git/config"); rec.Code != http.StatusForbidden {
		t.Fatalf("un scanner qui frappe un leurre sur un hôte inconnu est refusé : %d", rec.Code)
	}
	if rec := decoyRequest(s, "app.example.test", "203.0.113.71", "/.git/config"); rec.Code != http.StatusOK {
		t.Fatalf("une route qui déclare ce chemin le sert : %d", rec.Code)
	}
	if rec := decoyRequest(s, "app.example.test", "203.0.113.72", "/dump.sql"); rec.Code != http.StatusForbidden {
		t.Fatalf("un leurre que la route n'utilise pas reste un piège : %d", rec.Code)
	}
}
