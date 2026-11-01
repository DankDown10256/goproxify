// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf"
)

// hostLabelsWithPrefix liste les valeurs de l'étiquette `host` qui commencent par prefix, toutes métriques confondues.
func hostLabelsWithPrefix(t *testing.T, prefix string) []string {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "host" && strings.HasPrefix(lp.GetValue(), prefix) {
					out = append(out, mf.GetName()+"{host="+lp.GetValue()+"}")
				}
			}
		}
	}
	return out
}

// Un wildcard sert une infinité de sous-domaines : le nom que le client écrit dans Host ne doit jamais devenir une
// étiquette, sans quoi la mémoire de la passerelle croît à chaque nom inventé.
func TestWildcardRouteMetricsStayBounded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "wild", Host: "*.wildlabel.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		WAF: &router.WAFConfig{Enabled: true, Mode: "detect"}}
	exact := &router.Route{ID: "exact", Host: "app.wildlabel.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}}
	s := newEphorGateway(t, t.TempDir(), route, exact)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	s.wafEngine = waf.NewEngine(&router.WAFConfig{Enabled: true, Mode: "detect"}, s.log.Logger())

	get := func(host string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		req.RemoteAddr = "198.51.100.9:4000"
		rec := httptest.NewRecorder()
		s.dispatch(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : statut %d", host, rec.Code)
		}
	}
	const n = 30
	for i := 0; i < n; i++ {
		get(fmt.Sprintf("rnd%d.wildlabel.test", i))
	}
	get("app.wildlabel.test")

	for _, series := range hostLabelsWithPrefix(t, "rnd") {
		t.Errorf("série créée pour un nom choisi par le client : %s", series)
	}
	if got := testutil.ToFloat64(metrics.Edge.RequestsTotal.WithLabelValues("*.wildlabel.test", http.MethodGet, "200")); got != n {
		t.Errorf("requêtes comptées sous le wildcard : %v, attendu %d", got, n)
	}
	if got := testutil.ToFloat64(metrics.Edge.RequestsTotal.WithLabelValues("app.wildlabel.test", http.MethodGet, "200")); got != 1 {
		t.Errorf("un nom exact garde sa propre étiquette : %v, attendu 1", got)
	}
}
