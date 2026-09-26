// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/router"
)

var auditSeq int

// labelRoute fait suivre des labels Docker jusqu'à la route de la passerelle (Agent → payload → passerelle).
func labelRoute(t *testing.T, extra map[string]string) *router.Route {
	t.Helper()
	auditSeq++
	host := fmt.Sprintf("audit%d.example.fr", auditSeq)
	labels := map[string]string{"goproxify.enable": "true", "goproxify.host": host}
	for k, v := range extra {
		labels[k] = v
	}
	spec := docker.ParseLabels("abcdef12345"+fmt.Sprint(auditSeq), "web", "img", "net", labels, map[string]struct{}{"80/tcp": {}}, "10.0.0.9")
	if spec == nil {
		t.Fatal("spec nil")
	}
	payload := map[string]any{
		"host": host, "backends": []string{"http://10.0.0.9:80"},
		"container_id": spec.ContainerID, "agent_name": "ag",
	}
	docker.AttachSecurityPayload(payload, spec)
	s := testEdgeServer()
	postAgentContainer(t, s, payload)
	rt, ok := s.table.ByHost(host)
	if !ok {
		t.Fatal("route absente")
	}
	return rt
}

func eq(got, want string) string {
	if got != want {
		return fmt.Sprintf("%q, attendu %q", got, want)
	}
	return ""
}

func notNil(cond bool, v any) string {
	if !cond {
		return fmt.Sprintf("%+v", v)
	}
	return ""
}

// Audit : chaque label de configuration doit produire l'effet documenté sur la route. Un label qui
// n'arrive pas à la route (clé JSON différente entre l'Agent et la passerelle) est un no-op silencieux.
func TestDockerLabelsAudit(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		check  func(rt *router.Route) string // "" = OK, sinon le défaut constaté
	}{
		{"rate_limit", map[string]string{"goproxify.rate_limit": "100/s:50"}, func(rt *router.Route) string {
			return notNil(rt.RateLimit != nil && rt.RateLimit.RequestsPerSecond == 100 && rt.RateLimit.Burst == 50, rt.RateLimit)
		}},
		{"rate_limit.rps+burst", map[string]string{"goproxify.rate_limit.rps": "20", "goproxify.rate_limit.burst": "40"}, func(rt *router.Route) string {
			return notNil(rt.RateLimit != nil && rt.RateLimit.RequestsPerSecond == 20 && rt.RateLimit.Burst == 40, rt.RateLimit)
		}},
		{"ip_filter", map[string]string{"goproxify.ip_filter": "allow:10.0.0.0/8"}, func(rt *router.Route) string {
			return notNil(rt.IPFilter != nil && rt.IPFilter.Mode == "allow" && len(rt.IPFilter.CIDRs) == 1, rt.IPFilter)
		}},
		{"cors", map[string]string{"goproxify.cors": "https://a.example.com,https://b.example.com"}, func(rt *router.Route) string {
			return notNil(rt.CORS != nil && len(rt.CORS.AllowedOrigins) == 2, rt.CORS)
		}},
		{"geo_ip", map[string]string{"goproxify.geo_ip": "allow:FR,DE"}, func(rt *router.Route) string {
			return notNil(rt.GeoIP != nil && rt.GeoIP.Mode == "allow" && len(rt.GeoIP.Countries) == 2, rt.GeoIP)
		}},
		{"snippets", map[string]string{"goproxify.snippets": "s1,s2"}, func(rt *router.Route) string {
			return notNil(len(rt.SnippetIDs) == 2, rt.SnippetIDs)
		}},
		{"auth_provider", map[string]string{"goproxify.auth_provider": "authentik-prod"}, func(rt *router.Route) string {
			return eq(rt.AuthProviderID, "authentik-prod")
		}},
		{"waf", map[string]string{
			"goproxify.waf": "block", "goproxify.waf.anomaly_threshold": "10", "goproxify.waf.max_body_mb": "12",
			"goproxify.waf.exclude_ids": "942100,941100", "goproxify.waf.behavior": "true",
			"goproxify.waf.behavior.window": "90", "goproxify.waf.behavior.threshold": "7",
			"goproxify.waf.trusted_proxies": "10.0.0.0/8",
		}, func(rt *router.Route) string {
			w := rt.WAF
			return notNil(w != nil && w.Enabled && w.Mode == "block" && w.AnomalyThreshold == 10 && w.MaxBodyMB == 12 &&
				len(w.ExcludeIDs) == 2 && w.BehaviorEnabled && w.BehaviorWindowSec == 90 && w.BehaviorThreshold == 7 &&
				len(w.TrustedProxies) == 1, w)
		}},
		{"bot", map[string]string{"goproxify.bot": "true", "goproxify.bot.mode": "block"}, func(rt *router.Route) string {
			return notNil(rt.Bot != nil && rt.Bot.Enabled && rt.Bot.Mode == "block", rt.Bot)
		}},
		{"sentinel.whitelist", map[string]string{"goproxify.sentinel.whitelist": "192.168.1.5,10.0.0.0/8"}, func(rt *router.Route) string {
			return notNil(len(rt.SentinelWhitelist) == 2, rt.SentinelWhitelist)
		}},
		{"logs", map[string]string{"goproxify.logs": "true", "goproxify.logs.format": "json", "goproxify.logs.level": "warn"}, func(rt *router.Route) string {
			return notNil(rt.Logging != nil && rt.Logging.AccessLog && rt.Logging.Format == "json" && rt.Logging.Level == "warn", rt.Logging)
		}},
		{"preserve_host", map[string]string{"goproxify.preserve_host": "true"}, func(rt *router.Route) string {
			return notNil(rt.PreserveHost != nil && *rt.PreserveHost, rt.PreserveHost)
		}},
		{"websocket", map[string]string{"goproxify.websocket": "true"}, func(rt *router.Route) string {
			return notNil(rt.Websocket != nil && *rt.Websocket, rt.Websocket)
		}},
		{"request_id", map[string]string{"goproxify.request_id": "true"}, func(rt *router.Route) string {
			return notNil(rt.RequestID != nil && *rt.RequestID, rt.RequestID)
		}},
		{"http_version", map[string]string{"goproxify.http_version": "2"}, func(rt *router.Route) string { return eq(rt.HttpVersion, "2") }},
		{"strip_prefix", map[string]string{"goproxify.strip_prefix": "/api"}, func(rt *router.Route) string { return eq(rt.StripPrefix, "/api") }},
		{"path_rewrite", map[string]string{"goproxify.path_rewrite": "/api→/v2/api"}, func(rt *router.Route) string {
			return notNil(rt.PathRewrite != "", rt.PathRewrite)
		}},
		{"timeouts", map[string]string{"goproxify.timeout.connect": "5s", "goproxify.timeout.response": "30s", "goproxify.timeout.send": "10s"}, func(rt *router.Route) string {
			return notNil(rt.ConnectTimeout.Seconds() == 5 && rt.ResponseTimeout.Seconds() == 30 && rt.SendTimeout.Seconds() == 10,
				[]any{rt.ConnectTimeout, rt.ResponseTimeout, rt.SendTimeout})
		}},
		{"max_body_size", map[string]string{"goproxify.max_body_size": "10m"}, func(rt *router.Route) string {
			return notNil(rt.MaxBodySize == 10*1024*1024, rt.MaxBodySize)
		}},
		{"sticky_cookie", map[string]string{"goproxify.sticky_cookie": "GPXSID"}, func(rt *router.Route) string { return eq(rt.StickyCookie, "GPXSID") }},
		{"retry", map[string]string{"goproxify.retry": "3:500ms"}, func(rt *router.Route) string {
			return notNil(rt.Retry != nil && rt.Retry.Attempts == 3, rt.Retry)
		}},
		{"circuit_breaker", map[string]string{"goproxify.circuit_breaker": "5:30s"}, func(rt *router.Route) string {
			return notNil(rt.CircuitBreaker != nil && rt.CircuitBreaker.Threshold == 5 && rt.CircuitBreaker.Timeout.Seconds() == 30, rt.CircuitBreaker)
		}},
		{"limit_conn", map[string]string{"goproxify.limit_conn": "25"}, func(rt *router.Route) string {
			return notNil(rt.LimitConn != nil && rt.LimitConn.MaxPerIP == 25, rt.LimitConn)
		}},
		{"backpressure", map[string]string{"goproxify.backpressure": "200:100:2s"}, func(rt *router.Route) string {
			return notNil(rt.Backpressure != nil && rt.Backpressure.MaxInflight == 200 && rt.Backpressure.QueueTimeoutMs == 2000, rt.Backpressure)
		}},
		{"slow_start", map[string]string{"goproxify.slow_start": "30s"}, func(rt *router.Route) string {
			return notNil(rt.SlowStartSec == 30, rt.SlowStartSec)
		}},
		{"headers.add", map[string]string{"goproxify.headers.add": "X-Foo:bar,X-Baz:qux"}, func(rt *router.Route) string {
			return notNil(rt.HeadersManipulation != nil && rt.HeadersManipulation.RequestSetHeader["X-Foo"] == "bar", rt.HeadersManipulation)
		}},
		{"headers.remove", map[string]string{"goproxify.headers.remove": "X-Powered-By,Server"}, func(rt *router.Route) string {
			return notNil(rt.Transform != nil && len(rt.Transform.RemoveResponseHeaders) == 2, rt.Transform)
		}},
		{"jwt", map[string]string{"goproxify.jwt": "https://idp.example.com/.well-known/jwks.json", "goproxify.jwt.issuer": "https://idp.example.com", "goproxify.jwt.audience": "my-api"}, func(rt *router.Route) string {
			return notNil(rt.JWT != nil && rt.JWT.Enabled && rt.JWT.Issuer == "https://idp.example.com" && rt.JWT.Audience == "my-api", rt.JWT)
		}},
		{"mtls", map[string]string{"goproxify.mtls": "/etc/goproxify/ca.pem"}, func(rt *router.Route) string {
			return notNil(rt.MTLS != nil && rt.MTLS.Enabled && rt.MTLS.RequireClientCert && rt.MTLS.CACertFile == "/etc/goproxify/ca.pem", rt.MTLS)
		}},
		{"cache", map[string]string{"goproxify.cache": "60s"}, func(rt *router.Route) string {
			return notNil(rt.Cache != nil && rt.Cache.Enabled, rt.Cache)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := labelRoute(t, c.labels)
			if msg := c.check(rt); msg != "" {
				t.Errorf("label sans l'effet attendu sur la route : %s", msg)
			}
		})
	}
}

// goproxify.headers.remove retire l en-tête de la réponse du backend (pas de la requête).
func TestDockerHeadersRemoveStripsResponseHeaders(t *testing.T) {
	rt := labelRoute(t, map[string]string{"goproxify.headers.remove": "X-Powered-By,Server"})
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8")
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Keep", "1")
		if r.Header.Get("X-Powered-By") != "client" {
			t.Error("la requête vers le backend ne doit pas être modifiée")
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Powered-By", "client")
	rec := httptest.NewRecorder()
	middleware.Transform(rt.Transform)(backend).ServeHTTP(rec, req)
	if rec.Header().Get("X-Powered-By") != "" || rec.Header().Get("Server") != "" {
		t.Fatalf("en-têtes de réponse non retirés : %v", rec.Header())
	}
	if rec.Header().Get("X-Keep") != "1" {
		t.Fatal("les autres en-têtes doivent rester")
	}
}
