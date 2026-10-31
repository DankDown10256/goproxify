// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/grpctrans"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/proxyproto"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/waf"
)

// DryRunOptions configures optional checks (certs/snippets existence).
type DryRunOptions struct {
	// KnownCertNames: if non-nil, cert_name must be empty or listed.
	KnownCertNames map[string]bool
	// KnownSnippetIDs: if non-nil, snippet_ids must be subset.
	KnownSnippetIDs map[string]bool
	// KnownAuthProviders: if non-nil, auth_provider_id must be empty or listed.
	KnownAuthProviders map[string]bool
	// KnownPlugins: if non-nil, route.plugins must reference an installed plugin whose configuration
	// satisfies its manifest.
	KnownPlugins map[string]plugins.Manifest
}

// RunDryRun validates env against peers (other prod + validated revisions).
func RunDryRun(env *proxystore.Envelope, peers []*proxystore.Envelope, opts DryRunOptions) proxystore.DryRunResult {
	now := time.Now().UTC()
	errs := make([]string, 0)

	route, err := ParseRoute(env)
	if err != nil {
		return proxystore.DryRunResult{OK: false, CheckedAt: &now, Errors: []string{err.Error()}}
	}

	errs = append(errs, validateRouteBasics(route)...)
	errs = append(errs, validateConflicts(route, peers)...)
	errs = append(errs, validateRefs(route, opts)...)

	ok := len(errs) == 0
	return proxystore.DryRunResult{OK: ok, CheckedAt: &now, Errors: errs}
}

func validateRouteBasics(route *router.Route) []string {
	errs := make([]string, 0)
	if route.Type == "" {
		route.Type = router.RouteHTTP
	}
	switch route.Type {
	case router.RouteHTTP, router.RouteTCP, router.RouteUDP, "https":
	default:
		errs = append(errs, fmt.Sprintf("type invalide %q", route.Type))
	}

	if isHTTPRoute(route.Type) && strings.TrimSpace(route.Host) == "" {
		errs = append(errs, "host requis pour type http")
	}
	if routeIsL4(route.Type) && route.ListenPort <= 0 {
		errs = append(errs, "listen_port requis pour tcp/udp")
	}
	if !proxyproto.ValidVersion(route.ProxyProtocol) {
		errs = append(errs, fmt.Sprintf("proxy_protocol invalide %q (v1 ou v2)", route.ProxyProtocol))
	}
	errs = append(errs, middleware.ValidateRouteDetectors(route)...)
	if st := route.Static; st != nil && st.Enabled {
		if strings.TrimSpace(st.Root) == "" {
			errs = append(errs, "static.root requis")
		}
		if st.CacheMaxAge < 0 {
			errs = append(errs, "static.cache_max_age doit être positif")
		}
	} else if len(route.Backends) == 0 {
		errs = append(errs, "au moins un backend requis")
	}
	for i, b := range route.Backends {
		if strings.TrimSpace(b.URL) == "" {
			errs = append(errs, fmt.Sprintf("backends[%d].url vide", i))
			continue
		}
		if err := validateBackendURL(route.Type, b.URL); err != nil {
			errs = append(errs, fmt.Sprintf("backends[%d]: %v", i, err))
		}
	}
	errs = append(errs, validateTrafficSettings(route)...)
	errs = append(errs, middleware.ValidateRequestSchemaConfig(route.RequestSchema)...)
	errs = append(errs, middleware.ValidateOpenAPIConfig(route.OpenAPI)...)
	errs = append(errs, waf.ValidateConfig(route.WAF)...)
	if route.Surface != nil {
		if err := surface.ValidateMode(route.Surface.Mode); err != nil {
			errs = append(errs, err.Error())
		}
		if err := surface.ValidateType(route.Surface.Type); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if gerrs, _ := grpctrans.Validate(route.GRPCTranscode); len(gerrs) > 0 {
		errs = append(errs, gerrs...)
	}
	if route.Canary != nil && route.Canary.Backend != "" {
		if err := validateBackendURL(route.Type, route.Canary.Backend); err != nil {
			errs = append(errs, fmt.Sprintf("canary.backend: %v", err))
		}
		if route.Canary.Weight < 0 || route.Canary.Weight > 100 {
			errs = append(errs, "canary.weight doit être dans [0,100]")
		}
	}
	if route.Shadow != nil && route.Shadow.Backend != "" {
		if err := validateBackendURL(route.Type, route.Shadow.Backend); err != nil {
			errs = append(errs, fmt.Sprintf("shadow.backend: %v", err))
		}
	}
	return errs
}

func validateBackendURL(t router.RouteType, raw string) error {
	raw = strings.TrimSpace(raw)
	if t == router.RouteTCP || routeIsL4(t) {
		// Accept host:port without scheme.
		if !strings.Contains(raw, "://") {
			if !strings.Contains(raw, ":") {
				return fmt.Errorf("URL L4 attend host:port")
			}
			return nil
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("URL invalide %q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "tcp", "udp":
		return nil
	default:
		return fmt.Errorf("schéma non supporté %q", u.Scheme)
	}
}

func routeIsL4(t router.RouteType) bool {
	return t == router.RouteTCP || t == router.RouteUDP
}

func isHTTPRoute(t router.RouteType) bool {
	switch strings.ToLower(string(t)) {
	case string(router.RouteHTTP), "https":
		return true
	default:
		return false
	}
}

func validateConflicts(route *router.Route, peers []*proxystore.Envelope) []string {
	errs := make([]string, 0)
	host := strings.ToLower(strings.TrimSpace(route.Host))
	aliases := map[string]bool{}
	for _, a := range route.Aliases {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			aliases[a] = true
		}
	}

	for _, peer := range peers {
		pr, err := ParseRoute(peer)
		if err != nil {
			continue
		}
		peerHost := strings.ToLower(strings.TrimSpace(pr.Host))
		// L'unicité de host/alias ne s'applique qu'aux routes HTTP(S).
		// Les flux L4 réutilisent souvent un libellé (ex. "Minecraft" TCP+UDP).
		if isHTTPRoute(route.Type) && isHTTPRoute(pr.Type) {
			if host != "" && peerHost != "" && host == peerHost {
				errs = append(errs, fmt.Sprintf("conflit host %q avec proxy %s", host, peer.ID))
			}
			if host != "" {
				for _, a := range pr.Aliases {
					if strings.ToLower(strings.TrimSpace(a)) == host {
						errs = append(errs, fmt.Sprintf("host %q déjà alias du proxy %s", host, peer.ID))
					}
				}
			}
			for a := range aliases {
				if a == peerHost {
					errs = append(errs, fmt.Sprintf("alias %q entre en conflit avec host du proxy %s", a, peer.ID))
				}
				for _, pa := range pr.Aliases {
					if strings.ToLower(strings.TrimSpace(a)) == strings.ToLower(strings.TrimSpace(pa)) {
						errs = append(errs, fmt.Sprintf("alias %q déjà utilisé par proxy %s", a, peer.ID))
					}
				}
			}
		}
		// TCP et UDP peuvent partager le même port (Minecraft 25565).
		if route.ListenPort > 0 && pr.ListenPort > 0 && route.ListenPort == pr.ListenPort &&
			routeIsL4(route.Type) && route.Type == pr.Type {
			errs = append(errs, fmt.Sprintf("conflit listen_port %d avec proxy %s", route.ListenPort, peer.ID))
		}
	}
	return errs
}

func validateRefs(route *router.Route, opts DryRunOptions) []string {
	errs := make([]string, 0)
	if opts.KnownCertNames != nil && route.TLSEnabled && route.CertName != "" {
		if !opts.KnownCertNames[route.CertName] {
			errs = append(errs, fmt.Sprintf("cert_name inconnu %q", route.CertName))
		}
	}
	if opts.KnownSnippetIDs != nil {
		for _, sid := range route.SnippetIDs {
			if !opts.KnownSnippetIDs[sid] {
				errs = append(errs, fmt.Sprintf("snippet_id inconnu %q", sid))
			}
		}
	}
	errs = append(errs, validatePlugins(route, opts)...)
	if opts.KnownAuthProviders != nil && route.AuthProviderID != "" {
		if !opts.KnownAuthProviders[route.AuthProviderID] {
			errs = append(errs, fmt.Sprintf("auth_provider_id inconnu %q", route.AuthProviderID))
		}
	}
	return errs
}

// maxBackendWeight borne le poids d'un backend : la somme des poids sert de modulo à l'algorithme pondéré, et une
// somme qui déborde donnerait un diviseur nul ou négatif.
const maxBackendWeight = 1_000_000

// validateTrafficSettings contrôle la répartition de charge, les sondes, les relances et le disjoncteur. Une valeur
// inconnue ou négative n'échouait pas : l'algorithme retombait en silence sur le tourniquet (une faute de frappe
// dans « lb » faisait perdre la pondération) et les durées négatives étaient remplacées par les valeurs par défaut.
func validateTrafficSettings(route *router.Route) []string {
	var errs []string
	switch route.LB {
	case "", router.LBRoundRobin, router.LBWeighted, router.LBAdaptive:
	default:
		errs = append(errs, fmt.Sprintf("lb invalide %q (round_robin, weighted ou adaptive)", route.LB))
	}
	for i, b := range route.Backends {
		if b.Weight < 0 || b.Weight > maxBackendWeight {
			errs = append(errs, fmt.Sprintf("backends[%d].weight doit être dans [0,%d]", i, maxBackendWeight))
		}
	}
	if route.IdleTimeoutSec < 0 || route.IdleTimeoutSec > 86400 {
		errs = append(errs, "idle_timeout_sec doit être dans [0,86400]")
	}
	if hc := route.HealthCheck; hc != nil {
		if hc.Path != "" && !strings.HasPrefix(hc.Path, "/") {
			errs = append(errs, "health_check.path doit commencer par /")
		}
		if hc.Interval < 0 || hc.Timeout < 0 {
			errs = append(errs, "health_check : interval et timeout ne peuvent pas être négatifs")
		}
		if hc.HealthyThreshold < 0 || hc.UnhealthyThreshold < 0 {
			errs = append(errs, "health_check : les seuils ne peuvent pas être négatifs")
		}
	}
	if rt := route.Retry; rt != nil && (rt.InitialWait < 0 || rt.MaxWait < 0) {
		errs = append(errs, "retry : initial_wait et max_wait ne peuvent pas être négatifs")
	}
	if cb := route.CircuitBreaker; cb != nil && (cb.Threshold < 0 || cb.Timeout < 0) {
		errs = append(errs, "circuit_breaker : threshold et timeout ne peuvent pas être négatifs")
	}
	return errs
}
