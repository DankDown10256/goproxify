// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// IPFilter retourne un middleware de filtrage IP par CIDR.
// Une liste vide désactive le filtre ; un mode autre que allow/deny alors qu'une liste est
// configurée refuse tout (fail-closed) : le filtre ne doit jamais s'ouvrir sur une faute de frappe.
func IPFilter(cfg *router.IPFilterConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || len(cfg.CIDRs) == 0 {
			return next
		}
		mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
		nets := parseCIDRs(cfg.CIDRs)
		if len(nets) < len(cfg.CIDRs) {
			slog.Warn("ipfilter: entrées CIDR invalides ignorées", "configurées", len(cfg.CIDRs), "valides", len(nets))
		}
		if mode != "allow" && mode != "deny" {
			slog.Error("ipfilter: mode inconnu, accès refusé", "mode", cfg.Mode)
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "ipfilter", "invalid_mode").Inc()
				http.Error(w, "403 Forbidden", http.StatusForbidden)
			})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := net.ParseIP(clientIP(r))
			matched := matchAny(ip, nets)
			if mode == "allow" && !matched {
				metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "ipfilter", "not_in_allowlist").Inc()
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			if mode == "deny" && matched {
				metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "ipfilter", "in_denylist").Inc()
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if !strings.Contains(c, "/") {
			// IP seule → normalise en /32 ou /128
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c = c + "/32"
				} else {
					c = c + "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func matchAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
