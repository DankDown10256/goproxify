// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net"
	"net/http"

	"github.com/vincamok/goproxify/internal/core/router"
)

// IPFilter retourne un middleware de filtrage IP par CIDR.
func IPFilter(cfg *router.IPFilterConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || len(cfg.CIDRs) == 0 {
			return next
		}
		nets := parseCIDRs(cfg.CIDRs)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := net.ParseIP(clientIP(r))
			matched := matchAny(ip, nets)
			if cfg.Mode == "allow" && !matched {
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			if cfg.Mode == "deny" && matched {
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
		_, n, err := net.ParseCIDR(c)
		if err == nil {
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
