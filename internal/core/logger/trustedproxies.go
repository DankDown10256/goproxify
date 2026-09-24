// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"net"
	"os"
	"strings"
	"sync/atomic"
)

// EnvTrustedProxies liste (CSV d'IP/CIDR) les proxies dont les headers d'IP client sont crus,
// en plus des défauts (loopback + réseaux privés). "*" restaure l'ancien comportement (tout croire).
const EnvTrustedProxies = "GPX_TRUSTED_PROXIES"

var defaultTrustedProxies = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

type trustSet struct {
	all  bool
	nets []*net.IPNet
}

var trusted atomic.Pointer[trustSet]

func init() {
	SetTrustedProxies(strings.Split(os.Getenv(EnvTrustedProxies), ","))
}

// SetTrustedProxies remplace la liste des proxies de confiance (défauts privés toujours inclus).
// Les entrées invalides sont ignorées.
func SetTrustedProxies(entries []string) {
	ts := &trustSet{}
	for _, e := range append(append([]string{}, defaultTrustedProxies...), entries...) {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
		case e == "*":
			ts.all = true
		case strings.Contains(e, "/"):
			if _, n, err := net.ParseCIDR(e); err == nil {
				ts.nets = append(ts.nets, n)
			}
		default:
			if ip := net.ParseIP(e); ip != nil {
				bits := 8 * len(ip.To16())
				if v4 := ip.To4(); v4 != nil {
					ip, bits = v4, 32
				}
				ts.nets = append(ts.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
		}
	}
	trusted.Store(ts)
}

func isTrustedPeer(peer string) bool {
	ts := trusted.Load()
	if ts.all {
		return true
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, n := range ts.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
