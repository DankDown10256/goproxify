// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package bantarget donne la cible d'un ban automatique pour l'adresse d'un client : l'IP, ou le /64 d'une IPv6, et ce qu'on ne bannit
// jamais (une valeur qui n'est pas une IP, un réseau privé, Cloudflare, une liste blanche). Ephor, les plugins de détection et le signal
// « hôte inconnu » s'y alignent pour viser les mêmes cibles.
package bantarget

import (
	"net"
	"net/netip"
)

// BanTarget donne la cible d'un ban pour l'adresse d'un client (l'IP, ou le /64 d'une IPv6), ou false pour ce
// qu'on ne bannit jamais : une valeur qui n'est pas une IP, un réseau privé, Cloudflare, la liste blanche.
// Les détecteurs qui bannissent (Ephor, plugins) s'y alignent pour viser les mêmes cibles.
func BanTarget(ip string, whitelist []string) (string, bool) {
	addr, ok := clientAddr(ip)
	if !ok || isPrivateIP(addr) || whitelisted(netip.PrefixFrom(addr, addr.BitLen()), whitelist) {
		return "", false
	}
	return banKey(addr, whitelist), true
}

// clientAddr lit une IP seule, « IP:port » ou « [IPv6]:port ». Faux pour tout ce qui n'est pas une IP.
func clientAddr(s string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// toPrefix lit une IP (préfixe /32 ou /128) ou un CIDR.
func toPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	a, ok := clientAddr(s)
	return netip.PrefixFrom(a, a.BitLen()), ok
}

// banKey est la clé de comptage et la cible du ban : l'adresse pour une IPv4, son /64 pour une IPv6
// (même agrégation que les compteurs Ephor). Un /64 revient en général à un seul abonné, qui y
// change d'adresse à volonté : compté adresse par adresse, il resterait toujours sous le seuil.
// Si la liste blanche recoupe le /64, on s'en tient à l'adresse pour ne pas bloquer l'IP exemptée.
func banKey(a netip.Addr, whitelist []string) string {
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	if whitelisted(p, whitelist) {
		return a.String()
	}
	return p.String()
}

// whitelisted indique si p recoupe une entrée de la liste blanche (IP ou CIDR).
func whitelisted(p netip.Prefix, whitelist []string) bool {
	for _, entry := range whitelist {
		if w, ok := toPrefix(entry); ok && w.Overlaps(p) {
			return true
		}
	}
	return false
}

// cloudflareRanges : ces IPs portent le trafic de tous les utilisateurs finaux
// quand Cloudflare est en amont — ne jamais bannir.
var cloudflareRanges = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14",
	"108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
	"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
	"188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
	"198.41.128.0/17",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var exemptNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, cidr := range append([]string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	}, cloudflareRanges...) {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}()

func isPrivateIP(a netip.Addr) bool {
	for _, p := range exemptNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
