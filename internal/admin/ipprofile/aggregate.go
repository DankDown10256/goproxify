// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipprofile

import (
	"net/netip"
	"slices"
	"strings"
)

// nonPublic liste les plages qu'aucune liste de blocage ne doit contenir : les bloquer
// couperait le trafic interne (RFC 1918, loopback, link-local) sans jamais viser un attaquant.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::/8", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func covers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func parseCIDR(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// normalizeCIDRs valide, déduplique et agrège une liste d'IP/CIDR : les préfixes contenus
// dans un autre disparaissent et deux préfixes voisins de même taille fusionnent en leur parent.
// dropNonPublic retire en plus les plages privées/réservées (à réserver aux listes deny).
func normalizeCIDRs(in []string, dropNonPublic bool) []string {
	ps := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, ok := parseCIDR(s)
		if !ok {
			continue
		}
		if dropNonPublic && slices.ContainsFunc(nonPublic, func(np netip.Prefix) bool { return covers(np, p) }) {
			continue
		}
		ps = append(ps, p)
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})

	// Trié par adresse puis taille croissante : un conteneur précède toujours ses contenus,
	// donc comparer au dernier préfixe retenu suffit.
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if n := len(out); n > 0 && covers(out[n-1], p) {
			continue
		}
		out = append(out, p)
		for n := len(out); n >= 2; n = len(out) {
			a, b := out[n-2], out[n-1]
			if a.Bits() != b.Bits() || a.Bits() == 0 {
				break
			}
			parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
			if netip.PrefixFrom(b.Addr(), b.Bits()-1).Masked() != parent {
				break
			}
			out = append(out[:n-2], parent)
		}
	}

	res := make([]string, len(out))
	for i, p := range out {
		res[i] = p.String()
	}
	return res
}
