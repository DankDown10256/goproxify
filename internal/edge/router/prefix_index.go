// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"
	"net/netip"
	"sort"
)

// prefixIndex retrouve, pour une adresse, l'entrée la plus ancienne dont le préfixe la contient. Le coût d'une recherche
// ne dépend pas du nombre d'entrées : au plus une consultation de table par longueur de masque utilisée (33 en IPv4, 129
// en IPv6). Une IP seule est un préfixe plein (/32, /128).
type prefixIndex[T any] struct {
	v4, v6 []lenTable[T]
	n      int
}

type lenTable[T any] struct {
	bits int
	m    map[netip.Addr][]indexed[T]
}

type indexed[T any] struct {
	order int
	val   T
}

// prefixBuilder prépare un prefixIndex. order donne la priorité : à égalité de correspondance, la plus petite l'emporte (c'est
// l'ordre de la liste d'origine, que l'ancienne recherche linéaire respectait).
type prefixBuilder[T any] struct {
	v4, v6 map[int]map[netip.Addr][]indexed[T]
	n      int
}

func newPrefixBuilder[T any]() *prefixBuilder[T] {
	return &prefixBuilder[T]{v4: map[int]map[netip.Addr][]indexed[T]{}, v6: map[int]map[netip.Addr][]indexed[T]{}}
}

func (b *prefixBuilder[T]) add(order int, p netip.Prefix, v T) {
	p = p.Masked()
	tables := b.v6
	if p.Addr().Is4() {
		tables = b.v4
	}
	m := tables[p.Bits()]
	if m == nil {
		m = map[netip.Addr][]indexed[T]{}
		tables[p.Bits()] = m
	}
	m[p.Addr()] = append(m[p.Addr()], indexed[T]{order, v})
	b.n++
}

// addIP indexe une adresse seule.
func (b *prefixBuilder[T]) addIP(order int, ip net.IP, v T) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	b.add(order, netip.PrefixFrom(a, a.BitLen()), v)
	return true
}

// addNet indexe un réseau tel que net.ParseCIDR le rend. Un réseau IPv4 écrit en IPv6 (::ffff:a.b.c.d/n, n ≥ 96) devient
// un réseau IPv4 ; l'Admin normalise les CIDR, les autres formes ne sont pas prises en charge.
func (b *prefixBuilder[T]) addNet(order int, n *net.IPNet, v T) bool {
	ones, size := n.Mask.Size()
	if size == 0 {
		return false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return false
	}
	if a.Is4In6() && size == 128 && ones >= 96 {
		a, ones = a.Unmap(), ones-96
	}
	b.add(order, netip.PrefixFrom(a, ones), v)
	return true
}

func (b *prefixBuilder[T]) build() *prefixIndex[T] {
	freeze := func(tables map[int]map[netip.Addr][]indexed[T]) []lenTable[T] {
		out := make([]lenTable[T], 0, len(tables))
		for bits, m := range tables {
			out = append(out, lenTable[T]{bits: bits, m: m})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].bits > out[j].bits })
		return out
	}
	return &prefixIndex[T]{v4: freeze(b.v4), v6: freeze(b.v6), n: b.n}
}

// lookup rend l'entrée d'ordre le plus petit dont le préfixe contient addr (déjà sans IPv4-mappée), en ignorant celles que
// skip écarte (un ban expiré, par exemple).
func (x *prefixIndex[T]) lookup(addr netip.Addr, skip func(T) bool) (T, bool) {
	var out T
	if x == nil || !addr.IsValid() {
		return out, false
	}
	tables := x.v6
	if addr.Is4() {
		tables = x.v4
	}
	best := -1
	for i := range tables {
		p, err := addr.Prefix(tables[i].bits)
		if err != nil {
			continue
		}
		for _, e := range tables[i].m[p.Addr()] {
			if best >= 0 && e.order >= best {
				break
			}
			if skip != nil && skip(e.val) {
				continue
			}
			best, out = e.order, e.val
			break
		}
	}
	return out, best >= 0
}

// ParseClientAddr lit l'adresse d'un client. Faux pour tout ce qui n'est pas une IP (ou qui porte une zone IPv6) : un
// verdict « non bloqué » plutôt qu'une erreur, comme la recherche linéaire d'avant. Le dispatch l'appelle une fois par requête.
func ParseClientAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
