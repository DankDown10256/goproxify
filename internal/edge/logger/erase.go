// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"net/netip"
	"strings"
)

// EraseIP removes an IP's entries from the local log store.
// Without a local store, there is nothing to erase.
func (a *AccessLogger) EraseIP(ip string) (int, error) {
	s := a.store.Load()
	if s == nil {
		return 0, nil
	}
	s.Flush()
	n, err := s.EraseIP(CanonicalIP(ip))
	return int(n), err
}

// CanonicalIP normalise une adresse (IPv6 compressée, IPv4 mappée en IPv4, zone retirée) pour que
// deux écritures d'une même IP se comparent égales.
func CanonicalIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return ip
}
