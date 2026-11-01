// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

// privatePrefixes regroupe les plages RFC1918, loopback et link-local — toujours autorisées.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("169.254.0.0/16"),
}

func isPrivateAddr(a netip.Addr) bool {
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// WhitelistProfileID est l'identifiant du profil allow que l'Admin tient pour la liste blanche des
// bans. Contrairement aux autres profils allow (qui seulement priment sur les bans et les profils
// deny), ses adresses sont aussi exemptées de la détection Ephor.
const WhitelistProfileID = "bans-whitelist"

// IPProfile est un profil de filtrage IP reçu depuis Admin.
type IPProfile struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Mode  string   `json:"mode"` // allow | deny
	CIDRs []string `json:"cidrs"`
}

// IPProfileStore stocke les profils IP actifs en mémoire. Comme BanStore, il lit un index : le coût d'une vérification ne
// dépend pas du nombre de réseaux.
type IPProfileStore struct {
	mu       sync.RWMutex
	profiles []*IPProfile
	idx      atomic.Pointer[profileIndex]
}

type profileIndex struct {
	allow, deny, whitelist *prefixIndex[*IPProfile]
}

// NewIPProfileStore crée un store vide.
func NewIPProfileStore() *IPProfileStore {
	return &IPProfileStore{}
}

// Replace remplace atomiquement tous les profils.
func (s *IPProfileStore) Replace(profiles []*IPProfile) {
	allow, deny, wl := newPrefixBuilder[*IPProfile](), newPrefixBuilder[*IPProfile](), newPrefixBuilder[*IPProfile]()
	for order, p := range profiles {
		for _, cidr := range p.CIDRs {
			if !strings.Contains(cidr, "/") {
				if ip := net.ParseIP(cidr); ip != nil {
					if ip.To4() != nil {
						cidr = cidr + "/32"
					} else {
						cidr = cidr + "/128"
					}
				}
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			switch p.Mode {
			case "allow":
				allow.addNet(order, ipnet, p)
				if p.ID == WhitelistProfileID {
					wl.addNet(order, ipnet, p)
				}
			case "deny":
				deny.addNet(order, ipnet, p)
			}
		}
	}
	s.mu.Lock()
	s.profiles = profiles
	s.mu.Unlock()
	s.idx.Store(&profileIndex{allow: allow.build(), deny: deny.build(), whitelist: wl.build()})
}

// Len retourne le nombre de profils chargés.
func (s *IPProfileStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.profiles)
}

// IsAllowed indique si l'IP est explicitement autorisée (privée ou profil allow).
// Utilisé pour court-circuiter les bans d'Ephor et de CrowdSec.
func (s *IPProfileStore) IsAllowed(ipStr string) bool {
	addr, _ := ParseClientAddr(ipStr)
	return s.IsAllowedAddr(addr)
}

// IsAllowedAddr fait comme IsAllowed pour une adresse déjà lue (ParseClientAddr).
func (s *IPProfileStore) IsAllowedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if isPrivateAddr(addr) {
		return true
	}
	x := s.idx.Load()
	if x == nil {
		return false
	}
	_, ok := x.allow.lookup(addr, nil)
	return ok
}

// IsWhitelisted indique si l'IP figure dans la liste blanche des bans (WhitelistProfileID). Les
// adresses privées ne comptent pas ici : elles sont déjà exemptées de bans, mais restent évaluées
// par Ephor.
func (s *IPProfileStore) IsWhitelisted(ipStr string) bool {
	addr, _ := ParseClientAddr(ipStr)
	return s.IsWhitelistedAddr(addr)
}

// IsWhitelistedAddr fait comme IsWhitelisted pour une adresse déjà lue (ParseClientAddr).
func (s *IPProfileStore) IsWhitelistedAddr(addr netip.Addr) bool {
	x := s.idx.Load()
	if x == nil {
		return false
	}
	_, ok := x.whitelist.lookup(addr, nil)
	return ok
}

// CheckBlocked vérifie si une IP doit être bloquée.
// Priorité : IPs privées RFC1918 → toujours autorisées.
// Puis : profils allow → si match, autorisé (override deny).
// Puis : profils deny → si match, bloqué.
func (s *IPProfileStore) CheckBlocked(ipStr string) (bool, string) {
	addr, _ := ParseClientAddr(ipStr)
	return s.CheckBlockedAddr(addr)
}

// CheckBlockedAddr fait comme CheckBlocked pour une adresse déjà lue (ParseClientAddr). Quand plusieurs profils deny
// correspondent, c'est le premier de la liste reçue qui donne son nom.
func (s *IPProfileStore) CheckBlockedAddr(addr netip.Addr) (bool, string) {
	if !addr.IsValid() || isPrivateAddr(addr) {
		return false, ""
	}
	x := s.idx.Load()
	if x == nil {
		return false, ""
	}
	if _, ok := x.allow.lookup(addr, nil); ok {
		return false, ""
	}
	if p, ok := x.deny.lookup(addr, nil); ok {
		return true, p.Name
	}
	return false, ""
}
