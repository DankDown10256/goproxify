// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"
	"strings"
	"sync"
)

// privateNets regroupe les plages RFC1918, loopback et link-local — toujours autorisées.
var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"169.254.0.0/16",
	} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, ipnet)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, ipnet := range privateNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IPProfile est un profil de filtrage IP reçu depuis Admin.
type IPProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"` // allow | deny
	CIDRs []string `json:"cidrs"`

	nets []*net.IPNet
}

// IPProfileStore stocke les profils IP actifs en mémoire.
type IPProfileStore struct {
	mu       sync.RWMutex
	profiles []*IPProfile
}

// NewIPProfileStore crée un store vide.
func NewIPProfileStore() *IPProfileStore {
	return &IPProfileStore{}
}

// Replace remplace atomiquement tous les profils.
func (s *IPProfileStore) Replace(profiles []*IPProfile) {
	for _, p := range profiles {
		var nets []*net.IPNet
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
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
				nets = append(nets, ipnet)
			}
		}
		p.nets = nets
	}
	s.mu.Lock()
	s.profiles = profiles
	s.mu.Unlock()
}

// Len retourne le nombre de profils chargés.
func (s *IPProfileStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.profiles)
}

// IsAllowed indique si l'IP est explicitement autorisée (privée ou profil allow).
// Utilisé pour court-circuiter les bans Fail2Ban/CrowdSec.
func (s *IPProfileStore) IsAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if isPrivateIP(ip) {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.Mode != "allow" {
			continue
		}
		for _, ipnet := range p.nets {
			if ipnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// CheckBlocked vérifie si une IP doit être bloquée.
// Priorité : IPs privées RFC1918 → toujours autorisées.
// Puis : profils allow → si match, autorisé (override deny).
// Puis : profils deny → si match, bloqué.
func (s *IPProfileStore) CheckBlocked(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}
	// Les IPs privées/locales ne sont jamais bloquées
	if isPrivateIP(ip) {
		return false, ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Un profil allow explicite prime sur tout profil deny
	for _, p := range s.profiles {
		if p.Mode != "allow" {
			continue
		}
		for _, ipnet := range p.nets {
			if ipnet.Contains(ip) {
				return false, ""
			}
		}
	}
	// Vérifier les profils deny
	for _, p := range s.profiles {
		if p.Mode != "deny" {
			continue
		}
		for _, ipnet := range p.nets {
			if ipnet.Contains(ip) {
				return true, p.Name
			}
		}
	}
	return false, ""
}
