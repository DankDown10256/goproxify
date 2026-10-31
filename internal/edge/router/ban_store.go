// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"
	"sync"
	"time"
)

// BanSignal est un signal qui a contribué à un ban automatique : son nom (`path`, `rate`, `error4xx`…), les points qu'il
// a apportés et la valeur observée. La somme des points explique la décision (ADR 0011).
type BanSignal struct {
	Name   string  `json:"name"`
	Points float64 `json:"points"`
	Value  string  `json:"value,omitempty"`
}

// RuntimeBan est un bannissement IP actif poussé depuis Admin.
type RuntimeBan struct {
	ID        string     `json:"id"`
	IP        string     `json:"ip"` // IP seule ou CIDR
	Reason    string     `json:"reason,omitempty"`
	Source    string     `json:"source,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Scope : passerelles visées par un ban de l'Admin (nom de la passerelle ou "group:<nom>") ; vide = toutes.
	Scope string `json:"scope,omitempty"`
	// Signals : pourquoi un moteur automatique (Ephor, WAF) a banni l'IP ; vide pour les autres sources.
	Signals []BanSignal `json:"signals,omitempty"`
	// UserAgent : le dernier User-Agent vu pour l'IP au moment du ban automatique, quel que soit le moteur ; vide pour les autres sources.
	UserAgent string `json:"user_agent,omitempty"`

	ip   net.IP
	ipnet *net.IPNet
}

// BanStore stocke les bans actifs en mémoire (Fail2Ban, CrowdSec, natif).
type BanStore struct {
	mu   sync.RWMutex
	bans []*RuntimeBan
}

// NewBanStore crée un store vide.
func NewBanStore() *BanStore {
	return &BanStore{}
}

// Replace remplace atomiquement tous les bans et précompile les réseaux.
func (s *BanStore) Replace(bans []*RuntimeBan) {
	now := time.Now()
	out := make([]*RuntimeBan, 0, len(bans))
	for _, b := range bans {
		if b == nil || b.IP == "" {
			continue
		}
		if b.ExpiresAt != nil && !b.ExpiresAt.IsZero() && b.ExpiresAt.Before(now) {
			continue
		}
		compiled := *b
		if _, ipnet, err := net.ParseCIDR(b.IP); err == nil {
			compiled.ipnet = ipnet
		} else if ip := net.ParseIP(b.IP); ip != nil {
			compiled.ip = ip
		} else {
			continue
		}
		out = append(out, &compiled)
	}
	s.mu.Lock()
	s.bans = out
	s.mu.Unlock()
}

// Len retourne le nombre de bans chargés (non expirés au moment du Replace).
func (s *BanStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bans)
}

// CheckBlocked indique si l'IP est bannie (IPs privées toujours exemptées).
func (s *BanStore) CheckBlocked(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil || isPrivateIP(ip) {
		return false, ""
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.bans {
		if b.ExpiresAt != nil && !b.ExpiresAt.IsZero() && b.ExpiresAt.Before(now) {
			continue
		}
		matched := false
		if b.ipnet != nil {
			matched = b.ipnet.Contains(ip)
		} else if b.ip != nil {
			matched = b.ip.Equal(ip)
		}
		if matched {
			reason := b.Source
			if b.Reason != "" {
				if reason != "" {
					reason += ": "
				}
				reason += b.Reason
			}
			if reason == "" {
				reason = b.IP
			}
			return true, reason
		}
	}
	return false, ""
}
