// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"net"
	"net/netip"
	"sync/atomic"
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
}

// BanStore stocke les bans actifs en mémoire (Ephor, CrowdSec, natif). La vérification d'une IP lit un index
// (ADR 0020, étape 1) : son coût ne dépend pas du nombre de bans.
type BanStore struct {
	idx atomic.Pointer[banIndex]
}

type banIndex struct {
	n int
	p *prefixIndex[*RuntimeBan]
}

// NewBanStore crée un store vide.
func NewBanStore() *BanStore {
	return &BanStore{}
}

// Replace remplace atomiquement tous les bans et précompile l'index.
func (s *BanStore) Replace(bans []*RuntimeBan) {
	now := time.Now()
	b := newPrefixBuilder[*RuntimeBan]()
	n := 0
	for _, in := range bans {
		if in == nil || in.IP == "" {
			continue
		}
		if in.ExpiresAt != nil && !in.ExpiresAt.IsZero() && in.ExpiresAt.Before(now) {
			continue
		}
		compiled := *in
		if _, ipnet, err := net.ParseCIDR(in.IP); err == nil {
			if !b.addNet(n, ipnet, &compiled) {
				continue
			}
		} else if ip := net.ParseIP(in.IP); ip != nil {
			if !b.addIP(n, ip, &compiled) {
				continue
			}
		} else {
			continue
		}
		n++
	}
	s.idx.Store(&banIndex{n: n, p: b.build()})
}

// Len retourne le nombre de bans chargés (non expirés au moment du Replace).
func (s *BanStore) Len() int {
	if x := s.idx.Load(); x != nil {
		return x.n
	}
	return 0
}

// CheckBlocked indique si l'IP est bannie (IPs privées toujours exemptées).
func (s *BanStore) CheckBlocked(ipStr string) (bool, string) {
	addr, _ := ParseClientAddr(ipStr)
	return s.CheckBlockedAddr(addr)
}

// CheckBlockedAddr fait comme CheckBlocked pour une adresse déjà lue (ParseClientAddr). Une adresse invalide n'est pas bannie.
// Quand plusieurs bans correspondent, c'est le premier de la liste reçue qui donne la raison.
func (s *BanStore) CheckBlockedAddr(addr netip.Addr) (bool, string) {
	if !addr.IsValid() || isPrivateAddr(addr) {
		return false, ""
	}
	x := s.idx.Load()
	if x == nil {
		return false, ""
	}
	var now time.Time
	b, ok := x.p.lookup(addr, func(b *RuntimeBan) bool {
		if b.ExpiresAt == nil || b.ExpiresAt.IsZero() {
			return false
		}
		if now.IsZero() {
			now = time.Now()
		}
		return b.ExpiresAt.Before(now)
	})
	if !ok {
		return false, ""
	}
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
