// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"sync"
	"time"
)

// AccessGrant est un accès temporaire approuvé par un administrateur (poussé par l'Admin).
type AccessGrant struct {
	UserID    string `json:"user_id"`
	TargetID  string `json:"target_id"`
	ExpiresAt string `json:"expires_at"` // RFC3339
}

// AccessRequest est une demande d'accès temporaire émise par un utilisateur du portail.
type AccessRequest struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	TargetID    string `json:"target_id"`
	Reason      string `json:"reason"`
	DurationMin int    `json:"duration_min"`
}

// GrantSet garde en mémoire les accès temporaires ; l'Admin les repousse à chaque connexion.
type GrantSet struct {
	mu sync.RWMutex
	m  map[string]map[string]time.Time // user → target → expiration
}

// NewGrantSet crée un ensemble vide.
func NewGrantSet() *GrantSet { return &GrantSet{m: map[string]map[string]time.Time{}} }

// Replace remplace tous les accès (les dates invalides sont ignorées).
func (g *GrantSet) Replace(list []AccessGrant) {
	m := map[string]map[string]time.Time{}
	for _, a := range list {
		exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
		if err != nil || a.UserID == "" || a.TargetID == "" {
			continue
		}
		if m[a.UserID] == nil {
			m[a.UserID] = map[string]time.Time{}
		}
		m[a.UserID][a.TargetID] = exp
	}
	g.mu.Lock()
	g.m = m
	g.mu.Unlock()
}

// Expiry retourne l'expiration d'un accès actif.
func (g *GrantSet) Expiry(userID, targetID string) (time.Time, bool) {
	if g == nil {
		return time.Time{}, false
	}
	g.mu.RLock()
	exp, ok := g.m[userID][targetID]
	g.mu.RUnlock()
	if !ok || !time.Now().Before(exp) {
		return time.Time{}, false
	}
	return exp, true
}
