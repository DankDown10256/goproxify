// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net"
	"net/http"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// decoyIsLegit dit si la route qui sert la requête utilise vraiment ce chemin : une location qu'elle déclare, ou un chemin que son
// profil de surface appris a vu servir à des clients propres. Un leurre ne compte alors pas (ADR 0020, étape 2.a). Un hôte sans route
// n'a pas d'application derrière lui : le chemin y est un piège.
func (s *Server) decoyIsLegit(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	route, ok := s.table.ByHost(host)
	if !ok {
		return false
	}
	if loc := router.MatchLocation(route, r.URL.Path); loc != nil && loc.Path != "/" {
		return true
	}
	return s.surface != nil && s.surface.Knows(route.ID, r.URL.Path)
}

// enumerationKnown dit si le profil de surface de la route (convergé) connaît ce chemin : seul un gabarit que le trafic légitime utilise
// peut être énuméré, et seul un profil convergé dit ce qui est normal (ADR 0020, étape 4.b).
func (s *Server) enumerationKnown(host, path string) bool {
	if s.surface == nil {
		return false
	}
	route, ok := s.table.ByHost(host)
	if !ok {
		return false
	}
	return s.surface.Knows(route.ID, path) && s.surface.Converged(route.ID)
}
