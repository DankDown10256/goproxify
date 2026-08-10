// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package delegation filtre les proxies selon les domaines délégués inter-Cores.
// Un host couvert par un domaine délégué ne doit être poussé qu'au Core cible
// (delegated_to_core_id), pas au Core responsable ni aux autres.
package delegation

import (
	"strings"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Binding décrit une délégation de domaine active.
type Binding struct {
	Domain            string // ex: *.dankdown.fr
	ResponsibleCoreID string // core_id (UUID token ou node_name)
	TargetCoreID      string // delegated_to_core_id
}

// HostCoveredByDomain indique si host est couvert par le motif de domaine.
// Délègue à router.HostCoveredByPattern (wildcard DNS à un seul label).
func HostCoveredByDomain(host, domainPattern string) bool {
	return router.HostCoveredByPattern(host, domainPattern)
}

// RouteCoveredByDomain indique si la route (host ou alias) tombe sous le domaine délégué.
func RouteCoveredByDomain(r *router.Route, domainPattern string) bool {
	if r == nil {
		return false
	}
	if HostCoveredByDomain(r.Host, domainPattern) {
		return true
	}
	for _, a := range r.Aliases {
		if HostCoveredByDomain(a, domainPattern) {
			return true
		}
	}
	return false
}

func coreRefMatch(coreID, nodeName, ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	return coreID == ref || nodeName == ref
}

// FilterRoutesForCore retire les proxies couverts par une délégation sauf pour le Core cible.
func FilterRoutesForCore(coreID, nodeName string, routes []router.Route, bindings []Binding) []router.Route {
	if len(bindings) == 0 || len(routes) == 0 {
		return routes
	}
	out := make([]router.Route, 0, len(routes))
	for i := range routes {
		r := routes[i]
		keep := true
		for _, b := range bindings {
			if !RouteCoveredByDomain(&r, b.Domain) {
				continue
			}
			if !coreRefMatch(coreID, nodeName, b.TargetCoreID) {
				keep = false
			}
			break
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}
