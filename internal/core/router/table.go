// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Table est la table de routage du Core.
// Toutes les opérations sont thread-safe et sans verrou de lecture (sync.Map).
type Table struct {
	routes sync.Map // key: route.ID → *Route
	byHost sync.Map // key: host      → *Route  (HTTP uniquement)
	byPort sync.Map // key: port(int) → *Route  (TCP/UDP uniquement)
	count  atomic.Int64
}

// Upsert ajoute ou remplace une route atomiquement.
func (t *Table) Upsert(r *Route) {
	prev, loaded := t.routes.Swap(r.ID, r)
	if loaded {
		old := prev.(*Route)
		if old.Host != "" {
			t.byHost.Delete(old.Host)
		}
		for _, a := range old.Aliases {
			t.byHost.Delete(a)
		}
		if old.ListenPort > 0 {
			t.byPort.Delete(old.ListenPort)
		}
	} else {
		t.count.Add(1)
	}
	if r.Host != "" {
		t.byHost.Store(r.Host, r)
	}
	for _, a := range r.Aliases {
		if a != "" {
			t.byHost.Store(a, r)
		}
	}
	if r.ListenPort > 0 {
		t.byPort.Store(r.ListenPort, r)
	}
}

// Delete supprime une route par son ID.
func (t *Table) Delete(id string) bool {
	val, loaded := t.routes.LoadAndDelete(id)
	if !loaded {
		return false
	}
	r := val.(*Route)
	if r.Host != "" {
		t.byHost.Delete(r.Host)
	}
	for _, a := range r.Aliases {
		t.byHost.Delete(a)
	}
	if r.ListenPort > 0 {
		t.byPort.Delete(r.ListenPort)
	}
	t.count.Add(-1)
	return true
}

// ByHost retourne la route correspondant à un Host header.
// Essaie d'abord un match exact, puis un match wildcard (*.parent.tld).
func (t *Table) ByHost(host string) (*Route, bool) {
	if val, ok := t.byHost.Load(host); ok {
		return val.(*Route), true
	}
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		if val, ok := t.byHost.Load("*" + host[idx:]); ok {
			return val.(*Route), true
		}
	}
	return nil, false
}

// PassthroughRoute retourne une route TLS passthrough pour host si elle existe.
// Contrairement à ByHost, un proxy exact non-passthrough n'empêche pas de trouver
// un wildcard passthrough (ex: deleg-* *.domaine.fr) — requis pour la délégation inter-Cores.
func (t *Table) PassthroughRoute(host string) (*Route, bool) {
	if val, ok := t.byHost.Load(host); ok {
		if r := val.(*Route); r.TLSPassthrough {
			return r, true
		}
	}
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		if val, ok := t.byHost.Load("*" + host[idx:]); ok {
			if r := val.(*Route); r.TLSPassthrough {
				return r, true
			}
		}
	}
	return nil, false
}

// HostCoveredByPattern indique si host est couvert par un motif exact ou wildcard DNS.
// "*.example.fr" couvre un seul label ("api.example.fr") mais pas "a.b.example.fr"
// — aligné sur ByHost / PassthroughRoute.
func HostCoveredByPattern(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if host == "" || pattern == "" {
		return false
	}
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.fr"
		if !strings.HasSuffix(host, suffix) || len(host) <= len(suffix) {
			return false
		}
		rest := host[:len(host)-len(suffix)]
		return rest != "" && !strings.Contains(rest, ".")
	}
	return false
}

// ByPort retourne la route TCP/UDP écoutant sur ce port.
func (t *Table) ByPort(port int) (*Route, bool) {
	val, ok := t.byPort.Load(port)
	if !ok {
		return nil, false
	}
	return val.(*Route), true
}

// All retourne toutes les routes (snapshot).
func (t *Table) All() []*Route {
	routes := make([]*Route, 0, t.count.Load())
	t.routes.Range(func(_, val any) bool {
		routes = append(routes, val.(*Route))
		return true
	})
	return routes
}

// Len retourne le nombre de routes.
func (t *Table) Len() int64 { return t.count.Load() }

// Replace remplace toute la table atomiquement (utilisé lors du chargement du cache).
// En cas d'erreur de validation, la table courante n'est pas touchée (revue P1 #11).
func (t *Table) Replace(routes []*Route) error {
	for _, r := range routes {
		if r == nil || r.ID == "" {
			return fmt.Errorf("route sans ID ignorée")
		}
	}
	var next Table
	for _, r := range routes {
		next.Upsert(r)
	}
	t.routes = next.routes
	t.byHost = next.byHost
	t.byPort = next.byPort
	t.count.Store(next.count.Load())
	return nil
}
