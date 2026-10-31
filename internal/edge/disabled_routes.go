// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/labels"
)

// Désactivation des routes issues des conteneurs (Docker, Portainer, Podman, Kubernetes, annuaires). Une route des
// labels n'a pas de fichier : la désactiver, c'est tenir son hôte à l'écart de la table de routage. L'Admin pousse la
// liste complète des hôtes désactivés ; elle passe par le journal des documents poussés, donc chaque membre du groupe
// HA la retient, la rend à un pair en retard et la retrouve après un redémarrage, l'Admin étant injoignable.
//
// Une route désactivée n'existe pas pour le routage : ni trafic, ni sonde de santé, ni certificat. Elle reste listée
// (avec « disabled ») d'après le dernier état complet de l'Agent, qui sert aussi à la remettre en service sans attendre
// son prochain scan.

// disabledRoutes est l'ensemble des hôtes désactivés.
type disabledRoutes struct {
	mu    sync.RWMutex
	hosts map[string]bool
}

func disabledKey(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func (d *disabledRoutes) has(host string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.hosts[disabledKey(host)]
}

func (d *disabledRoutes) list() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.hosts))
	for h := range d.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// replace remplace l'ensemble et rend les hôtes devenus désactivés et ceux qui ne le sont plus.
func (d *disabledRoutes) replace(hosts []string) (disabled, enabled []string) {
	next := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if k := disabledKey(h); k != "" {
			next[k] = true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for h := range next {
		if !d.hosts[h] {
			disabled = append(disabled, h)
		}
	}
	for h := range d.hosts {
		if !next[h] {
			enabled = append(enabled, h)
		}
	}
	d.hosts = next
	sort.Strings(disabled)
	sort.Strings(enabled)
	return disabled, enabled
}

// applyDisabledRoutes applique la liste poussée par l'Admin : retire de la table les routes des hôtes désactivés et
// rend celles des hôtes réactivés à partir des derniers états complets des Agents.
func (s *Server) applyDisabledRoutes(raw json.RawMessage) error {
	var p edgews.DisabledRoutes
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	disabled, enabled := s.disabledRoutes.replace(p.Hosts)
	removed := s.dropDisabledRoutes()
	restored := s.restoreRoutes(enabled)
	if removed+restored > 0 {
		metrics.Edge.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
	}
	if len(disabled)+len(enabled) > 0 {
		s.log.Info("routes de conteneurs: désactivations appliquées", "désactivés", len(disabled), "réactivés", len(enabled), "routes retirées", removed, "routes rendues", restored)
	}
	return nil
}

// dropDisabledRoutes retire de la table les routes découvertes dont l'hôte est désactivé. Rend leur nombre.
func (s *Server) dropDisabledRoutes() int {
	n := 0
	for _, rt := range s.table.All() {
		if router.IsDiscoveredID(rt.ID) && s.disabledRoutes.has(rt.Host) && s.table.Delete(rt.ID) {
			n++
		}
	}
	return n
}

// restoreRoutes remet en table les routes que les derniers états des Agents déclarent pour ces hôtes. Rend le nombre de
// routes appliquées.
func (s *Server) restoreRoutes(hosts []string) int {
	if len(hosts) == 0 {
		return 0
	}
	want := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		want[h] = true
	}
	n := 0
	for _, st := range s.agentStates.all() {
		for i := range st.Routes {
			p := st.Routes[i]
			host, _ := labels.ParseHostEntry(p.Host)
			if !want[disabledKey(host)] {
				continue
			}
			p.Aliases = append([]string(nil), p.Aliases...)
			p.Paths = append([]string(nil), p.Paths...)
			if code, why := s.applyAgentRoute(&p); code != http.StatusNoContent {
				s.log.Warn("routes de conteneurs: route non rétablie", "host", p.Host, "agent", st.AgentName, "status", code, "err", why)
				continue
			}
			n++
		}
	}
	return n
}

// disabledEntries liste les routes désactivées que les états des Agents déclarent encore, une par (hôte, Agent, source).
func (s *Server) disabledEntries(agent string) []disabledEntry {
	if len(s.disabledRoutes.list()) == 0 {
		return nil
	}
	byKey := map[string]*disabledEntry{}
	var order []string
	for _, st := range s.agentStates.all() {
		if agent != "" && st.AgentName != agent {
			continue
		}
		for _, p := range st.Routes {
			host, _ := labels.ParseHostEntry(p.Host)
			if !s.disabledRoutes.has(host) {
				continue
			}
			key := disabledKey(host) + "|" + st.AgentName + "|" + st.Source
			e, ok := byKey[key]
			if !ok {
				id := p.ID
				if id == "" {
					id = dockerHostRouteID(host)
				}
				e = &disabledEntry{ID: id, Host: host, Aliases: p.Aliases, Source: st.Source, Agent: st.AgentName, TLS: p.TLSEnabled || p.Passthrough}
				byKey[key] = e
				order = append(order, key)
			}
			e.Backends = append(e.Backends, p.Backends...)
			if p.ContainerID != "" {
				e.ContainerIDs = append(e.ContainerIDs, p.ContainerID)
			}
		}
	}
	out := make([]disabledEntry, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// disabledEntry est une route désactivée, telle que la liste des conteneurs la montre.
type disabledEntry struct {
	ID           string
	Host         string
	Aliases      []string
	Backends     []string
	ContainerIDs []string
	TLS          bool
	Source       string
	Agent        string
}
