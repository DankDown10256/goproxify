// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/archstore"
)

// TopologyFromArchitecture relit les hôtes déclarés dans architecture.json : un hôte est l'ensemble des nœuds qui
// partagent `config.host`, son adresse est `config.reachable_host` (sans le port du hub), et les noms et identifiants
// des nœuds sont ceux du fichier. L'Admin n'y figure pas (ce n'est pas un nœud) ; la topologie n'a pas d'hôte local.
// Les nœuds sans hôte déclaré sont ignorés : on ne sait pas où les installer.
func TopologyFromArchitecture(arch *archstore.Architecture) *Topology {
	t := &Topology{}
	index := map[string]int{}
	for _, n := range arch.Nodes {
		if n.Role != RoleEdge && n.Role != RoleAgent {
			continue
		}
		var cfg struct {
			Host          string `json:"host"`
			ReachableHost string `json:"reachable_host"`
			Cluster       bool   `json:"cluster"`
			ClusterGroup  string `json:"cluster_group"`
			TargetEdge    string `json:"target_edge"`
		}
		if json.Unmarshal(n.Config, &cfg) != nil || cfg.Host == "" {
			continue
		}
		i, ok := index[cfg.Host]
		if !ok {
			i = len(t.Hosts)
			index[cfg.Host] = i
			t.Hosts = append(t.Hosts, Host{Name: cfg.Host})
		}
		h := &t.Hosts[i]
		if h.Addr == "" {
			h.Addr = hostOf(cfg.ReachableHost)
		}
		h.Roles = append(h.Roles, n.Role)
		if n.Role == RoleEdge {
			h.EdgeNode, h.EdgeID = n.Name, n.ID
			if cfg.Cluster {
				h.Group = cfg.ClusterGroup
			}
		} else {
			h.AgentNode, h.AgentID, h.AgentTarget = n.Name, n.ID, cfg.TargetEdge
		}
	}
	return t
}

// hostOf retire d'une adresse déclarée le schéma et le port : `192.168.1.50:8000` → `192.168.1.50`.
func hostOf(reachable string) string {
	if strings.Contains(reachable, "://") {
		if u, err := url.Parse(reachable); err == nil {
			return u.Hostname()
		}
	}
	if host, _, err := net.SplitHostPort(reachable); err == nil {
		return host
	}
	return reachable
}

// Host cherche un hôte par son nom.
func (t *Topology) Host(name string) (Host, bool) { return t.host(name) }

// NodeNames sont les noms des nœuds (passerelle, Agent) à installer sur l'hôte.
func (t *Topology) NodeNames(h Host) []string {
	var out []string
	if h.Has(RoleEdge) {
		out = append(out, t.EdgeName(h))
	}
	if h.Has(RoleAgent) {
		out = append(out, t.AgentName(h))
	}
	return out
}
