// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// edgeControlPort est le port du hub WS d'une passerelle (fixe côté passerelle).
const edgeControlPort = "8000"

// controlEndpointFromRaft déduit l'endpoint Admin → passerelle (hub WS) d'un pair à partir
// de son URL Raft : même hôte, port du hub.
func controlEndpointFromRaft(raftURL string) (string, bool) {
	raftURL = strings.TrimSpace(raftURL)
	if raftURL == "" {
		return "", false
	}
	if !strings.Contains(raftURL, "://") {
		raftURL = "http://" + raftURL
	}
	u, err := url.Parse(raftURL)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	scheme := u.Scheme
	if scheme != "https" {
		scheme = "http"
	}
	return scheme + "://" + net.JoinHostPort(u.Hostname(), edgeControlPort), true
}

// discoverClusterPeers enregistre les passerelles que le heartbeat d'une passerelle désigne comme pairs Raft
// et que l'Admin ne connaît pas encore. Aucun réglage supplémentaire : la topologie déjà
// déclarée sur la passerelle (cluster.peers) sert de source.
func (m *Manager) discoverClusterPeers(ctx context.Context, hb edgeWS.EdgeHeartbeatPayload) {
	for name, raftURL := range hb.ClusterPeers {
		if name == "" || name == hb.NodeName || m.hasEdge("", name) || m.nodeReportedHeartbeat(ctx, name) {
			continue
		}
		endpoint, ok := controlEndpointFromRaft(raftURL)
		if !ok {
			continue
		}
		id, role, err := m.ensureEdgeToken(ctx, name, endpoint)
		if err != nil {
			m.log.Warn("edgews: découverte pair — token impossible", "edge", name, "err", err)
			continue
		}
		_, _ = m.db.ExecContext(ctx,
			`UPDATE tokens SET raft_endpoint=? WHERE id=? AND COALESCE(raft_endpoint,'')=''`, raftURL, id)
		m.Register(id, name, endpoint, role)
		if m.archStore != nil {
			_ = m.archStore.EnsureEdge(id, name, endpoint, role)
		}
		m.log.Info("edgews: Passerelle découvert via les pairs du cluster", "edge", name,
			"endpoint", endpoint, "annoncé_par", hb.NodeName)
	}
}

// nodeReportedHeartbeat indique si une passerelle de ce nom a déjà envoyé un heartbeat : il est alors
// connu de l'Admin (souvent sous un autre nom de connexion) et ne doit pas être dédoublé.
func (m *Manager) nodeReportedHeartbeat(ctx context.Context, name string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var n int
	_ = m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM nodes WHERE role='edge' AND node_name=?`, name).Scan(&n)
	return n > 0
}

// registerArchitectureEdges reconnecte les passerelles de architecture.json qui portent un endpoint
// et ne sont pas déjà connus (le fichier est la source de vérité de l'architecture).
func (m *Manager) registerArchitectureEdges(ctx context.Context) {
	if m.archStore == nil {
		return
	}
	nodes, err := m.archStore.EdgeEndpoints()
	if err != nil {
		m.log.Warn("edgews: lecture architecture.json", "err", err)
		return
	}
	for _, n := range nodes {
		if m.hasEdge(n.ID, n.Name) {
			continue
		}
		id, role, err := m.ensureEdgeTokenWithID(ctx, n.Name, n.Endpoint, n.ID)
		if err != nil {
			m.log.Warn("edgews: architecture.json — token impossible", "edge", n.Name, "err", err)
			continue
		}
		m.Register(id, n.Name, n.Endpoint, role)
		m.log.Info("edgews: Passerelle chargé depuis architecture.json", "edge", n.Name, "endpoint", n.Endpoint)
	}
}

// applyArchitecture aligne la base sur architecture.json (nœuds déclarés, périmètres, domaines).
func (m *Manager) applyArchitecture(ctx context.Context) {
	if m.archStore == nil {
		return
	}
	rep, err := m.archStore.ApplyToDB(ctx, m.db)
	if err != nil {
		m.log.Warn("edgews: architecture.json → base", "err", err)
	}
	if rep != (archstore.ApplyReport{}) {
		m.log.Info("edgews: base alignée sur architecture.json", "declares", rep.Declared,
			"supprimes", rep.Removed, "perimetres", rep.Scopes, "domaines", rep.Domains)
	}
}

// seedArchitecture crée architecture.json depuis la base s'il n'existe pas encore (jamais d'écrasement).
func (m *Manager) seedArchitecture(ctx context.Context) {
	if m.archStore == nil {
		return
	}
	if err := m.archStore.SeedFromDB(ctx, m.db); err != nil {
		m.log.Warn("edgews: amorçage architecture.json", "err", err)
	}
}

// ReloadArchitecture reconnecte les passerelles de architecture.json (après une restauration de version).
func (m *Manager) ReloadArchitecture(ctx context.Context) {
	m.registerArchitectureEdges(ctx)
}
