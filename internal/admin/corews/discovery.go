// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package corews

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	coreWS "github.com/vincamok/goproxify/internal/core/ws"
)

// coreControlPort est le port du hub WS d'un Core (fixe côté Core).
const coreControlPort = "8000"

// controlEndpointFromRaft déduit l'endpoint Admin → Core (hub WS) d'un pair à partir
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
	return scheme + "://" + net.JoinHostPort(u.Hostname(), coreControlPort), true
}

// discoverClusterPeers enregistre les Cores que le heartbeat d'un Core désigne comme pairs Raft
// et que l'Admin ne connaît pas encore. Aucun réglage supplémentaire : la topologie déjà
// déclarée sur le Core (cluster.peers) sert de source.
func (m *Manager) discoverClusterPeers(ctx context.Context, hb coreWS.CoreHeartbeatPayload) {
	for name, raftURL := range hb.ClusterPeers {
		if name == "" || name == hb.NodeName || m.hasCore("", name) || m.nodeReportedHeartbeat(ctx, name) {
			continue
		}
		endpoint, ok := controlEndpointFromRaft(raftURL)
		if !ok {
			continue
		}
		id, role, err := m.ensureCoreToken(ctx, name, endpoint)
		if err != nil {
			m.log.Warn("corews: découverte pair — token impossible", "core", name, "err", err)
			continue
		}
		_, _ = m.db.ExecContext(ctx,
			`UPDATE tokens SET raft_endpoint=? WHERE id=? AND COALESCE(raft_endpoint,'')=''`, raftURL, id)
		m.Register(id, name, endpoint, role)
		if m.archStore != nil {
			_ = m.archStore.EnsureCore(id, name, endpoint, role)
		}
		m.log.Info("corews: Core découvert via les pairs du cluster", "core", name,
			"endpoint", endpoint, "annoncé_par", hb.NodeName)
	}
}

// nodeReportedHeartbeat indique si un Core de ce nom a déjà envoyé un heartbeat : il est alors
// connu de l'Admin (souvent sous un autre nom de connexion) et ne doit pas être dédoublé.
func (m *Manager) nodeReportedHeartbeat(ctx context.Context, name string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var n int
	_ = m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM nodes WHERE role='core' AND node_name=?`, name).Scan(&n)
	return n > 0
}

// registerArchitectureCores reconnecte les Cores de architecture.json qui portent un endpoint
// et ne sont pas déjà connus (le fichier est la source de vérité de l'architecture).
func (m *Manager) registerArchitectureCores(ctx context.Context) {
	if m.archStore == nil {
		return
	}
	nodes, err := m.archStore.CoreEndpoints()
	if err != nil {
		m.log.Warn("corews: lecture architecture.json", "err", err)
		return
	}
	for _, n := range nodes {
		if m.hasCore(n.ID, n.Name) {
			continue
		}
		id, role, err := m.ensureCoreTokenWithID(ctx, n.Name, n.Endpoint, n.ID)
		if err != nil {
			m.log.Warn("corews: architecture.json — token impossible", "core", n.Name, "err", err)
			continue
		}
		m.Register(id, n.Name, n.Endpoint, role)
		m.log.Info("corews: Core chargé depuis architecture.json", "core", n.Name, "endpoint", n.Endpoint)
	}
}

// applyArchitecture aligne la base sur architecture.json (nœuds déclarés, périmètres, domaines).
func (m *Manager) applyArchitecture(ctx context.Context) {
	if m.archStore == nil {
		return
	}
	rep, err := m.archStore.ApplyToDB(ctx, m.db)
	if err != nil {
		m.log.Warn("corews: architecture.json → base", "err", err)
	}
	if rep != (archstore.ApplyReport{}) {
		m.log.Info("corews: base alignée sur architecture.json", "declares", rep.Declared,
			"supprimes", rep.Removed, "perimetres", rep.Scopes, "domaines", rep.Domains)
	}
}

// seedArchitecture crée architecture.json depuis la base s'il n'existe pas encore (jamais d'écrasement).
func (m *Manager) seedArchitecture(ctx context.Context) {
	if m.archStore == nil {
		return
	}
	if err := m.archStore.SeedFromDB(ctx, m.db); err != nil {
		m.log.Warn("corews: amorçage architecture.json", "err", err)
	}
}

// ReloadArchitecture reconnecte les Cores de architecture.json (après une restauration de version).
func (m *Manager) ReloadArchitecture(ctx context.Context) {
	m.registerArchitectureCores(ctx)
}
