// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"

	"github.com/vincamok/goproxify/internal/admin/archstore"
)

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
