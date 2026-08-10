// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package cluster gère le groupe de Cores : membership, leader Raft, synchronisation.
package cluster

import (
	"context"
	"log/slog"
	"time"

	"github.com/vincamok/goproxify/internal/core/raft"
)

// Group représente un groupe de Cores partageant un cluster Raft.
type Group struct {
	name      string
	node      *raft.Node
	raftSrv   *raft.Server
	log       *slog.Logger
}

// Config configure le groupe de Cores.
type Config struct {
	NodeID    string
	GroupName string
	// Peers: map id → base URL (ex: "core-2" → "http://10.0.0.2:8002")
	Peers     map[string]string
	RaftPort  int
	ApplyFunc func(entry raft.LogEntry)
}

// NewGroup crée et initialise le groupe.
func NewGroup(cfg Config, log *slog.Logger) *Group {
	raftCfg := raft.Config{
		ID:                 cfg.NodeID,
		Peers:              cfg.Peers,
		ElectionTimeoutMin: 150 * time.Millisecond,
		ElectionTimeoutMax: 300 * time.Millisecond,
		HeartbeatInterval:  50 * time.Millisecond,
		ApplyFunc:          cfg.ApplyFunc,
	}
	transport := raft.NewHTTPTransport()
	node := raft.NewNode(raftCfg, transport, log)
	srv := raft.NewServer(node, cfg.RaftPort, log)

	return &Group{
		name:    cfg.GroupName,
		node:    node,
		raftSrv: srv,
		log:     log,
	}
}

// Start démarre le serveur Raft et le nœud.
func (g *Group) Start(_ context.Context) error {
	if err := g.raftSrv.Start(); err != nil {
		return err
	}
	g.node.Start()
	g.log.Info("cluster group démarré", "group", g.name)
	return nil
}

// Stop arrête le nœud Raft.
func (g *Group) Stop() {
	g.node.Stop()
}

// IsLeader indique si ce nœud est le leader du groupe.
func (g *Group) IsLeader() bool { return g.node.IsLeader() }

// LeaderID retourne l'ID du leader courant.
func (g *Group) LeaderID() string { return g.node.LeaderID() }

// Propose soumet une commande au cluster (doit être leader).
func (g *Group) Propose(command []byte) error { return g.node.Propose(command) }

// UpdatePeers met à jour la topologie cluster à chaud (reçue depuis Admin).
func (g *Group) UpdatePeers(peers map[string]string) { g.node.UpdatePeers(peers) }
