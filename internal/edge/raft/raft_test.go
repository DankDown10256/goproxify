// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"testing"
	"time"
)

// TestSingleNodeElectsItselfLeader vérifie qu'un nœud sans pairs (dernier
// survivant, ou cluster à un seul nœud) s'élit leader lui-même au lieu de
// rester bloqué en Candidate indéfiniment.
func TestSingleNodeElectsItselfLeader(t *testing.T) {
	n := NewNode(Config{ID: "solo", Peers: map[string]string{}}, nil, discardLogger())
	n.startElection()

	if !n.IsLeader() {
		t.Fatalf("nœud sans pairs devrait s'élire leader, état=%s", n.State())
	}
	if got := n.LeaderID(); got != "solo" {
		t.Fatalf("LeaderID() = %q, attendu %q", got, "solo")
	}
}

// TestSingleNodeProposeAfterElection vérifie qu'un nœud solo élu leader peut
// accepter des propositions (Propose ne renvoie plus ErrNotLeader).
func TestSingleNodeProposeAfterElection(t *testing.T) {
	n := NewNode(Config{ID: "solo", Peers: map[string]string{}}, nil, discardLogger())
	n.startElection()

	if err := n.Propose([]byte("cmd")); err != nil {
		t.Fatalf("Propose() a échoué sur un leader solo: %v", err)
	}
}

func TestNewNodeDefaultTimeouts(t *testing.T) {
	n := NewNode(Config{ID: "n1"}, nil, discardLogger())
	if n.cfg.ElectionTimeoutMin != 150*time.Millisecond {
		t.Fatalf("ElectionTimeoutMin par défaut inattendu: %v", n.cfg.ElectionTimeoutMin)
	}
	if n.cfg.HeartbeatInterval != 50*time.Millisecond {
		t.Fatalf("HeartbeatInterval par défaut inattendu: %v", n.cfg.HeartbeatInterval)
	}
}
