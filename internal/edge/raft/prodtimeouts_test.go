// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"testing"
	"time"
)

// TestClusterProdTimeoutsStable vérifie la stabilité du leadership avec les
// timeouts réellement utilisés en production (voir internal/admin/ha.New:
// 200-500ms d'élection, 75ms de heartbeat) : un leader élu doit le rester
// bien au-delà d'une seule fenêtre de timeout d'élection tant qu'il envoie
// ses heartbeats, et non churner à chaque fenêtre.
func TestClusterProdTimeoutsStable(t *testing.T) {
	transport := newMemTransport()
	ids := []string{"n1", "n2", "n3"}
	nodes := make(map[string]*Node)
	for _, id := range ids {
		peers := map[string]string{}
		for _, o := range ids {
			if o != id {
				peers[o] = o
			}
		}
		n := NewNode(Config{
			ID:                 id,
			Peers:              peers,
			ElectionTimeoutMin: 200 * time.Millisecond,
			ElectionTimeoutMax: 500 * time.Millisecond,
			HeartbeatInterval:  75 * time.Millisecond,
		}, transport, discardLogger())
		nodes[id] = n
		transport.register(id, n)
	}
	for _, n := range nodes {
		n.Start()
	}
	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	deadline := time.Now().Add(1 * time.Second)
	var leaderID string
	for time.Now().Before(deadline) {
		for id, n := range nodes {
			if n.IsLeader() {
				leaderID = id
			}
		}
		if leaderID != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if leaderID == "" {
		t.Fatal("pas de leader élu")
	}

	initialTerm := nodes[leaderID].State()
	_ = initialTerm
	nodes[leaderID].mu.Lock()
	term0 := nodes[leaderID].currentTerm
	nodes[leaderID].mu.Unlock()

	// Le leader doit rester en poste 1.5s (3x la fenêtre max d'élection)
	// sans que le terme change, tant qu'il continue d'envoyer ses
	// heartbeats normalement.
	stableUntil := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(stableUntil) {
		if !nodes[leaderID].IsLeader() {
			t.Fatalf("le leader %s a perdu son mandat sans raison durant la fenêtre de stabilité", leaderID)
		}
		nodes[leaderID].mu.Lock()
		term := nodes[leaderID].currentTerm
		nodes[leaderID].mu.Unlock()
		if term != term0 {
			t.Fatalf("le terme a changé (%d -> %d) alors que le leader %s restait actif : réélections spontanées", term0, term, leaderID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
