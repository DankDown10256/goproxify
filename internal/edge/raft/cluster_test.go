// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// memTransport route les RPC Raft en mémoire entre nœuds d'un même test,
// sans passer par HTTP. Permet de simuler un vrai cluster à plusieurs nœuds
// et de couper un nœud (panne) pour vérifier le failover.
type memTransport struct {
	mu    sync.RWMutex
	nodes map[string]*Node // URL (= ID ici) -> nœud cible
	down  map[string]bool  // nœuds "éteints" : toute RPC échoue
}

func newMemTransport() *memTransport {
	return &memTransport{
		nodes: make(map[string]*Node),
		down:  make(map[string]bool),
	}
}

func (t *memTransport) register(id string, n *Node) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[id] = n
}

func (t *memTransport) setDown(id string, down bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.down[id] = down
}

func (t *memTransport) RequestVote(peerURL string, args RequestVoteArgs) (RequestVoteReply, error) {
	t.mu.RLock()
	n, ok := t.nodes[peerURL]
	dead := t.down[peerURL]
	t.mu.RUnlock()
	if !ok || dead {
		return RequestVoteReply{}, errors.New("peer injoignable")
	}
	return n.HandleRequestVote(args), nil
}

func (t *memTransport) AppendEntries(peerURL string, args AppendEntriesArgs) (AppendEntriesReply, error) {
	t.mu.RLock()
	n, ok := t.nodes[peerURL]
	dead := t.down[peerURL]
	t.mu.RUnlock()
	if !ok || dead {
		return AppendEntriesReply{}, errors.New("peer injoignable")
	}
	return n.HandleAppendEntries(args), nil
}

// cluster est un ensemble de nœuds Raft reliés par un memTransport commun,
// pratique pour les tests d'intégration HA (élection, réplication, failover).
type cluster struct {
	t          *testing.T
	transport  *memTransport
	nodes      map[string]*Node
	applied    map[string]*[]LogEntry
	appliedMus map[string]*sync.Mutex
	killed     map[string]bool
}

func newCluster(t *testing.T, ids ...string) *cluster {
	t.Helper()
	transport := newMemTransport()
	c := &cluster{
		t:          t,
		transport:  transport,
		nodes:      make(map[string]*Node),
		applied:    make(map[string]*[]LogEntry),
		appliedMus: make(map[string]*sync.Mutex),
		killed:     make(map[string]bool),
	}

	for _, id := range ids {
		peers := make(map[string]string, len(ids)-1)
		for _, other := range ids {
			if other != id {
				peers[other] = other // en mémoire, l'URL = l'ID
			}
		}

		entries := &[]LogEntry{}
		mu := &sync.Mutex{}
		c.applied[id] = entries
		c.appliedMus[id] = mu

		cfg := Config{
			ID:                 id,
			Peers:              peers,
			ElectionTimeoutMin: 20 * time.Millisecond,
			ElectionTimeoutMax: 40 * time.Millisecond,
			HeartbeatInterval:  10 * time.Millisecond,
			ApplyFunc: func(entry LogEntry) {
				mu.Lock()
				*entries = append(*entries, entry)
				mu.Unlock()
			},
		}
		n := NewNode(cfg, transport, discardLogger())
		c.nodes[id] = n
		transport.register(id, n)
	}
	return c
}

func (c *cluster) startAll() {
	for _, n := range c.nodes {
		n.Start()
	}
}

func (c *cluster) stopAll() {
	for id, n := range c.nodes {
		if c.killed[id] {
			continue
		}
		n.Stop()
	}
}

// awaitLeader attend qu'exactement un leader émerge parmi les nœuds actifs
// et retourne son ID, ou échoue le test après le délai imparti.
func (c *cluster) awaitLeader(timeout time.Duration, activeOnly bool) string {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := []string{}
		for id, n := range c.nodes {
			if activeOnly && c.isDown(id) {
				continue
			}
			if n.IsLeader() {
				leaders = append(leaders, id)
			}
		}
		if len(leaders) == 1 {
			return leaders[0]
		}
		if len(leaders) > 1 {
			c.t.Fatalf("plusieurs leaders simultanés détectés: %v", leaders)
		}
		time.Sleep(2 * time.Millisecond)
	}
	c.t.Fatalf("aucun leader élu après %s", timeout)
	return ""
}

func (c *cluster) isDown(id string) bool {
	c.transport.mu.RLock()
	defer c.transport.mu.RUnlock()
	return c.transport.down[id]
}

// killNode simule une panne : le nœud est arrêté et le transport refuse
// toute RPC à destination (pour empêcher les autres de compter dessus).
func (c *cluster) killNode(id string) {
	c.transport.setDown(id, true)
	c.nodes[id].Stop()
	c.killed[id] = true
}

// TestClusterElectsSingleLeader vérifie qu'un cluster à 3 nœuds converge
// vers un unique leader.
func TestClusterElectsSingleLeader(t *testing.T) {
	c := newCluster(t, "n1", "n2", "n3")
	c.startAll()
	defer c.stopAll()

	leader := c.awaitLeader(2*time.Second, false)
	if leader == "" {
		t.Fatal("pas de leader élu")
	}
}

// TestClusterReplicatesAndApplies vérifie que Propose() sur le leader
// finit par être appliqué (via ApplyFunc) sur tous les nœuds du cluster.
func TestClusterReplicatesAndApplies(t *testing.T) {
	c := newCluster(t, "n1", "n2", "n3")
	c.startAll()
	defer c.stopAll()

	leaderID := c.awaitLeader(2*time.Second, false)
	leader := c.nodes[leaderID]

	cmd := []byte("route:add:example.com")
	if err := leader.Propose(cmd); err != nil {
		t.Fatalf("Propose() sur le leader a échoué: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		allApplied := true
		for id, entries := range c.applied {
			c.appliedMus[id].Lock()
			has := false
			for _, e := range *entries {
				if string(e.Command) == string(cmd) {
					has = true
					break
				}
			}
			c.appliedMus[id].Unlock()
			if !has {
				allApplied = false
			}
		}
		if allApplied {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("la commande proposée n'a pas été appliquée sur tous les nœuds à temps")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestClusterFailoverElectsNewLeader vérifie qu'après la panne du leader,
// le cluster restant (quorum toujours atteint) élit un nouveau leader.
func TestClusterFailoverElectsNewLeader(t *testing.T) {
	c := newCluster(t, "n1", "n2", "n3")
	c.startAll()
	defer c.stopAll()

	firstLeader := c.awaitLeader(2*time.Second, false)
	c.killNode(firstLeader)

	newLeader := c.awaitLeader(2*time.Second, true)
	if newLeader == firstLeader {
		t.Fatalf("le nouveau leader (%s) est le même que l'ancien nœud tombé en panne", newLeader)
	}
}

// TestClusterLastSurvivorElectsSelf reproduit le scénario du bug corrigé :
// après un reconfiguration du cluster (topologie poussée par Admin via
// UpdatePeers, ex. suite au retrait explicite des deux autres nœuds), un
// nœud qui se retrouve seul dans sa propre vue du cluster (Peers vide) doit
// s'élire lui-même leader. Sans le fix, il restait bloqué en Candidate
// indéfiniment puisqu'aucune goroutine de réponse à un pair ne pouvait
// jamais déclencher becomeLeader().
//
// Note : couper la joignabilité réseau de 2 nœuds sur 3 sans reconfigurer
// Peers ne doit PAS permettre au survivant de s'élire seul (ce serait un
// bug de sécurité, pas une correction : les 2 autres pourraient reformer
// leur propre majorité ailleurs en cas de partition réseau). Le scénario
// testé ici est donc une reconfiguration explicite, pas une simple panne.
func TestClusterLastSurvivorElectsSelf(t *testing.T) {
	c := newCluster(t, "n1", "n2", "n3")
	c.startAll()
	defer c.stopAll()

	leaderID := c.awaitLeader(2*time.Second, false)
	_ = leaderID

	survivor := "n1"
	c.killNode("n2")
	c.killNode("n3")
	c.nodes[survivor].UpdatePeers(map[string]string{})

	deadline := time.Now().Add(2 * time.Second)
	for {
		if c.nodes[survivor].IsLeader() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("le survivant reconfiguré seul (%s) ne s'est jamais élu leader (état=%s)", survivor, c.nodes[survivor].State())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
