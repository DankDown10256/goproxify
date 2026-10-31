// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"sync"
	"testing"
	"time"
)

func termOf(n *Node) uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.currentTerm
}

// TestIsolatedNodeDoesNotInflateTerm reproduit la boucle d'élections vue en
// production (terme +1 toutes les ~200 ms, jamais de leader) : un nœud dont
// les pairs sont injoignables ne doit pas incrémenter son terme.
func TestIsolatedNodeDoesNotInflateTerm(t *testing.T) {
	c := newCluster(t, "n1", "n2", "n3")
	c.transport.setDown("n2", true)
	c.transport.setDown("n3", true)
	c.nodes["n1"].Start()
	defer c.nodes["n1"].Stop()

	time.Sleep(500 * time.Millisecond) // ~12 timeouts d'élection à 20-40 ms

	if got := termOf(c.nodes["n1"]); got != 0 {
		t.Fatalf("nœud isolé : terme = %d, attendu 0 (pas d'élection sans quorum)", got)
	}
	if c.nodes["n1"].IsLeader() {
		t.Fatal("nœud isolé devenu leader sans quorum")
	}
}

// TestRejoiningNodeDoesNotDepositLeader : un nœud coupé puis rétabli ne doit
// pas faire tomber le leader sain.
func TestRejoiningNodeDoesNotDepositLeader(t *testing.T) {
	c := newCluster(t, "n1", "n2", "n3")
	c.startAll()
	defer c.stopAll()

	leader := c.awaitLeader(2*time.Second, false)
	var isolated string
	for id := range c.nodes {
		if id != leader {
			isolated = id
			break
		}
	}

	// Le nœud n'entend plus le leader (heartbeats perdus) mais continue
	// d'émettre : il tente des élections que le reste du groupe doit refuser.
	c.transport.setDown(isolated, true)
	termBefore := termOf(c.nodes[leader])
	time.Sleep(300 * time.Millisecond)
	c.transport.setDown(isolated, false)
	time.Sleep(300 * time.Millisecond)

	if !c.nodes[leader].IsLeader() {
		t.Fatalf("le leader %s a été déposé au retour de %s", leader, isolated)
	}
	if got := termOf(c.nodes[leader]); got != termBefore {
		t.Fatalf("terme du leader %d -> %d au retour du nœud isolé", termBefore, got)
	}
}

// TestPreVoteDeniedWhileLeaderAlive : un nœud qui vient d'entendre son leader
// refuse le pré-vote, et un pré-vote ne consomme jamais de vote réel.
func TestPreVoteDeniedWhileLeaderAlive(t *testing.T) {
	n := NewNode(Config{ID: "n1", Peers: map[string]string{"n2": "n2"}}, nil, discardLogger())
	n.HandleAppendEntries(AppendEntriesArgs{Term: 1, LeaderID: "n2"})

	reply := n.HandleRequestVote(RequestVoteArgs{Term: 2, CandidateID: "n3", PreVote: true})
	if reply.VoteGranted {
		t.Fatal("pré-vote accordé alors qu'un leader est actif")
	}

	n.mu.Lock()
	n.lastLeaderContact = time.Now().Add(-time.Hour)
	n.mu.Unlock()
	reply = n.HandleRequestVote(RequestVoteArgs{Term: 2, CandidateID: "n3", PreVote: true})
	if !reply.VoteGranted {
		t.Fatal("pré-vote refusé alors que le leader est silencieux")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.currentTerm != 1 || n.votedFor != "" {
		t.Fatalf("le pré-vote a modifié l'état : terme=%d votedFor=%q", n.currentTerm, n.votedFor)
	}
}

// TestSelfInPeersIgnored : la topologie poussée peut contenir le nœud
// lui-même, il ne doit pas se compter deux fois dans le quorum.
func TestSelfInPeersIgnored(t *testing.T) {
	n := NewNode(Config{ID: "n1", Peers: map[string]string{"n1": "n1", "n2": "n2"}}, nil, discardLogger())
	if _, ok := n.cfg.Peers["n1"]; ok {
		t.Fatal("le nœud figure parmi ses propres pairs")
	}
	n.UpdatePeers(map[string]string{"n1": "n1", "n3": "n3"})
	if _, ok := n.cfg.Peers["n1"]; ok || len(n.cfg.Peers) != 1 {
		t.Fatalf("UpdatePeers n'a pas retiré le nœud : %v", n.cfg.Peers)
	}
}

type countingTransport struct {
	*memTransport
	votes int
	mu    sync.Mutex
}

func (c *countingTransport) RequestVote(url string, args RequestVoteArgs) (RequestVoteReply, error) {
	c.mu.Lock()
	c.votes++
	c.mu.Unlock()
	return c.memTransport.RequestVote(url, args)
}

// TestNoQuorumBacksOff : tant que les pairs restent introuvables, les
// tentatives s'espacent au lieu de se répéter à chaque délai d'élection.
func TestNoQuorumBacksOff(t *testing.T) {
	tr := &countingTransport{memTransport: newMemTransport()}
	n := NewNode(Config{
		ID:                 "n1",
		Peers:              map[string]string{"n2": "n2", "n3": "n3"},
		ElectionTimeoutMin: 20 * time.Millisecond,
		ElectionTimeoutMax: 40 * time.Millisecond,
		HeartbeatInterval:  10 * time.Millisecond,
	}, tr, discardLogger())
	n.Start()
	defer n.Stop()

	time.Sleep(1500 * time.Millisecond)

	tr.mu.Lock()
	defer tr.mu.Unlock()
	// Sans espacement : ~50 tentatives x 2 pairs = ~100 requêtes.
	if tr.votes > 40 {
		t.Fatalf("%d requêtes de pré-vote en 1,5 s : pas d'espacement", tr.votes)
	}
	if tr.votes == 0 {
		t.Fatal("aucune tentative de pré-vote")
	}
}
