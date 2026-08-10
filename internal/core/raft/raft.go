// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// Node est un nœud Raft complet.
type Node struct {
	cfg Config
	log *slog.Logger

	mu          sync.Mutex
	state       State
	currentTerm uint64
	votedFor    string
	logEntries  []LogEntry
	commitIndex uint64
	lastApplied uint64

	// Leader state
	nextIndex  map[string]uint64 // peer → prochain index à envoyer
	matchIndex map[string]uint64 // peer → dernier index confirmé

	leaderID atomic.Value // string

	electionTimer *time.Timer
	stopCh        chan struct{}
	applyCh       chan LogEntry

	transport Transport
}

// NewNode crée un nœud Raft avec la config donnée.
func NewNode(cfg Config, transport Transport, log *slog.Logger) *Node {
	if cfg.ElectionTimeoutMin == 0 {
		cfg.ElectionTimeoutMin = 150 * time.Millisecond
	}
	if cfg.ElectionTimeoutMax == 0 {
		cfg.ElectionTimeoutMax = 300 * time.Millisecond
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 50 * time.Millisecond
	}

	n := &Node{
		cfg:        cfg,
		log:        log,
		state:      Follower,
		logEntries: []LogEntry{{Index: 0, Term: 0}}, // entrée sentinelle
		nextIndex:  make(map[string]uint64),
		matchIndex: make(map[string]uint64),
		stopCh:     make(chan struct{}),
		applyCh:    make(chan LogEntry, 256),
		transport:  transport,
	}
	n.leaderID.Store("")
	return n
}

// Start démarre le nœud Raft.
func (n *Node) Start() {
	go n.applyLoop()
	n.resetElectionTimer()
	go n.run()
}

// Stop arrête le nœud.
func (n *Node) Stop() {
	close(n.stopCh)
}

// State retourne l'état courant du nœud.
func (n *Node) State() State {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

// LeaderID retourne l'ID du leader actuel (vide si inconnu).
func (n *Node) LeaderID() string {
	v := n.leaderID.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// UpdatePeers met à jour la liste des pairs Raft à chaud.
// Utilisé pour recevoir la topologie cluster poussée par Admin.
func (n *Node) UpdatePeers(peers map[string]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	newPeers := make(map[string]string, len(peers))
	for k, v := range peers {
		newPeers[k] = v
	}
	n.cfg.Peers = newPeers
}

// IsLeader retourne true si ce nœud est le leader.
func (n *Node) IsLeader() bool {
	return n.State() == Leader
}

// Propose soumet une commande au cluster Raft.
// Retourne une erreur si le nœud n'est pas leader.
func (n *Node) Propose(command []byte) error {
	n.mu.Lock()
	if n.state != Leader {
		n.mu.Unlock()
		return ErrNotLeader{LeaderID: n.LeaderID()}
	}
	entry := LogEntry{
		Index:   uint64(len(n.logEntries)),
		Term:    n.currentTerm,
		Command: command,
	}
	n.logEntries = append(n.logEntries, entry)
	n.mu.Unlock()

	// Réplication immédiate
	go n.broadcastAppendEntries()
	return nil
}

// --- Boucle principale ----------------------------------------------------

func (n *Node) run() {
	for {
		select {
		case <-n.stopCh:
			return
		default:
		}

		n.mu.Lock()
		state := n.state
		n.mu.Unlock()

		switch state {
		case Follower, Candidate:
			n.runFollowerCandidate()
		case Leader:
			n.runLeader()
		}
	}
}

func (n *Node) runFollowerCandidate() {
	select {
	case <-n.stopCh:
	case <-n.electionTimer.C:
		n.startElection()
	}
}

func (n *Node) runLeader() {
	ticker := time.NewTicker(n.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			n.mu.Lock()
			if n.state != Leader {
				n.mu.Unlock()
				return
			}
			n.mu.Unlock()
			n.broadcastAppendEntries()
		}
	}
}

// --- Élection -------------------------------------------------------------

func (n *Node) startElection() {
	n.mu.Lock()
	n.state = Candidate
	n.currentTerm++
	n.votedFor = n.cfg.ID
	term := n.currentTerm
	lastLogIndex := uint64(len(n.logEntries) - 1)
	lastLogTerm := n.logEntries[lastLogIndex].Term
	n.mu.Unlock()

	n.log.Info("raft: début élection", "id", n.cfg.ID, "term", term)
	n.resetElectionTimer()

	votes := 1 // vote pour soi-même
	total := len(n.cfg.Peers) + 1
	quorum := total/2 + 1

	var mu sync.Mutex
	for peerID, peerURL := range n.cfg.Peers {
		go func(pid, purl string) {
			reply, err := n.transport.RequestVote(purl, RequestVoteArgs{
				Term:         term,
				CandidateID:  n.cfg.ID,
				LastLogIndex: lastLogIndex,
				LastLogTerm:  lastLogTerm,
			})
			if err != nil {
				return
			}
			n.mu.Lock()
			if reply.Term > n.currentTerm {
				n.stepDown(reply.Term)
				n.mu.Unlock()
				return
			}
			n.mu.Unlock()

			if reply.VoteGranted {
				mu.Lock()
				votes++
				won := votes >= quorum
				mu.Unlock()
				if won {
					n.becomeLeader()
				}
			}
		}(peerID, peerURL)
	}
}

func (n *Node) becomeLeader() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != Candidate {
		return
	}
	n.state = Leader
	n.leaderID.Store(n.cfg.ID)
	// Initialise nextIndex et matchIndex
	nextIdx := uint64(len(n.logEntries))
	for pid := range n.cfg.Peers {
		n.nextIndex[pid] = nextIdx
		n.matchIndex[pid] = 0
	}
	n.log.Info("raft: élu leader", "id", n.cfg.ID, "term", n.currentTerm)
}

func (n *Node) stepDown(term uint64) {
	n.state = Follower
	n.currentTerm = term
	n.votedFor = ""
	n.resetElectionTimer()
}

// --- AppendEntries --------------------------------------------------------

func (n *Node) broadcastAppendEntries() {
	n.mu.Lock()
	if n.state != Leader {
		n.mu.Unlock()
		return
	}
	term := n.currentTerm
	leaderCommit := n.commitIndex
	logLen := uint64(len(n.logEntries))
	n.mu.Unlock()

	replicated := 1
	total := len(n.cfg.Peers) + 1
	quorum := total/2 + 1
	var mu sync.Mutex

	for peerID, peerURL := range n.cfg.Peers {
		go func(pid, purl string) {
			n.mu.Lock()
			ni := n.nextIndex[pid]
			if ni == 0 {
				ni = 1
			}
			prevLogIndex := ni - 1
			prevLogTerm := uint64(0)
			if prevLogIndex < uint64(len(n.logEntries)) {
				prevLogTerm = n.logEntries[prevLogIndex].Term
			}
			entries := []LogEntry{}
			if ni < logLen {
				entries = n.logEntries[ni:]
			}
			n.mu.Unlock()

			reply, err := n.transport.AppendEntries(purl, AppendEntriesArgs{
				Term:         term,
				LeaderID:     n.cfg.ID,
				PrevLogIndex: prevLogIndex,
				PrevLogTerm:  prevLogTerm,
				Entries:      entries,
				LeaderCommit: leaderCommit,
			})
			if err != nil {
				return
			}

			n.mu.Lock()
			defer n.mu.Unlock()

			if reply.Term > n.currentTerm {
				n.stepDown(reply.Term)
				return
			}
			if n.state != Leader {
				return
			}

			if reply.Success {
				newMatch := prevLogIndex + uint64(len(entries))
				if newMatch > n.matchIndex[pid] {
					n.matchIndex[pid] = newMatch
					n.nextIndex[pid] = newMatch + 1
				}
				mu.Lock()
				replicated++
				if replicated >= quorum {
					n.maybeCommit()
				}
				mu.Unlock()
			} else {
				// Recule nextIndex
				if reply.ConflictIndex > 0 {
					n.nextIndex[pid] = reply.ConflictIndex
				} else if n.nextIndex[pid] > 1 {
					n.nextIndex[pid]--
				}
			}
		}(peerID, peerURL)
	}
}

// maybeCommit avance commitIndex au plus grand index répliqué sur la majorité.
// Doit être appelé avec n.mu verrouillé.
func (n *Node) maybeCommit() {
	logLen := uint64(len(n.logEntries))
	for idx := logLen - 1; idx > n.commitIndex; idx-- {
		if n.logEntries[idx].Term != n.currentTerm {
			continue
		}
		// Compte les pairs qui ont répliqué cet index
		count := 1
		for _, mi := range n.matchIndex {
			if mi >= idx {
				count++
			}
		}
		if count > (len(n.cfg.Peers)+1)/2 {
			n.commitIndex = idx
			break
		}
	}
}

// --- Application ----------------------------------------------------------

func (n *Node) applyLoop() {
	for {
		select {
		case <-n.stopCh:
			return
		default:
		}
		n.mu.Lock()
		for n.lastApplied < n.commitIndex {
			n.lastApplied++
			entry := n.logEntries[n.lastApplied]
			n.mu.Unlock()
			if n.cfg.ApplyFunc != nil {
				n.cfg.ApplyFunc(entry)
			}
			n.mu.Lock()
		}
		n.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
}

// --- Gestion des RPCs entrants --------------------------------------------

// HandleRequestVote traite un RequestVote reçu d'un candidat.
func (n *Node) HandleRequestVote(args RequestVoteArgs) RequestVoteReply {
	n.mu.Lock()
	defer n.mu.Unlock()

	reply := RequestVoteReply{Term: n.currentTerm}

	if args.Term < n.currentTerm {
		return reply
	}
	if args.Term > n.currentTerm {
		n.stepDown(args.Term)
	}

	lastLogIndex := uint64(len(n.logEntries) - 1)
	lastLogTerm := n.logEntries[lastLogIndex].Term
	logOK := args.LastLogTerm > lastLogTerm ||
		(args.LastLogTerm == lastLogTerm && args.LastLogIndex >= lastLogIndex)

	if (n.votedFor == "" || n.votedFor == args.CandidateID) && logOK {
		n.votedFor = args.CandidateID
		n.resetElectionTimer()
		reply.VoteGranted = true
	}
	reply.Term = n.currentTerm
	return reply
}

// HandleAppendEntries traite un AppendEntries reçu du leader.
func (n *Node) HandleAppendEntries(args AppendEntriesArgs) AppendEntriesReply {
	n.mu.Lock()
	defer n.mu.Unlock()

	reply := AppendEntriesReply{Term: n.currentTerm}

	if args.Term < n.currentTerm {
		return reply
	}
	if args.Term > n.currentTerm || n.state == Candidate {
		n.stepDown(args.Term)
	}
	n.leaderID.Store(args.LeaderID)
	n.resetElectionTimer()

	// Vérifie la cohérence du log précédent
	if args.PrevLogIndex >= uint64(len(n.logEntries)) ||
		n.logEntries[args.PrevLogIndex].Term != args.PrevLogTerm {
		ci := uint64(len(n.logEntries))
		if ci > 0 {
			ci--
		}
		reply.ConflictIndex = ci
		return reply
	}

	// Ajoute les nouvelles entrées
	for i, entry := range args.Entries {
		idx := args.PrevLogIndex + 1 + uint64(i)
		if idx < uint64(len(n.logEntries)) {
			if n.logEntries[idx].Term != entry.Term {
				n.logEntries = n.logEntries[:idx]
				n.logEntries = append(n.logEntries, args.Entries[i:]...)
				break
			}
		} else {
			n.logEntries = append(n.logEntries, args.Entries[i:]...)
			break
		}
	}

	// Met à jour commitIndex
	if args.LeaderCommit > n.commitIndex {
		lastNew := args.PrevLogIndex + uint64(len(args.Entries))
		if args.LeaderCommit < lastNew {
			n.commitIndex = args.LeaderCommit
		} else {
			n.commitIndex = lastNew
		}
	}

	reply.Success = true
	reply.Term = n.currentTerm
	return reply
}

// --- Helpers --------------------------------------------------------------

func (n *Node) resetElectionTimer() {
	timeout := n.cfg.ElectionTimeoutMin +
		time.Duration(rand.Int63n(int64(n.cfg.ElectionTimeoutMax-n.cfg.ElectionTimeoutMin)))
	if n.electionTimer == nil {
		n.electionTimer = time.NewTimer(timeout)
	} else {
		if !n.electionTimer.Stop() {
			select {
			case <-n.electionTimer.C:
			default:
			}
		}
		n.electionTimer.Reset(timeout)
	}
}

// ErrNotLeader est retourné par Propose si le nœud n'est pas leader.
type ErrNotLeader struct {
	LeaderID string
}

func (e ErrNotLeader) Error() string {
	if e.LeaderID == "" {
		return "raft: pas de leader connu"
	}
	return "raft: nœud non-leader, leader=" + e.LeaderID
}
