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

	// lastLeaderContact : dernier AppendEntries valide reçu d'un leader. Sert
	// au pré-vote : un nœud qui a un leader actif refuse de laisser un pair
	// lancer une élection (sinon un nœud isolé qui revient fait tomber le
	// leader sain avec son terme gonflé).
	lastLeaderContact time.Time
	preVoteRunning    atomic.Bool
	lastNoQuorumLog   time.Time
	// noQuorumStreak : pré-votes consécutifs sans quorum. Espace les tentatives
	// (backoff exponentiel) tant que les pairs restent introuvables ; remis à
	// zéro dès qu'un leader parle ou qu'un pré-vote aboutit.
	noQuorumStreak int

	// electionResetCh signale à la goroutine run() qu'un heartbeat/vote
	// valide a été reçu, pour reporter l'élection. Le timer d'élection
	// lui-même n'est possédé et manipulé que par cette goroutine (voir
	// runFollowerCandidate) : Reset/Stop d'un time.Timer depuis plusieurs
	// goroutines pendant qu'une autre lit son canal C est documenté comme
	// non sûr et provoquait des élections en boucle malgré des heartbeats
	// reçus à temps.
	electionResetCh chan struct{}
	// leaderCh notifie runFollowerCandidate qu'une élection lancée par ce
	// nœud vient d'aboutir de façon asynchrone (becomeLeader appelé depuis
	// une goroutine de dépouillement de vote). Sans cela, l'instance de
	// runFollowerCandidate déjà relancée en attendant l'issue du vote (le
	// résultat arrive après coup, dans une autre goroutine) ignore que le
	// nœud est devenu leader : à l'expiration de son propre timer, elle
	// rappelle startElection() sans vérifier l'état courant, ce qui
	// redégrade aussitôt le leader tout juste élu et fait grimper le
	// terme en boucle — aucun leader ne reste jamais assez longtemps en
	// poste pour committer quoi que ce soit.
	leaderCh chan struct{}
	stopCh   chan struct{}
	applyCh  chan LogEntry

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

	cfg.Peers = withoutSelf(cfg.ID, cfg.Peers)
	n := &Node{
		cfg:             cfg,
		log:             log,
		state:           Follower,
		logEntries:      []LogEntry{{Index: 0, Term: 0}}, // entrée sentinelle
		nextIndex:       make(map[string]uint64),
		matchIndex:      make(map[string]uint64),
		electionResetCh: make(chan struct{}, 1),
		leaderCh:        make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		applyCh:         make(chan LogEntry, 256),
		transport:       transport,
	}
	n.leaderID.Store("")
	return n
}

// Start démarre le nœud Raft.
func (n *Node) Start() {
	go n.applyLoop()
	go n.run()
}

// Stop arrête le nœud.
func (n *Node) Stop() {
	close(n.stopCh)
}

// ID retourne l'identifiant de ce nœud.
func (n *Node) ID() string { return n.cfg.ID }

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
	n.cfg.Peers = withoutSelf(n.cfg.ID, peers)
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

// runFollowerCandidate attend soit l'expiration du délai d'élection, soit un
// signal de reset (heartbeat ou vote valide reçu). Le timer est créé et
// uniquement manipulé ici, dans cette unique goroutine : c'est ce qui
// garantit que Reset/Stop/lecture de son canal restent data-race-free.
func (n *Node) runFollowerCandidate() {
	timer := time.NewTimer(n.randomElectionTimeout())
	defer timer.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-n.leaderCh:
			// Élection lancée par ce nœud gagnée entretemps (annoncée de
			// façon asynchrone par becomeLeader) : on rend la main à run()
			// pour qu'il bascule sur runLeader() au lieu de laisser cette
			// instance repartir sur son propre timer et redémarrer une
			// élection sans lieu d'être.
			return
		case <-n.electionResetCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(n.randomElectionTimeout())
		case <-timer.C:
			n.startElection()
			return
		}
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

// startElection lance un pré-vote auprès des pairs et ne démarre la vraie
// élection (terme incrémenté) que si une majorité répond qu'elle voterait pour
// ce nœud. Sans cela, un nœud dont les pairs sont injoignables incrémentait son
// terme à chaque timeout sans jamais pouvoir gagner : terme qui s'envole, log
// saturé, et un leader sain déposé dès le retour du nœud isolé.
func (n *Node) startElection() {
	n.mu.Lock()
	peers := n.cfg.Peers
	term := n.currentTerm
	lastLogIndex := uint64(len(n.logEntries) - 1)
	lastLogTerm := n.logEntries[lastLogIndex].Term
	n.mu.Unlock()

	if len(peers) == 0 {
		n.campaign(term, time.Time{})
		return
	}
	if !n.preVoteRunning.CompareAndSwap(false, true) {
		return
	}
	started := time.Now()
	go func() {
		defer n.preVoteRunning.Store(false)
		ok := n.preVote(peers, term, lastLogIndex, lastLogTerm)
		n.mu.Lock()
		if ok {
			n.noQuorumStreak = 0
		} else if n.noQuorumStreak < maxBackoffShift {
			n.noQuorumStreak++
		}
		n.mu.Unlock()
		if ok {
			n.campaign(term, started)
		}
	}()
}

// preVote retourne true si une majorité (soi compris) voterait pour ce nœud au
// terme term+1. N'altère ni le terme ni le vote de personne.
func (n *Node) preVote(peers map[string]string, term, lastLogIndex, lastLogTerm uint64) bool {
	quorum := (len(peers)+1)/2 + 1
	type result struct {
		reply RequestVoteReply
		err   error
	}
	results := make(chan result, len(peers))
	for _, peerURL := range peers {
		go func(purl string) {
			reply, err := n.transport.RequestVote(purl, RequestVoteArgs{
				Term:         term + 1,
				CandidateID:  n.cfg.ID,
				LastLogIndex: lastLogIndex,
				LastLogTerm:  lastLogTerm,
				PreVote:      true,
			})
			results <- result{reply, err}
		}(peerURL)
	}

	granted, reachable := 1, 0
	for range peers {
		r := <-results
		if r.err != nil {
			continue
		}
		reachable++
		if r.reply.Term > term {
			n.mu.Lock()
			if r.reply.Term > n.currentTerm {
				n.stepDown(r.reply.Term)
			}
			n.mu.Unlock()
			return false
		}
		if r.reply.VoteGranted {
			granted++
			if granted >= quorum {
				return true
			}
		}
	}
	n.logNoQuorum(reachable, len(peers))
	return false
}

// logNoQuorum signale l'absence de quorum au plus une fois par minute : une
// passerelle dont les pairs sont coupés retente toutes les ~200 ms.
func (n *Node) logNoQuorum(reachable, total int) {
	n.mu.Lock()
	due := time.Since(n.lastNoQuorumLog) > time.Minute
	if due {
		n.lastNoQuorumLog = time.Now()
	}
	n.mu.Unlock()
	if due {
		n.log.Warn("raft: pas de quorum, élection non lancée", "id", n.cfg.ID, "pairs_joignables", reachable, "pairs_total", total)
	}
}

// campaign démarre la vraie élection. expectedTerm est le terme observé avant
// le pré-vote : si un leader a parlé depuis since ou si le terme a changé, le
// pré-vote est périmé et on renonce.
func (n *Node) campaign(expectedTerm uint64, since time.Time) {
	n.mu.Lock()
	if n.currentTerm != expectedTerm || n.state == Leader || n.lastLeaderContact.After(since) {
		n.mu.Unlock()
		return
	}
	n.state = Candidate
	n.currentTerm++
	n.votedFor = n.cfg.ID
	term := n.currentTerm
	peers := n.cfg.Peers
	lastLogIndex := uint64(len(n.logEntries) - 1)
	lastLogTerm := n.logEntries[lastLogIndex].Term
	n.mu.Unlock()

	n.log.Info("raft: début élection", "id", n.cfg.ID, "term", term)

	votes := 1 // vote pour soi-même
	total := len(peers) + 1
	quorum := total/2 + 1

	if votes >= quorum {
		n.becomeLeader(term)
		return
	}

	var mu sync.Mutex
	for peerID, peerURL := range peers {
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
					n.becomeLeader(term)
				}
			}
		}(peerID, peerURL)
	}
}

// becomeLeader ne promeut le nœud que si l'élection gagnée est toujours celle
// du terme courant : le dépouillement est asynchrone, et des votes tardifs
// d'un terme révolu ne doivent pas élire le nœud dans un terme plus récent.
func (n *Node) becomeLeader(term uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != Candidate || n.currentTerm != term {
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

	select {
	case n.leaderCh <- struct{}{}:
	default:
	}
}

func (n *Node) stepDown(term uint64) {
	n.state = Follower
	n.currentTerm = term
	n.votedFor = ""
	n.signalElectionReset()
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
	peers := n.cfg.Peers
	n.mu.Unlock()

	replicated := 1
	total := len(peers) + 1
	quorum := total/2 + 1
	var mu sync.Mutex

	for peerID, peerURL := range peers {
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

	lastLogIndex := uint64(len(n.logEntries) - 1)
	lastLogTerm := n.logEntries[lastLogIndex].Term
	logOK := args.LastLogTerm > lastLogTerm ||
		(args.LastLogTerm == lastLogTerm && args.LastLogIndex >= lastLogIndex)

	if args.PreVote {
		leaderAlive := n.state == Leader || time.Since(n.lastLeaderContact) < n.cfg.ElectionTimeoutMin
		reply.VoteGranted = args.Term > n.currentTerm && logOK && !leaderAlive
		return reply
	}

	if args.Term < n.currentTerm {
		return reply
	}
	if args.Term > n.currentTerm {
		n.stepDown(args.Term)
	}

	if (n.votedFor == "" || n.votedFor == args.CandidateID) && logOK {
		n.votedFor = args.CandidateID
		n.signalElectionReset()
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
	n.lastLeaderContact = time.Now()
	n.noQuorumStreak = 0
	n.signalElectionReset()

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

// maxBackoffShift borne l'espacement à 16 fois le délai d'élection (≈ 5 s avec
// les 150-300 ms par défaut).
const maxBackoffShift = 4

func (n *Node) randomElectionTimeout() time.Duration {
	n.mu.Lock()
	shift := n.noQuorumStreak
	n.mu.Unlock()
	base := n.cfg.ElectionTimeoutMin +
		time.Duration(rand.Int63n(int64(n.cfg.ElectionTimeoutMax-n.cfg.ElectionTimeoutMin)))
	return base << shift
}

// withoutSelf copie les pairs en retirant ce nœud : s'il figure dans la
// topologie reçue, il se compterait deux fois dans les quorums.
func withoutSelf(self string, peers map[string]string) map[string]string {
	out := make(map[string]string, len(peers))
	for id, url := range peers {
		if id != self {
			out[id] = url
		}
	}
	return out
}

// signalElectionReset notifie runFollowerCandidate qu'un événement valide
// (heartbeat, vote accordé) vient d'être reçu, sans jamais toucher au timer
// lui-même : seule la goroutine run() le manipule. L'envoi est non-bloquant
// (canal bufferisé à 1) : un reset déjà en attente suffit, inutile d'en
// empiler d'autres.
func (n *Node) signalElectionReset() {
	select {
	case n.electionResetCh <- struct{}{}:
	default:
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
