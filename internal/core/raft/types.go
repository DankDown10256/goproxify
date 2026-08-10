// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package raft implémente l'algorithme de consensus Raft utilisé par les Cores
// (élection de coordinateur de groupe) et l'Administration (HA multi-nœuds).
package raft

import "time"

// State représente l'état d'un nœud Raft.
type State int

const (
	Follower  State = iota
	Candidate State = iota
	Leader    State = iota
)

func (s State) String() string {
	switch s {
	case Follower:
		return "follower"
	case Candidate:
		return "candidate"
	case Leader:
		return "leader"
	}
	return "unknown"
}

// LogEntry est une entrée dans le journal Raft.
type LogEntry struct {
	Index   uint64 `json:"index"`
	Term    uint64 `json:"term"`
	Command []byte `json:"command"` // payload opaque (JSON de la commande)
}

// RequestVoteArgs est envoyé par un candidat pour demander un vote.
type RequestVoteArgs struct {
	Term         uint64 `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex uint64 `json:"last_log_index"`
	LastLogTerm  uint64 `json:"last_log_term"`
}

// RequestVoteReply est la réponse à RequestVote.
type RequestVoteReply struct {
	Term        uint64 `json:"term"`
	VoteGranted bool   `json:"vote_granted"`
}

// AppendEntriesArgs est envoyé par le leader (heartbeat ou réplication).
type AppendEntriesArgs struct {
	Term         uint64     `json:"term"`
	LeaderID     string     `json:"leader_id"`
	PrevLogIndex uint64     `json:"prev_log_index"`
	PrevLogTerm  uint64     `json:"prev_log_term"`
	Entries      []LogEntry `json:"entries"`
	LeaderCommit uint64     `json:"leader_commit"`
}

// AppendEntriesReply est la réponse à AppendEntries.
type AppendEntriesReply struct {
	Term    uint64 `json:"term"`
	Success bool   `json:"success"`
	// ConflictIndex aide le leader à reculer rapidement en cas de conflit.
	ConflictIndex uint64 `json:"conflict_index,omitempty"`
}

// Config configure un nœud Raft.
type Config struct {
	// ID unique du nœud (ex: "core-1")
	ID string
	// Peers : map id → URL HTTP (ex: "core-2" → "http://10.0.0.2:8002")
	Peers map[string]string
	// Timeouts
	ElectionTimeoutMin  time.Duration // défaut: 150ms
	ElectionTimeoutMax  time.Duration // défaut: 300ms
	HeartbeatInterval   time.Duration // défaut: 50ms
	// ApplyFunc est appelée quand une entrée est committée.
	ApplyFunc func(entry LogEntry)
}
