// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// Server expose les endpoints HTTP Raft d'un nœud.
type Server struct {
	node   *Node
	port   int
	log    *slog.Logger
	httpSrv *http.Server
}

// NewServer crée un serveur HTTP Raft.
func NewServer(node *Node, port int, log *slog.Logger) *Server {
	return &Server{node: node, port: port, log: log}
}

// Start démarre le serveur HTTP sur le port configuré.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/raft/vote", s.handleVote)
	mux.HandleFunc("/raft/append", s.handleAppend)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("raft server: listen: %w", err)
	}
	s.httpSrv = &http.Server{Handler: mux}
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("raft server: serve error", "err", err)
		}
	}()
	s.log.Info("raft server démarré", "port", s.port)
	return nil
}

func (s *Server) handleVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var args RequestVoteArgs
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	reply := s.node.HandleRequestVote(args)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply) //nolint:errcheck
}

func (s *Server) handleAppend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var args AppendEntriesArgs
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	reply := s.node.HandleAppendEntries(args)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply) //nolint:errcheck
}
