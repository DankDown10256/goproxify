// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"encoding/json"
	"fmt"

	"github.com/vincamok/goproxify/internal/core/raft"
)

// CommandType distingue les types de commandes répliquées via Raft.
type CommandType string

const (
	CmdPushRoutes CommandType = "push_routes"
	CmdPushCert   CommandType = "push_cert"
)

// Command est le payload sérialisé dans le log Raft.
type Command struct {
	Type    CommandType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// RoutesPayload est le payload pour CmdPushRoutes.
type RoutesPayload struct {
	Routes []json.RawMessage `json:"routes"`
}

// CertPayload est le payload pour CmdPushCert.
// La clé privée n'est jamais persistée — elle transite uniquement en RAM.
type CertPayload struct {
	Name    string `json:"name"`
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
}

// ProposeRoutes réplique un ensemble de routes vers tous les membres du groupe.
func (g *Group) ProposeRoutes(routes []json.RawMessage) error {
	payload, err := json.Marshal(RoutesPayload{Routes: routes})
	if err != nil {
		return fmt.Errorf("cluster: marshal routes: %w", err)
	}
	cmd, err := json.Marshal(Command{Type: CmdPushRoutes, Payload: payload})
	if err != nil {
		return fmt.Errorf("cluster: marshal command: %w", err)
	}
	return g.Propose(cmd)
}

// ProposeCert réplique un certificat (cert + clé) vers tous les membres.
// La clé privée transite uniquement en RAM, jamais stockée.
func (g *Group) ProposeCert(name string, certPEM, keyPEM []byte) error {
	payload, err := json.Marshal(CertPayload{Name: name, CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		return fmt.Errorf("cluster: marshal cert: %w", err)
	}
	cmd, err := json.Marshal(Command{Type: CmdPushCert, Payload: payload})
	if err != nil {
		return fmt.Errorf("cluster: marshal command: %w", err)
	}
	return g.Propose(cmd)
}

// DecodeCommand désérialise une entrée de log Raft en Command.
func DecodeCommand(entry raft.LogEntry) (Command, error) {
	var cmd Command
	if err := json.Unmarshal(entry.Command, &cmd); err != nil {
		return cmd, fmt.Errorf("cluster: decode command: %w", err)
	}
	return cmd, nil
}
