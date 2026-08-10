// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"log/slog"
	"sync"
)

// NetworkManager connecte le conteneur Core aux réseaux Docker des apps découvertes.
type NetworkManager struct {
	client            *Client
	coreContainerName string
	log               *slog.Logger
	mu                sync.Mutex
	connected         map[string]bool // networkID → true si déjà connecté
}

// NewNetworkManager crée un NetworkManager.
func NewNetworkManager(client *Client, coreContainerName string, log *slog.Logger) *NetworkManager {
	return &NetworkManager{
		client:            client,
		coreContainerName: coreContainerName,
		log:               log,
		connected:         make(map[string]bool),
	}
}

// ConnectCoreToNetwork connecte le Core au réseau Docker s'il n'y est pas déjà.
func (m *NetworkManager) ConnectCoreToNetwork(ctx context.Context, networkID string) error {
	if networkID == "" || m.coreContainerName == "" {
		return nil
	}

	m.mu.Lock()
	if m.connected[networkID] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	err := m.client.Post(ctx, "/networks/"+networkID+"/connect",
		NetworkConnectBody{Container: m.coreContainerName}, nil)
	if err != nil {
		// 403 / 409 = déjà connecté — pas une vraie erreur
		return nil
	}

	m.mu.Lock()
	m.connected[networkID] = true
	m.mu.Unlock()

	m.log.Info("docker: Core connecté au réseau", "network", networkID, "core", m.coreContainerName)
	return nil
}

// DisconnectCoreFromNetwork déconnecte le Core d'un réseau Docker.
func (m *NetworkManager) DisconnectCoreFromNetwork(ctx context.Context, networkID string) error {
	if networkID == "" || m.coreContainerName == "" {
		return nil
	}
	err := m.client.Post(ctx, "/networks/"+networkID+"/disconnect",
		NetworkConnectBody{Container: m.coreContainerName}, nil)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.connected, networkID)
	m.mu.Unlock()
	m.log.Info("docker: Core déconnecté du réseau", "network", networkID)
	return nil
}
