// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"log/slog"
	"sync"
)

// NetworkManager connecte le conteneur passerelle aux réseaux Docker des apps découvertes.
type NetworkManager struct {
	client            *Client
	edgeContainerName string
	log               *slog.Logger
	mu                sync.Mutex
	connected         map[string]bool // networkID → true si déjà connecté
}

// NewNetworkManager crée un NetworkManager.
func NewNetworkManager(client *Client, edgeContainerName string, log *slog.Logger) *NetworkManager {
	return &NetworkManager{
		client:            client,
		edgeContainerName: edgeContainerName,
		log:               log,
		connected:         make(map[string]bool),
	}
}

// ConnectEdgeToNetwork connecte la passerelle au réseau Docker s'il n'y est pas déjà.
func (m *NetworkManager) ConnectEdgeToNetwork(ctx context.Context, networkID string) error {
	if networkID == "" || m.edgeContainerName == "" {
		return nil
	}

	m.mu.Lock()
	if m.connected[networkID] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	err := m.client.Post(ctx, "/networks/"+networkID+"/connect",
		NetworkConnectBody{Container: m.edgeContainerName}, nil)
	if err != nil {
		// 403 / 409 = déjà connecté — pas une vraie erreur
		return nil
	}

	m.mu.Lock()
	m.connected[networkID] = true
	m.mu.Unlock()

	m.log.Info("docker: Passerelle connectée au réseau", "network", networkID, "edge", m.edgeContainerName)
	return nil
}

// DisconnectEdgeFromNetwork déconnecte la passerelle d'un réseau Docker.
func (m *NetworkManager) DisconnectEdgeFromNetwork(ctx context.Context, networkID string) error {
	if networkID == "" || m.edgeContainerName == "" {
		return nil
	}
	err := m.client.Post(ctx, "/networks/"+networkID+"/disconnect",
		NetworkConnectBody{Container: m.edgeContainerName}, nil)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.connected, networkID)
	m.mu.Unlock()
	m.log.Info("docker: Passerelle déconnecté du réseau", "network", networkID)
	return nil
}
