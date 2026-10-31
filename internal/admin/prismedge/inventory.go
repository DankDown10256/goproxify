// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// GatewayInventory : les applications qu'une passerelle reconnaît derrière ses proxies (ADR 0017).
type GatewayInventory struct {
	NodeID   string                  `json:"node_id"`
	NodeName string                  `json:"node_name"`
	Entries  []logapi.InventoryEntry `json:"entries"`
}

// Inventory demande à chaque passerelle (ou à celle de nodeName) les applications qu'elle reconnaît, éventuellement pour le seul proxy route.
func (s *Source) Inventory(ctx context.Context, nodeName, route string) ([]GatewayInventory, Meta, error) {
	out := []GatewayInventory{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) ([]logapi.InventoryEntry, error) {
			r, err := c.Inventory(ctx, t, route)
			if err != nil {
				return nil, err
			}
			return r.Entries, nil
		},
		func(t edgeproxy.Target, e []logapi.InventoryEntry) {
			out = append(out, GatewayInventory{NodeID: t.ID, NodeName: t.NodeName, Entries: e})
		})
	return out, m, err
}
