// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// GatewayTLSReputation : la réputation des empreintes TLS d'une passerelle (ADR 0020, étape 4.c).
type GatewayTLSReputation struct {
	NodeID     string                       `json:"node_id"`
	NodeName   string                       `json:"node_name"`
	Reputation logapi.TLSReputationResponse `json:"reputation"`
}

// TLSReputation demande à chaque passerelle (ou à celle de nodeName) la réputation de ses empreintes TLS.
func (s *Source) TLSReputation(ctx context.Context, nodeName string) ([]GatewayTLSReputation, Meta, error) {
	out := []GatewayTLSReputation{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*logapi.TLSReputationResponse, error) {
			return c.TLSReputation(ctx, t)
		},
		func(t edgeproxy.Target, r *logapi.TLSReputationResponse) {
			out = append(out, GatewayTLSReputation{NodeID: t.ID, NodeName: t.NodeName, Reputation: *r})
		})
	return out, m, err
}
