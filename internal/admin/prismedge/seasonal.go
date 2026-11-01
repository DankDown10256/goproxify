// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// GatewaySeasonal : la référence saisonnière du trafic d'une passerelle (ADR 0020, étape 3).
type GatewaySeasonal struct {
	NodeID   string                  `json:"node_id"`
	NodeName string                  `json:"node_name"`
	Traffic  logapi.SeasonalResponse `json:"traffic"`
}

// Seasonal demande à chaque passerelle (ou à celle de nodeName) la référence saisonnière de son trafic.
func (s *Source) Seasonal(ctx context.Context, nodeName string) ([]GatewaySeasonal, Meta, error) {
	out := []GatewaySeasonal{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*logapi.SeasonalResponse, error) {
			return c.Seasonal(ctx, t)
		},
		func(t edgeproxy.Target, r *logapi.SeasonalResponse) {
			out = append(out, GatewaySeasonal{NodeID: t.ID, NodeName: t.NodeName, Traffic: *r})
		})
	return out, m, err
}
