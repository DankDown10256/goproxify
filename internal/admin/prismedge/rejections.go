// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// GatewayRejections : ce que l'entrée d'une passerelle a refusé depuis son démarrage (ADR 0020, étape 1.c).
type GatewayRejections struct {
	NodeID   string                    `json:"node_id"`
	NodeName string                    `json:"node_name"`
	Rejected logapi.RejectionsResponse `json:"rejections"`
}

// Rejections demande à chaque passerelle (ou à celle de nodeName) ce que son entrée a refusé.
func (s *Source) Rejections(ctx context.Context, nodeName string) ([]GatewayRejections, Meta, error) {
	out := []GatewayRejections{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*logapi.RejectionsResponse, error) {
			return c.Rejections(ctx, t)
		},
		func(t edgeproxy.Target, r *logapi.RejectionsResponse) {
			out = append(out, GatewayRejections{NodeID: t.ID, NodeName: t.NodeName, Rejected: *r})
		})
	return out, m, err
}
