// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package coreproxy

import (
	"context"
	"fmt"
)

// SyncMissing publie sur target les proxies de production que ses pairs ont et
// qu'il n'a pas (Core resté hors ligne pendant un publishAll). Les proxies déjà
// présents ne sont pas touchés, et aucune suppression n'est propagée.
func (c *Client) SyncMissing(ctx context.Context, target Target, peers []Target) (int, error) {
	have, err := c.List(ctx, target)
	if err != nil {
		return 0, fmt.Errorf("list %s: %w", target.NodeName, err)
	}
	present := make(map[string]bool, len(have.Production))
	for _, e := range have.Production {
		present[e.ID] = true
	}

	synced := 0
	var lastErr error
	for _, peer := range peers {
		if peer.Endpoint == target.Endpoint {
			continue
		}
		res, err := c.List(ctx, peer)
		if err != nil {
			lastErr = err
			continue
		}
		for _, e := range res.Production {
			if present[e.ID] {
				continue
			}
			if _, err := c.Publish(ctx, target, e.ID, e.Host, e.Enabled, e.Config, e.CreatedBy); err != nil {
				lastErr = err
				continue
			}
			present[e.ID] = true
			synced++
		}
	}
	return synced, lastErr
}
