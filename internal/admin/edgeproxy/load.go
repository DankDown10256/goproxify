// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// db is kept in signatures for API compatibility (e.g. listing Edge targets from tokens table).

// LoadProductionEnvelopes loads unique production envelopes from all Edge targets.
func LoadProductionEnvelopes(ctx context.Context, db *sql.DB) ([]*proxystore.Envelope, error) {
	return loadFromEdges(ctx, db)
}

// LoadEnabledEnvelopes is like LoadProductionEnvelopes but only enabled=true.
func LoadEnabledEnvelopes(ctx context.Context, db *sql.DB) ([]*proxystore.Envelope, error) {
	all, err := loadFromEdges(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make([]*proxystore.Envelope, 0, len(all))
	for _, e := range all {
		if e != nil && e.Enabled {
			out = append(out, e)
		}
	}
	return out, nil
}

// LoadEnabledRoutes parses enabled envelopes into router.Route.
func LoadEnabledRoutes(ctx context.Context, db *sql.DB) ([]*router.Route, error) {
	envs, err := LoadEnabledEnvelopes(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make([]*router.Route, 0, len(envs))
	for _, e := range envs {
		var route router.Route
		if json.Unmarshal(e.Config, &route) != nil {
			continue
		}
		if route.ID == "" {
			route.ID = e.ID
		}
		out = append(out, &route)
	}
	return out, nil
}

func loadFromEdges(ctx context.Context, db *sql.DB) ([]*proxystore.Envelope, error) {
	targets, err := ListTargets(ctx, db)
	if err != nil {
		return nil, err
	}
	client := NewClient()
	byID := map[string]*proxystore.Envelope{}
	for _, t := range targets {
		res, err := client.List(ctx, t)
		if err != nil {
			continue
		}
		for _, e := range res.Production {
			if e != nil {
				byID[e.ID] = e
			}
		}
	}
	out := make([]*proxystore.Envelope, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	return out, nil
}

