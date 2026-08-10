// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

// DiscoveredContainersHandler agrège les conteneurs découverts par les Agents
// depuis tous les Cores actifs via GET /internal/v1/agent/containers.
type DiscoveredContainersHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type discoveredContainer struct {
	ID           string         `json:"id"`
	Host         string         `json:"host"`
	Aliases      []string       `json:"aliases,omitempty"`
	Backends     []string       `json:"backends"`
	ContainerIDs []string       `json:"container_ids,omitempty"`
	TLS          bool           `json:"tls"`
	Source       string         `json:"source"`
	CoreName     string         `json:"core_name"`
	AgentName    string         `json:"agent_name,omitempty"`
	Config       map[string]any `json:"config,omitempty"`
}

func (h *DiscoveredContainersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	result := h.fetchFromCores(r.Context())
	jsonOK(w, result)
}

func (h *DiscoveredContainersHandler) fetchFromCores(ctx context.Context) []discoveredContainer {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT node_name, node_endpoint, token FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return []discoveredContainer{}
	}
	defer rows.Close()

	type coreInfo struct{ name, endpoint, token string }
	var cores []coreInfo
	for rows.Next() {
		var c coreInfo
		if rows.Scan(&c.name, &c.endpoint, &c.token) == nil && c.endpoint != "" {
			c.token = auth.PlainNodeToken(c.token)
			cores = append(cores, c)
		}
	}

	var mu sync.Mutex
	var result []discoveredContainer
	var wg sync.WaitGroup

	for _, c := range cores {
		wg.Add(1)
		go func(name, ep, tok string) {
			defer wg.Done()
			items := h.fetchContainersFromCore(ctx, ep, tok)
			for i := range items {
				items[i].CoreName = name
			}
			mu.Lock()
			result = append(result, items...)
			mu.Unlock()
		}(c.name, c.endpoint, c.token)
	}
	wg.Wait()
	return result
}

func (h *DiscoveredContainersHandler) fetchContainersFromCore(ctx context.Context, coreEndpoint, token string) []discoveredContainer {
	warn := func(msg string, args ...any) {
		if h.Log != nil {
			h.Log.Warn(msg, args...)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		coreEndpoint+"/internal/v1/agent/containers", nil)
	if err != nil {
		warn("discovered-containers: requête invalide", "endpoint", coreEndpoint, "err", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		warn("discovered-containers: Core injoignable", "endpoint", coreEndpoint, "err", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		warn("discovered-containers: Core a refusé", "endpoint", coreEndpoint, "status", resp.StatusCode)
		return nil
	}
	var items []discoveredContainer
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		warn("discovered-containers: JSON invalide", "endpoint", coreEndpoint, "err", err)
		return nil
	}
	return items
}
