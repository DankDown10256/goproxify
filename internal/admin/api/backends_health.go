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
)

// BackendsHealthHandler agrège l'état santé des backends depuis tous les Cores actifs
// via GET /internal/v1/backends/health.
type BackendsHealthHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *BackendsHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	jsonOK(w, map[string]any{"backends": h.fetchFromCores(r.Context())})
}

func (h *BackendsHealthHandler) fetchFromCores(ctx context.Context) map[string]string {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT node_name, node_endpoint, token FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		if h.Log != nil {
			h.Log.Warn("backends-health: query tokens", "err", err)
		}
		return map[string]string{}
	}
	defer rows.Close()

	type coreCred struct {
		name, endpoint, token string
	}
	var cores []coreCred
	for rows.Next() {
		var c coreCred
		if err := rows.Scan(&c.name, &c.endpoint, &c.token); err != nil {
			continue
		}
		cores = append(cores, c)
	}

	var mu sync.Mutex
	merged := make(map[string]string)
	var wg sync.WaitGroup
	for _, c := range cores {
		wg.Add(1)
		go func(c coreCred) {
			defer wg.Done()
			part := h.fetchFromCore(ctx, c.endpoint, c.token, c.name)
			if len(part) == 0 {
				return
			}
			mu.Lock()
			for url, st := range part {
				// down gagne toujours ; up ne remplace pas down.
				prev, ok := merged[url]
				if !ok || st == "down" || (st == "up" && prev == "unknown") {
					merged[url] = st
				}
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return merged
}

func (h *BackendsHealthHandler) fetchFromCore(ctx context.Context, coreEndpoint, token, coreName string) map[string]string {
	warn := func(msg string, args ...any) {
		if h.Log != nil {
			h.Log.Warn(msg, args...)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		coreEndpoint+"/internal/v1/backends/health", nil)
	if err != nil {
		warn("backends-health: requête invalide", "core", coreName, "endpoint", coreEndpoint, "err", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		warn("backends-health: Core injoignable", "core", coreName, "endpoint", coreEndpoint, "err", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		warn("backends-health: Core a refusé", "core", coreName, "endpoint", coreEndpoint, "status", resp.StatusCode)
		return nil
	}
	var payload struct {
		Backends map[string]string `json:"backends"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		warn("backends-health: JSON invalide", "core", coreName, "err", err)
		return nil
	}
	return payload.Backends
}
