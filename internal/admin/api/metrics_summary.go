// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"time"
)

var metricsSummaryClient = &http.Client{Timeout: 5 * time.Second}

// metricsSummary proxies GET /internal/v1/metrics/summary from the Core with the given node ID.
func (h *NodesHandler) metricsSummary(w http.ResponseWriter, r *http.Request, id string) {
	// Lookup node_name from nodes table
	var nodeName string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT node_name FROM nodes WHERE id=? OR node_name=?`, id, id,
	).Scan(&nodeName)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}

	// Lookup endpoint + token from tokens table (most recent active token)
	var endpoint, token string
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT node_endpoint, token FROM tokens
		 WHERE node_name=? AND role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		 ORDER BY created_at DESC LIMIT 1`, nodeName,
	).Scan(&endpoint, &token)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		endpoint+"/internal/v1/metrics/summary", nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := metricsSummaryClient.Do(req)
	if err != nil {
		if h.Log != nil {
			h.Log.Warn("metrics-summary: Core injoignable", "node", nodeName, "err", err)
		}
		writeErr(w, r, http.StatusBadGateway, "api.err.core_unreachable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeErr(w, r, http.StatusBadGateway, "api.err.core_error")
		return
	}

	var summary map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, summary)
}
