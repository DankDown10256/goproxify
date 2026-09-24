// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// McpAccessHandler expose, pour les admins, une vue d'ensemble du périmètre
// d'accès MCP : catalogue de scopes ↔ outils, et PAT actifs système entier
// (lecture seule — la création/révocation d'un PAT reste self-service sur
// /me/tokens, un PAT est personnel).
type McpAccessHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *McpAccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp-access")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "scopes":
		h.scopes(w, r)
	case r.Method == http.MethodGet && path == "tokens":
		h.tokens(w, r)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

type mcpScopeRow struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Tools       []string `json:"tools"`
}

func (h *McpAccessHandler) scopes(w http.ResponseWriter, r *http.Request) {
	catalog := rbac.ScopeCatalog()
	out := make([]mcpScopeRow, 0, len(catalog))
	for _, s := range catalog {
		tools := rbac.ToolsForScope(s.ID)
		if tools == nil {
			tools = []string{}
		}
		out = append(out, mcpScopeRow{ID: s.ID, Description: s.Description, Tools: tools})
	}
	jsonOK(w, out)
}

type mcpTokenRow struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	OwnerEmail string     `json:"owner_email"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (h *McpAccessHandler) tokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT t.id, t.label, u.email, t.expires_at, t.last_used_at, t.created_at
		FROM user_api_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.revoked = 0
		ORDER BY t.created_at DESC`)
	if err != nil {
		h.Log.Error("mcp_access: list tokens", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	var out []mcpTokenRow
	for rows.Next() {
		var tok mcpTokenRow
		var expiresAt, lastUsedAt sql.NullTime
		if err := rows.Scan(&tok.ID, &tok.Label, &tok.OwnerEmail, &expiresAt, &lastUsedAt, &tok.CreatedAt); err != nil {
			continue
		}
		if expiresAt.Valid {
			tok.ExpiresAt = &expiresAt.Time
		}
		if lastUsedAt.Valid {
			tok.LastUsedAt = &lastUsedAt.Time
		}
		scopeRows, err := h.DB.QueryContext(r.Context(),
			`SELECT scope FROM user_api_token_scopes WHERE token_id = ? ORDER BY scope`, tok.ID)
		if err == nil {
			for scopeRows.Next() {
				var s string
				if scopeRows.Scan(&s) == nil {
					tok.Scopes = append(tok.Scopes, s)
				}
			}
			scopeRows.Close()
		}
		if tok.Scopes == nil {
			tok.Scopes = []string{}
		}
		out = append(out, tok)
	}
	jsonOK(w, out)
}
