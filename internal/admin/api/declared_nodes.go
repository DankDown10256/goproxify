// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DeclaredNodesHandler gère les nœuds déclarés via l'assistant Infrastructure.
// Ces nœuds sont configurés mais pas encore connectés (status "declared").
type DeclaredNodesHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type declaredNode struct {
	ID          string          `json:"id"`
	Role        string          `json:"role"`
	Name        string          `json:"name"`
	Region      string          `json:"region,omitempty"`
	Environment string          `json:"environment,omitempty"`
	Config      json.RawMessage `json:"config"`
	CreatedAt   time.Time       `json:"created_at"`
}

func (h *DeclaredNodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/declared-nodes")
	path = strings.TrimPrefix(path, "/")
	id := strings.SplitN(path, "/", 2)[0]

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodDelete && id != "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *DeclaredNodesHandler) list(w http.ResponseWriter, r *http.Request) {
	h.ensureTable()
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, role, name, region, environment, config, created_at FROM declared_nodes ORDER BY created_at DESC`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]declaredNode, 0)
	for rows.Next() {
		var n declaredNode
		var cfg string
		if err := rows.Scan(&n.ID, &n.Role, &n.Name, &n.Region, &n.Environment, &cfg, &n.CreatedAt); err != nil {
			continue
		}
		n.Config = json.RawMessage(cfg)
		result = append(result, n)
	}
	jsonOK(w, result)
}

func (h *DeclaredNodesHandler) ensureTable() {
	h.DB.Exec(`CREATE TABLE IF NOT EXISTS declared_nodes (
		id         TEXT PRIMARY KEY,
		role       TEXT NOT NULL CHECK(role IN ('core','agent')),
		name       TEXT NOT NULL,
		region     TEXT NOT NULL DEFAULT '',
		environment TEXT NOT NULL DEFAULT '',
		config     TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`) //nolint:errcheck
}

func (h *DeclaredNodesHandler) create(w http.ResponseWriter, r *http.Request) {
	h.ensureTable()
	var req struct {
		Role        string          `json:"role"`
		Name        string          `json:"name"`
		Region      string          `json:"region"`
		Environment string          `json:"environment"`
		Config      json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.Role != "core" && req.Role != "agent" {
		http.Error(w, "role invalide (core|agent)", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	cfg := "{}"
	if len(req.Config) > 0 {
		cfg = string(req.Config)
	}

	// Upsert par (role, name) : permet de persister placement / options pour un nœud déjà live.
	var existingID string
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT id FROM declared_nodes WHERE role=? AND name=? ORDER BY created_at DESC LIMIT 1`,
		req.Role, req.Name,
	).Scan(&existingID)

	var id string
	if existingID != "" {
		_, err := h.DB.ExecContext(r.Context(),
			`UPDATE declared_nodes SET region=?, environment=?, config=? WHERE id=?`,
			req.Region, req.Environment, cfg, existingID,
		)
		if err != nil {
			if !isCtxErr(err) {
				h.Log.Error("declared_nodes: update", "err", err)
			}
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
		id = existingID
	} else {
		err := h.DB.QueryRowContext(r.Context(),
			`INSERT INTO declared_nodes(id, role, name, region, environment, config)
			 VALUES('dn_'||lower(hex(randomblob(6))),?,?,?,?,?) RETURNING id`,
			req.Role, req.Name, req.Region, req.Environment, cfg,
		).Scan(&id)
		if err != nil {
			if !isCtxErr(err) {
				h.Log.Error("declared_nodes: insert", "err", err)
			}
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
	}

	var n declaredNode
	var cfgBack string
	h.DB.QueryRowContext(r.Context(), //nolint:errcheck
		`SELECT id, role, name, region, environment, config, created_at FROM declared_nodes WHERE id=?`, id,
	).Scan(&n.ID, &n.Role, &n.Name, &n.Region, &n.Environment, &cfgBack, &n.CreatedAt)
	n.Config = json.RawMessage(cfgBack)

	if existingID != "" {
		jsonOK(w, n)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, n)
}

func (h *DeclaredNodesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.ensureTable()
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM declared_nodes WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
