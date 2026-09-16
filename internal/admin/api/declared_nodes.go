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

	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/admin/backup"
)

// DeclaredNodesHandler gère les nœuds déclarés via l'assistant Infrastructure.
// Ces nœuds sont configurés mais pas encore connectés (status "declared").
type DeclaredNodesHandler struct {
	DB           *sql.DB
	Log          *slog.Logger
	CoreNodeName string // depuis admin.json identity.core_node_name ; sert de base déclarative
	Scheduler    *backup.Scheduler
	ArchStore    *archstore.Store // nil = pas de persistance disque
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
	inDB := map[string]bool{} // role:name déjà en DB
	for rows.Next() {
		var n declaredNode
		var cfg string
		if err := rows.Scan(&n.ID, &n.Role, &n.Name, &n.Region, &n.Environment, &cfg, &n.CreatedAt); err != nil {
			continue
		}
		n.Config = json.RawMessage(cfg)
		result = append(result, n)
		inDB[n.Role+":"+n.Name] = true
	}
	rows.Close()

	// Compléter avec les nœuds dérivés des fichiers config (source de vérité déclarative).
	// 1. Core principal déclaré dans admin.json (identity.core_node_name).
	// N'ajouter le Core env-var que si aucun Core n'est déjà déclaré en DB (évite doublon
	// quand l'opérateur renomme le Core principal via le Wizard).
	hasDBCore := false
	for k := range inDB {
		if len(k) > 5 && k[:5] == "core:" {
			hasDBCore = true
			break
		}
	}
	if h.CoreNodeName != "" && !inDB["core:"+h.CoreNodeName] && !hasDBCore {
		result = append(result, declaredNode{
			ID:     "cfg:core:" + h.CoreNodeName,
			Role:   "core",
			Name:   h.CoreNodeName,
			Config: json.RawMessage(`{"source":"config"}`),
		})
	}
	// 2. Nœuds enregistrés via tokens (cores + agents appairés).
	trows, _ := h.DB.QueryContext(r.Context(),
		`SELECT role, node_name, node_endpoint FROM tokens WHERE revoked=0 AND node_name!='' ORDER BY created_at`)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var role, name, endpoint string
			if err := trows.Scan(&role, &name, &endpoint); err != nil {
				continue
			}
			if role != "core" && role != "agent" {
				continue
			}
			if inDB[role+":"+name] {
				continue
			}
			cfgBytes, _ := json.Marshal(map[string]string{"endpoint": endpoint, "source": "token"})
			result = append(result, declaredNode{
				ID:     "cfg:" + role + ":" + name,
				Role:   role,
				Name:   name,
				Config: json.RawMessage(cfgBytes),
			})
			inDB[role+":"+name] = true
		}
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

	// Snapshot before change so previous state is restorable.
	if h.Scheduler != nil {
		go h.Scheduler.TakeSnapshot("avant:"+req.Role+":"+req.Name, "", 0) //nolint:errcheck
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

	if h.ArchStore != nil {
		_ = h.ArchStore.Upsert(archstore.NodeEntry{
			ID: n.ID, Role: n.Role, Name: n.Name,
			Region: n.Region, Environment: n.Environment, Config: cfgBack,
		})
	}

	if existingID != "" {
		jsonOK(w, n)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, n)
}

func (h *DeclaredNodesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.ensureTable()
	if h.Scheduler != nil {
		go h.Scheduler.TakeSnapshot("avant-suppression:"+id, "", 0) //nolint:errcheck
	}
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
	if h.ArchStore != nil {
		_ = h.ArchStore.Delete(id)
	}
	w.WriteHeader(http.StatusNoContent)
}
