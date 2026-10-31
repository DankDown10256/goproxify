// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Les accès HTTP vivent dans la base de chaque passerelle (ADR 0012) : leur durée de conservation est celle que la
// passerelle applique, pas celle de l'Admin, qui ne garde que les événements de sécurité et ses propres logs.

const (
	edgeRetentionKey = "logs.edge_retention"
	// Défauts d'une passerelle sans ordre de l'Admin ni réglage dans edge.json (logstore.DefaultAccessRetention et
	// DefaultSystemRetention).
	EdgeDefaultAccessDays = 365
	EdgeDefaultSystemDays = 90
	maxEdgeRetentionDays  = 3650
)

// EdgeRetentionOverride est l'exception d'une passerelle ; 0 : la valeur commune.
type EdgeRetentionOverride struct {
	AccessDays int `json:"access_days,omitempty"`
	SystemDays int `json:"system_days,omitempty"`
}

// EdgeRetention est la conservation des logs que l'Admin impose aux passerelles.
type EdgeRetention struct {
	AccessDays int `json:"access_days"`
	SystemDays int `json:"system_days"`
	// Nodes : exceptions par nom de passerelle.
	Nodes map[string]EdgeRetentionOverride `json:"nodes,omitempty"`
}

// EdgeLogInfo est la rétention qu'une passerelle a annoncée appliquer.
type EdgeLogInfo struct {
	NodeName   string `json:"node_name"`
	AccessDays int    `json:"access_days"`
	SystemDays int    `json:"system_days"`
	ReportedAt string `json:"reported_at"`
	// BufferActive, UnackedDays, BufferMaxDays : la base de la passerelle est un tampon que l'Admin acquitte (ADR 0018) ; âge de
	// la plus ancienne ligne non acquittée et âge où elle est supprimée.
	BufferActive  bool `json:"buffer_active,omitempty"`
	UnackedDays   int  `json:"unacked_days,omitempty"`
	BufferMaxDays int  `json:"buffer_max_days,omitempty"`
	Stale      bool   `json:"stale,omitempty"`
}

// EdgeRetentionControl pousse la rétention aux passerelles et rend celle qu'elles annoncent.
type EdgeRetentionControl interface {
	PushLogRetention(ctx context.Context)
	LogInfo() []EdgeLogInfo
}

// LoadEdgeRetention lit la rétention imposée aux passerelles ; configured est faux tant que personne ne l'a réglée :
// chaque passerelle garde alors celle de son edge.json (365 et 90 jours par défaut).
func LoadEdgeRetention(db *sql.DB) (r EdgeRetention, configured bool) {
	raw := admindb.GetSetting(db, edgeRetentionKey, "")
	if raw == "" || json.Unmarshal([]byte(raw), &r) != nil || r.AccessDays < 1 || r.SystemDays < 1 {
		return EdgeRetention{AccessDays: EdgeDefaultAccessDays, SystemDays: EdgeDefaultSystemDays}, false
	}
	return r, true
}

// For rend la conservation, en jours, qui s'applique à une passerelle.
func (r EdgeRetention) For(node string) (access, system int) {
	access, system = r.AccessDays, r.SystemDays
	if o, ok := r.Nodes[node]; ok {
		if o.AccessDays > 0 {
			access = o.AccessDays
		}
		if o.SystemDays > 0 {
			system = o.SystemDays
		}
	}
	return access, system
}

func (r EdgeRetention) validate() error {
	ok := func(d int) bool { return d >= 1 && d <= maxEdgeRetentionDays }
	if !ok(r.AccessDays) || !ok(r.SystemDays) {
		return fmt.Errorf("durées de conservation entre 1 et %d jours", maxEdgeRetentionDays)
	}
	for n, o := range r.Nodes {
		if n == "" || len(n) > 128 || (o.AccessDays != 0 && !ok(o.AccessDays)) || (o.SystemDays != 0 && !ok(o.SystemDays)) {
			return fmt.Errorf("exception de la passerelle %q hors limites (1 à %d jours)", n, maxEdgeRetentionDays)
		}
	}
	return nil
}

// edgeRetentionView est la partie « passerelles » de GET /logs/settings.
func (h *LogsHandler) edgeRetentionView() map[string]any {
	r, configured := LoadEdgeRetention(h.DB)
	nodes := r.Nodes
	if nodes == nil {
		nodes = map[string]EdgeRetentionOverride{}
	}
	var edges []EdgeLogInfo
	if h.Retention != nil {
		edges = h.Retention.LogInfo()
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].NodeName < edges[j].NodeName })
	if edges == nil {
		edges = []EdgeLogInfo{}
	}
	return map[string]any{
		"configured": configured, "access_days": r.AccessDays, "system_days": r.SystemDays, "nodes": nodes, "edges": edges,
		"defaults": map[string]int{"access_days": EdgeDefaultAccessDays, "system_days": EdgeDefaultSystemDays},
	}
}

// saveEdgeRetention valide et enregistre la rétention des passerelles, puis la leur pousse.
func (h *LogsHandler) saveEdgeRetention(r EdgeRetention) error {
	for n, o := range r.Nodes {
		if o == (EdgeRetentionOverride{}) {
			delete(r.Nodes, n)
		}
	}
	if err := r.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := admindb.SetSetting(h.DB, edgeRetentionKey, string(raw)); err != nil {
		return err
	}
	if h.Retention != nil {
		h.Retention.PushLogRetention(context.Background())
	}
	return nil
}
