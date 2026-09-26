// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

const (
	// HASessionSticky : les sessions web du portail restent sur la passerelle qui les a émises
	// (affinité à assurer sur le load balancer). C'est le défaut.
	HASessionSticky = "sticky"
	// HASessionShared : les sessions web sont répliquées entre les passerelles du groupe.
	HASessionShared = "shared"

	settingPortalHAKeyPrefix = "portal.ha_key."
)

// scope retourne la portée d'un réglage du portail pour la passerelle demandée : le groupe HA
// auquel elle appartient, sinon elle-même.
func (h *PortalHandler) scope(edge string) string { return scopeFor(h.Groups, edge) }

// BuildPortalPayload construit la config du portail à pousser à une passerelle : celle de son
// groupe HA (ou la sienne), avec les informations de réplication et l'activation propre au nœud.
func BuildPortalPayload(db *sql.DB, g GroupResolver, edgeName string) PortalConfig {
	scope := scopeFor(g, edgeName)
	cfg := loadPortalConfig(db, scope)
	cfg.EdgeName = edgeName
	grantEdges := []string{edgeName}

	group, inGroup := strings.CutPrefix(scope, groupScopePrefix)
	if inGroup {
		cfg.HAGroup = group
		cfg.HAMembers = memberNames(g, group)
		grantEdges = cfg.HAMembers
		if cfg.HASessionMode != HASessionShared {
			cfg.HASessionMode = HASessionSticky
		}
		cfg.HAKey = groupPortalKey(db, group)
	} else {
		cfg.HASessionMode = ""
	}

	cfg.Grants = listActiveGrants(db, grantEdges)
	// L'activation est une propriété du nœud (wizard : config.portal). Un nœud qui n'héberge pas le
	// portail reçoit quand même la config du groupe, en attente, pour être prêt à prendre le relais.
	if g != nil {
		if n, ok := g.NodeOf(edgeName); ok {
			if enabled, declared := n.PortalFlag(); declared && !enabled {
				cfg.HAStandby = inGroup && cfg.Enabled
				cfg.Enabled = false
			}
		}
	}
	return cfg
}

// LoadPortalConfigForEdge expose la config pour le full_sync WS.
func LoadPortalConfigForEdge(db *sql.DB, g GroupResolver, edgeName string) PortalConfig {
	return BuildPortalPayload(db, g, edgeName)
}

func memberNames(g GroupResolver, group string) []string {
	var out []string
	for _, n := range g.GroupMembers(group) {
		out = append(out, n.Name)
	}
	return out
}

// pushScope pousse la config du portail à toutes les passerelles concernées par la portée.
func (h *PortalHandler) pushScope(ctx context.Context, scope string) {
	if h.Pusher == nil || scope == "" {
		return
	}
	if group, ok := strings.CutPrefix(scope, groupScopePrefix); ok && h.Groups != nil {
		for _, name := range memberNames(h.Groups, group) {
			h.Pusher.PushPortal(ctx, name, BuildPortalPayload(h.DB, h.Groups, name))
		}
		return
	}
	h.Pusher.PushPortal(ctx, scope, BuildPortalPayload(h.DB, h.Groups, scope))
}

// groupPortalKey retourne la clé de réplication du portail d'un groupe HA (créée au premier usage,
// scellée dans la base). Elle chiffre les échanges entre les passerelles du groupe.
func groupPortalKey(db *sql.DB, group string) string {
	key := settingPortalHAKeyPrefix + groupScopePrefix + group
	if stored := admindb.GetSetting(db, key, ""); stored != "" {
		if plain, err := auth.OpenNodeToken(stored); err == nil && plain != "" {
			return plain
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	plain := hex.EncodeToString(raw)
	if err := admindb.SetSetting(db, key, auth.SealNodeToken(plain)); err != nil {
		return ""
	}
	return plain
}

// MigratePortalGroups rattache au groupe HA les données du portail propres à ses membres
// (config, destinations, utilisateurs invités). Idempotent : une fois rattachées, les lignes portent la
// portée du groupe. Un désaccord de config entre membres est signalé, jamais écrasé.
func MigratePortalGroups(ctx context.Context, db *sql.DB, g GroupResolver, log *slog.Logger) {
	if g == nil {
		return
	}
	names, members := g.Groups()
	for _, group := range names {
		scope := groupScopePrefix + group
		refs := memberRefs(ctx, db, members[group])
		if len(refs) == 0 {
			continue
		}

		// config : reprise du premier membre qui en a une
		cfgKey := settingPortalConfigPrefix + scope
		if admindb.GetSetting(db, cfgKey, "") == "" {
			var chosen, from string
			var conflicts []string
			for _, ref := range refs {
				raw := admindb.GetSetting(db, settingPortalConfigPrefix+ref, "")
				if raw == "" {
					continue
				}
				if chosen == "" {
					chosen, from = raw, ref
				} else if !sameJSON(chosen, raw) {
					conflicts = append(conflicts, ref)
				}
			}
			if chosen != "" && admindb.SetSetting(db, cfgKey, chosen) == nil {
				log.Info("portail: config de groupe créée", "groupe", group, "reprise_de", from)
				if len(conflicts) > 0 {
					log.Warn("portail: configs différentes entre membres, celle du premier est retenue",
						"groupe", group, "retenue", from, "differentes", conflicts)
				}
			}
		}

		// destinations et utilisateurs : ré-étiquetage vers la portée du groupe
		for _, ref := range refs {
			if res, err := db.ExecContext(ctx, `UPDATE portal_destinations SET edge_name=? WHERE edge_name=?`, scope, ref); err == nil {
				if n, _ := res.RowsAffected(); n > 0 {
					log.Info("portail: destinations rattachées au groupe", "groupe", group, "depuis", ref, "count", n)
				}
			}
			_, _ = db.ExecContext(ctx, `UPDATE portal_users SET home_edge=? WHERE home_edge=?`, scope, ref)
		}
		// des membres qui déclaraient la même destination : on n'en garde qu'une
		if res, err := db.ExecContext(ctx, `DELETE FROM portal_destinations WHERE edge_name=? AND rowid NOT IN (
			SELECT MIN(rowid) FROM portal_destinations WHERE edge_name=?
			GROUP BY kind, name, host, port, agent_name, container)`, scope, scope); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				log.Info("portail: destinations en double retirées", "groupe", group, "count", n)
			}
		}
	}
}

// memberRefs liste toutes les façons dont une ligne du portail peut désigner un membre : nom du nœud,
// id du nœud, id de son token (l'UI désigne les passerelles par l'id de token).
func memberRefs(ctx context.Context, db *sql.DB, members []archstore.NodeEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, n := range members {
		add(n.Name)
		add(n.ID)
		rows, err := db.QueryContext(ctx, `SELECT id FROM tokens WHERE node_name=? AND role='edge'`, n.Name)
		if err != nil {
			continue
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				add(id)
			}
		}
		rows.Close()
	}
	return out
}
