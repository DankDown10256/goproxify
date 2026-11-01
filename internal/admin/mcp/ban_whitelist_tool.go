// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/security"
)

func banWhitelistTools() []map[string]any {
	return []map[string]any{
		{
			"name": "list_ban_whitelist",
			"description": "Liste la liste blanche des bans : adresses et plages qu'aucun ban n'atteint (manuel, Seuils, CrowdSec, Ephor, règles) " +
				"et que Ephor n'évalue pas, avec leur commentaire et le nombre de bans actifs qu'elles rendent sans effet.",
			"inputSchema": schema(),
		},
		{
			"name": "add_ban_whitelist",
			"description": "Ajoute une adresse IP ou une plage CIDR à la liste blanche des bans, et l'envoie aux passerelles. La cible est normalisée " +
				"(203.0.113.7/24 devient 203.0.113.0/24) ; une plage plus large que /16 (IPv4) ou /32 (IPv6) est refusée. Si une entrée existante " +
				"la couvre déjà, rien ne change ; les entrées plus précises qu'elle deviennent redondantes et sont retirées. Les bans existants " +
				"ne sont pas supprimés : ils cessent simplement de s'appliquer à ces adresses.",
			"inputSchema": schema(
				req("ip", "string", "Adresse IP ou plage CIDR à exempter"),
				opt("comment", "string", "Pourquoi (ex. « bureau Paris », « supervision »)"),
			),
		},
		{
			"name":        "remove_ban_whitelist",
			"description": "Retire une entrée de la liste blanche des bans (valeur exacte telle qu'enregistrée) et l'envoie aux passerelles. Les bans qu'elle neutralisait s'appliquent de nouveau.",
			"inputSchema": schema(req("ip", "string", "Adresse IP ou plage CIDR à retirer")),
		},
	}
}

func init() { tools = append(tools, banWhitelistTools()...) }

func (h *Handler) toolListBanWhitelist() (any, error) {
	entries := security.LoadWhitelist(h.DB)
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"value": e.Value, "comment": e.Comment, "added_by": e.AddedBy, "added_at": e.AddedAt,
		})
	}
	return out, nil
}

func (h *Handler) toolAddBanWhitelist(r *http.Request, args map[string]any) (any, error) {
	raw, _ := args["ip"].(string)
	comment, _ := args["comment"].(string)
	t, err := security.ParseBanTarget(raw)
	if err != nil {
		return nil, err
	}
	actor := adminauth.ActorFromContext(r.Context())
	entry, added, covering, err := security.AddWhitelist(h.DB, t, comment, actor)
	if err != nil {
		return nil, err
	}
	if !added {
		return map[string]any{"added": false, "covered_by": covering.Value}, nil
	}
	_ = admindb.WriteAudit(h.DB, actor, "whitelist_add", "ban-whitelist:"+entry.Value, comment)
	if h.OnWhitelistChange != nil {
		h.OnWhitelistChange()
	}
	return map[string]any{"added": true, "value": entry.Value, "comment": entry.Comment}, nil
}

func (h *Handler) toolRemoveBanWhitelist(r *http.Request, args map[string]any) (any, error) {
	raw, _ := args["ip"].(string)
	t, err := security.ParseBanTarget(raw)
	if err != nil {
		return nil, err
	}
	found, err := security.RemoveWhitelist(h.DB, t)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("entrée introuvable : %s", t.Value)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "whitelist_remove", "ban-whitelist:"+t.Value, "")
	if h.OnWhitelistChange != nil {
		h.OnWhitelistChange()
	}
	return map[string]any{"removed": t.Value}, nil
}
