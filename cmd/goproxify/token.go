// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type cliTokenRow struct {
	ID           string     `json:"id"`
	Token        string     `json:"token"`
	Role         string     `json:"role"`
	RBACRole     string     `json:"rbac_role"`
	NodeName     string     `json:"node_name"`
	NodeEndpoint string     `json:"node_endpoint,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	Revoked      bool       `json:"revoked"`
}

func runToken() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "create", "":
		args := parseFlags(os.Args[3:])
		role := flagValue(args, "-role", "")
		node := flagValue(args, "-node", "")
		ttlStr := flagValue(args, "-ttl", "0")
		endpoint := flagValue(args, "-endpoint", "")
		rbacRole := flagValue(args, "-rbac-role", "admin")
		if role == "" || node == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify token create -role core|agent -node <nom> [-ttl <durée>] [-endpoint <url>] [-rbac-role admin|operator|viewer]")
			fmt.Fprintln(os.Stderr, adminAuthHint())
			os.Exit(1)
		}
		if role != "core" && role != "agent" {
			fmt.Fprintf(os.Stderr, "-role doit être 'core' ou 'agent' (reçu: %q)\n", role)
			os.Exit(1)
		}
		ttlHours, err := parseTTLHours(ttlStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-ttl invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		body := map[string]any{
			"role":          role,
			"node_name":     node,
			"rbac_role":     rbacRole,
			"ttl_hours":     ttlHours,
			"node_endpoint": endpoint,
		}
		var row cliTokenRow
		if _, err := client.DoJSON("POST", "/api/v1/tokens", body, &row, 201); err != nil {
			fmt.Fprintf(os.Stderr, "token create : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Token créé")
		fmt.Printf("  ID        : %s\n", row.ID)
		fmt.Printf("  Rôle      : %s\n", row.Role)
		fmt.Printf("  RBAC      : %s\n", row.RBACRole)
		fmt.Printf("  Node      : %s\n", row.NodeName)
		if row.NodeEndpoint != "" {
			fmt.Printf("  Endpoint  : %s\n", row.NodeEndpoint)
		}
		if row.ExpiresAt != nil {
			fmt.Printf("  Expire    : %s\n", row.ExpiresAt.Format(time.RFC3339))
		} else {
			fmt.Printf("  Expire    : permanent\n")
		}
		fmt.Printf("  Token     : %s\n", row.Token)
		fmt.Println("\nCopiez le token maintenant — il ne sera plus affiché en clair côté list (masqué).")

	case "list":
		args := parseFlags(os.Args[3:])
		role := flagValue(args, "-role", "")
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		path := "/api/v1/tokens"
		if role != "" {
			path += "?role=" + role
		}
		var rows []cliTokenRow
		if _, err := client.DoJSON("GET", path, nil, &rows); err != nil {
			fmt.Fprintf(os.Stderr, "token list : %v\n", err)
			os.Exit(1)
		}
		if len(rows) == 0 {
			fmt.Println("(aucun token)")
			return
		}
		fmt.Printf("%-36s  %-6s  %-8s  %-20s  %-8s  %s\n", "ID", "ROLE", "RBAC", "NODE", "STATUS", "TOKEN")
		for _, t := range rows {
			status := "active"
			if t.Revoked {
				status = "revoked"
			} else if t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()) {
				status = "expired"
			}
			fmt.Printf("%-36s  %-6s  %-8s  %-20s  %-8s  %s\n",
				t.ID, t.Role, t.RBACRole, truncate(t.NodeName, 20), status, maskToken(t.Token))
		}

	case "revoke":
		if len(os.Args) < 4 || strings.HasPrefix(os.Args[3], "-") {
			fmt.Fprintln(os.Stderr, "usage: goproxify token revoke <id> [-admin-url <url>] [-token <token>]")
			os.Exit(1)
		}
		id := os.Args[3]
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/tokens/"+id, nil, nil, 204); err != nil {
			fmt.Fprintf(os.Stderr, "token revoke : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token %s révoqué\n", id)

	case "help":
		fmt.Print(`Usage: goproxify token <sous-commande> [options]

Sous-commandes :
  create   Génère un token d'appairage Core/Agent (défaut si omis)
  list     Liste les tokens existants
  revoke   Révoque un token

goproxify token create -role core|agent -node <nom> [options]
  -role        Rôle du nœud : core | agent
  -node        Nom du nœud (ex: serveur-production-1)
  -ttl         Durée de validité (ex: 24h, 7d, 0 = permanent)
  -endpoint    URL du Core (enregistré dès la création si role=core)
  -rbac-role   admin | operator | viewer (défaut: admin)
  -admin-url   URL Admin (ou GPX_CONTROLPLANE_ADMIN_ENDPOINT)
  -token       Token/PAT Admin (ou GPX_CONTROLPLANE_AUTH_TOKEN)

goproxify token list [-role core|agent] [-admin-url …] [-token …]

goproxify token revoke <id> [-admin-url …] [-token …]

Note : distinct de « goproxify core token » (tokens locaux du Core).
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande token inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify token help")
		os.Exit(1)
	}
}

// parseTTLHours convertit "24h", "7d", "2" ou "0" en heures entières.
func parseTTLHours(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("valeur négative")
		}
		return n, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		// support 7d (non natif Go)
		if strings.HasSuffix(s, "d") {
			n, err2 := strconv.Atoi(strings.TrimSuffix(s, "d"))
			if err2 != nil || n < 0 {
				return 0, fmt.Errorf("durée invalide %q", s)
			}
			return n * 24, nil
		}
		return 0, fmt.Errorf("durée invalide %q (ex: 24h, 7d, 0)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("valeur négative")
	}
	h := int(d.Hours())
	if h == 0 && d > 0 {
		h = 1 // arrondi min 1h si durée < 1h
	}
	return h, nil
}

func maskToken(tok string) string {
	if len(tok) <= 12 {
		return "***"
	}
	return tok[:10] + "…" + tok[len(tok)-4:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
