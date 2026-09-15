// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runAgentCmd() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var agents []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/agents", nil, &agents); err != nil {
			fmt.Fprintf(os.Stderr, "agent list : %v\n", err)
			os.Exit(1)
		}
		if len(agents) == 0 {
			fmt.Println("(aucun agent)")
			return
		}
		fmt.Printf("%-36s  %-30s  %-12s  %s\n", "ID", "NOM", "STATUT", "CORE")
		fmt.Println(strings.Repeat("-", 90))
		for _, a := range agents {
			id, _ := a["id"].(string)
			name, _ := a["name"].(string)
			status, _ := a["status"].(string)
			coreID, _ := a["core_id"].(string)
			fmt.Printf("%-36s  %-30s  %-12s  %s\n", id, name, status, coreID)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify agent-mgmt get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var agent map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/agents/"+url.PathEscape(id), nil, &agent); err != nil {
			fmt.Fprintf(os.Stderr, "agent get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(agent, "", "  ")
		fmt.Println(string(out))

	case "approve":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify agent-mgmt approve <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/agents/"+url.PathEscape(id)+"/approve", nil, nil, 200, 202); err != nil {
			fmt.Fprintf(os.Stderr, "agent approve : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Agent %s approuvé.\n", id)

	case "revoke":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify agent-mgmt revoke <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/agents/"+url.PathEscape(id)+"/revoke", nil, nil, 200, 202); err != nil {
			fmt.Fprintf(os.Stderr, "agent revoke : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Agent %s révoqué.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify agent-mgmt delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer l'agent %q ? [y/N] ", id)
			var confirm string
			fmt.Scanln(&confirm) //nolint:errcheck
			if strings.ToLower(confirm) != "y" {
				fmt.Println("Annulé.")
				return
			}
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/agents/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "agent delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Agent %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify agent-mgmt <sous-commande> [options]

Sous-commandes :
  list     Liste les agents enregistrés
  get      Affiche un agent
  approve  Approuve un agent en attente
  revoke   Révoque un agent approuvé
  delete   Supprime un agent

goproxify agent-mgmt list    [-admin-url …] [-token …]
goproxify agent-mgmt get     <id> [-admin-url …] [-token …]
goproxify agent-mgmt approve <id> [-admin-url …] [-token …]
goproxify agent-mgmt revoke  <id> [-admin-url …] [-token …]
goproxify agent-mgmt delete  <id> [-y] [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande agent-mgmt inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify agent-mgmt help")
		os.Exit(1)
	}
}
