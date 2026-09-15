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

func runTeams() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var teams []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/teams", nil, &teams); err != nil {
			fmt.Fprintf(os.Stderr, "teams list : %v\n", err)
			os.Exit(1)
		}
		if len(teams) == 0 {
			fmt.Println("(aucune équipe)")
			return
		}
		fmt.Printf("%-36s  %-30s  %s\n", "ID", "NOM", "MEMBRES")
		fmt.Println(strings.Repeat("-", 80))
		for _, t := range teams {
			id, _ := t["id"].(string)
			name, _ := t["name"].(string)
			members := ""
			if m, ok := t["member_count"].(float64); ok {
				members = fmt.Sprintf("%d", int(m))
			}
			fmt.Printf("%-36s  %-30s  %s\n", id, name, members)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var team map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/teams/"+url.PathEscape(id), nil, &team); err != nil {
			fmt.Fprintf(os.Stderr, "teams get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(team, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[3:])
		name := firstPositional(os.Args[3:], args)
		if name == "" {
			name = flagValue(args, "-name", "")
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams create <nom> [-role admin|operator|viewer]")
			os.Exit(1)
		}
		payload := map[string]any{"name": name}
		if role := flagValue(args, "-role", ""); role != "" {
			payload["role"] = role
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/teams", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "teams create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		fmt.Printf("Équipe créée : %s (%s)\n", rid, name)

	case "update":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams update <id> [-name <nom>] [-role admin|operator|viewer]")
			os.Exit(1)
		}
		payload := map[string]any{}
		if v := flagValue(args, "-name", ""); v != "" {
			payload["name"] = v
		}
		if v := flagValue(args, "-role", ""); v != "" {
			payload["role"] = v
		}
		if len(payload) == 0 {
			fmt.Fprintln(os.Stderr, "aucun champ à mettre à jour (-name, -role)")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PATCH", "/api/v1/teams/"+url.PathEscape(id), payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "teams update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Équipe %s mise à jour.\n", id)

	case "members":
		runTeamMembers()

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer l'équipe %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/teams/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "teams delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Équipe %s supprimée.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify teams <sous-commande> [options]

Sous-commandes :
  list     Liste les équipes
  get      Affiche une équipe
  create   Crée une équipe
  update   Modifie une équipe
  members  Gestion des membres (list / add / remove)
  delete   Supprime une équipe

goproxify teams list   [-admin-url …] [-token …]
goproxify teams get    <id> [-admin-url …] [-token …]
goproxify teams create <nom> [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify teams update <id> [-name <nom>] [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify teams delete <id> [-y] [-admin-url …] [-token …]

goproxify teams members list   <team-id> [-admin-url …] [-token …]
goproxify teams members add    <team-id> -user <user-id> [-admin-url …] [-token …]
goproxify teams members remove <team-id> -user <user-id> [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande teams inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify teams help")
		os.Exit(1)
	}
}

func runTeamMembers() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[4:])
		teamID := firstPositional(os.Args[4:], args)
		if teamID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams members list <team-id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var members []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/teams/"+url.PathEscape(teamID)+"/members", nil, &members); err != nil {
			fmt.Fprintf(os.Stderr, "teams members list : %v\n", err)
			os.Exit(1)
		}
		if len(members) == 0 {
			fmt.Println("(aucun membre)")
			return
		}
		fmt.Printf("%-36s  %s\n", "USER ID", "EMAIL")
		fmt.Println(strings.Repeat("-", 70))
		for _, m := range members {
			uid, _ := m["user_id"].(string)
			email, _ := m["email"].(string)
			fmt.Printf("%-36s  %s\n", uid, email)
		}

	case "add":
		args := parseFlags(os.Args[4:])
		teamID := firstPositional(os.Args[4:], args)
		userID := flagValue(args, "-user", "")
		if teamID == "" || userID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams members add <team-id> -user <user-id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/teams/"+url.PathEscape(teamID)+"/members",
			map[string]any{"user_id": userID}, nil, 200, 201, 204); err != nil {
			fmt.Fprintf(os.Stderr, "teams members add : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Utilisateur %s ajouté à l'équipe %s.\n", userID, teamID)

	case "remove", "rm":
		args := parseFlags(os.Args[4:])
		teamID := firstPositional(os.Args[4:], args)
		userID := flagValue(args, "-user", "")
		if teamID == "" || userID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify teams members remove <team-id> -user <user-id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/teams/"+url.PathEscape(teamID)+"/members/"+url.PathEscape(userID),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "teams members remove : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Utilisateur %s retiré de l'équipe %s.\n", userID, teamID)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande teams members inconnue : %q\n", sub)
		os.Exit(1)
	}
}
