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

func runSnippet() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var snippets []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/snippets", nil, &snippets); err != nil {
			fmt.Fprintf(os.Stderr, "snippet list : %v\n", err)
			os.Exit(1)
		}
		if len(snippets) == 0 {
			fmt.Println("(aucun snippet)")
			return
		}
		fmt.Printf("%-36s  %-20s  %s\n", "ID", "TYPE", "NOM")
		fmt.Println(strings.Repeat("-", 80))
		for _, s := range snippets {
			id, _ := s["id"].(string)
			typ, _ := s["type"].(string)
			name, _ := s["name"].(string)
			fmt.Printf("%-36s  %-20s  %s\n", id, typ, name)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify snippet get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var snippet map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/snippets/"+url.PathEscape(id), nil, &snippet); err != nil {
			fmt.Fprintf(os.Stderr, "snippet get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(snippet, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[3:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify snippet create -file <snippet.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/snippets", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "snippet create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		name, _ := result["name"].(string)
		fmt.Printf("Snippet créé : %s (%s)\n", rid, name)

	case "update":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		file := flagValue(args, "-file", "")
		if id == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify snippet update <id> -file <snippet.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", "/api/v1/snippets/"+url.PathEscape(id), payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "snippet update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Snippet %s mis à jour.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify snippet delete <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/snippets/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "snippet delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Snippet %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify snippet <sous-commande> [options]

Sous-commandes :
  list    Liste les snippets de sécurité
  get     Affiche un snippet
  create  Crée un snippet depuis un fichier JSON
  update  Met à jour un snippet depuis un fichier JSON
  delete  Supprime un snippet

goproxify snippet list   [-admin-url …] [-token …]
goproxify snippet get    <id> [-admin-url …] [-token …]
goproxify snippet create -file <snippet.json> [-admin-url …] [-token …]
goproxify snippet update <id> -file <snippet.json> [-admin-url …] [-token …]
goproxify snippet delete <id> [-admin-url …] [-token …]

Exemple de fichier snippet.json :
  {
    "name": "waf-strict",
    "type": "waf",
    "config": { "enabled": true, "mode": "block", "anomaly_threshold": 5 }
  }
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande snippet inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify snippet help")
		os.Exit(1)
	}
}
