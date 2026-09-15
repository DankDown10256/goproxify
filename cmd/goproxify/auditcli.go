// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runAudit() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		q := url.Values{}
		if actor := flagValue(args, "-actor", ""); actor != "" {
			q.Set("actor", actor)
		}
		if action := flagValue(args, "-action", ""); action != "" {
			q.Set("action", action)
		}
		if limit := flagValue(args, "-limit", "50"); limit != "" {
			q.Set("limit", limit)
		}
		path := "/api/v1/audit"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", path, nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "audit list : %v\n", err)
			os.Exit(1)
		}
		entries, _ := result["entries"].([]any)
		if len(entries) == 0 {
			fmt.Println("(aucune entrée)")
			return
		}
		fmt.Printf("%-25s  %-20s  %-25s  %s\n", "DATE", "ACTEUR", "ACTION", "DÉTAIL")
		fmt.Println(strings.Repeat("-", 100))
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			ts, _ := entry["created_at"].(string)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			actor, _ := entry["actor_email"].(string)
			if actor == "" {
				actor, _ = entry["actor_id"].(string)
			}
			action, _ := entry["action"].(string)
			detail, _ := entry["resource_id"].(string)
			fmt.Printf("%-25s  %-20s  %-25s  %s\n", ts, actor, action, detail)
		}

	case "export":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		output := flagValue(args, "-output", "audit-export.csv")
		data, _, _, err := client.DoRaw("GET", "/api/v1/audit/export", nil, "", 200)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit export : %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(output, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "écriture fichier : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Audit exporté : %s (%d octets)\n", output, len(data))

	case "help":
		fmt.Print(`Usage: goproxify audit <sous-commande> [options]

Sous-commandes :
  list    Liste les entrées du journal d'audit
  export  Exporte le journal complet en CSV

goproxify audit list   [-actor <email>] [-action <action>] [-limit <n>] [-admin-url …] [-token …]
goproxify audit export [-output <fichier.csv>] [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande audit inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify audit help")
		os.Exit(1)
	}
}
