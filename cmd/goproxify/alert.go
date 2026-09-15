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

func runAlert() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "channels":
		runAlertChannels()
	case "rules":
		runAlertRules()
	case "test":
		args := parseFlags(os.Args[3:])
		channel := flagValue(args, "-channel", "")
		_, all := args["-all"]
		if channel == "" && !all {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert test -channel <id> | -all")
			fmt.Fprintln(os.Stderr, adminAuthHint())
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if all {
			var channels []map[string]any
			if _, err := client.DoJSON("GET", "/api/v1/alert-channels", nil, &channels); err != nil {
				fmt.Fprintf(os.Stderr, "alert list : %v\n", err)
				os.Exit(1)
			}
			if len(channels) == 0 {
				fmt.Println("(aucun canal)")
				return
			}
			ok, fail := 0, 0
			for _, ch := range channels {
				id, _ := ch["id"].(string)
				name, _ := ch["name"].(string)
				typ, _ := ch["type"].(string)
				enabled, _ := ch["enabled"].(bool)
				label := name
				if label == "" {
					label = id
				}
				if !enabled {
					fmt.Printf("SKIP  %s (%s) — désactivé\n", label, typ)
					continue
				}
				if err := alertTestOne(client, id); err != nil {
					fmt.Printf("FAIL  %s (%s) : %v\n", label, typ, err)
					fail++
				} else {
					fmt.Printf("OK    %s (%s)\n", label, typ)
					ok++
				}
			}
			fmt.Printf("\nRésumé : %d OK, %d échec(s)\n", ok, fail)
			if fail > 0 {
				os.Exit(1)
			}
			return
		}
		if err := alertTestOne(client, channel); err != nil {
			fmt.Fprintf(os.Stderr, "alert test : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Test OK pour le canal %s\n", channel)

	case "help", "":
		fmt.Print(`Usage: goproxify alert <sous-commande> [options]

Sous-commandes :
  channels  Gestion des canaux de notification
  rules     Gestion des règles d'alerte
  test      Test d'un ou plusieurs canaux

goproxify alert channels list
goproxify alert channels get    <id>
goproxify alert channels create -file <channel.json>
goproxify alert channels update <id> -file <channel.json>
goproxify alert channels delete <id> [-y]

goproxify alert rules list
goproxify alert rules get    <id>
goproxify alert rules create -file <rule.json>
goproxify alert rules update <id> -file <rule.json>
goproxify alert rules delete <id> [-y]

goproxify alert test -channel <id> [-admin-url …] [-token …]
goproxify alert test -all          [-admin-url …] [-token …]
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande alert inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify alert help")
		os.Exit(1)
	}
}

func alertTestOne(client *adminClient, id string) error {
	_, err := client.DoJSON("POST", "/api/v1/alert-channels/"+id+"/test", map[string]any{}, nil)
	return err
}

func runAlertChannels() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var channels []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/alert-channels", nil, &channels); err != nil {
			fmt.Fprintf(os.Stderr, "alert channels list : %v\n", err)
			os.Exit(1)
		}
		if len(channels) == 0 {
			fmt.Println("(aucun canal)")
			return
		}
		fmt.Printf("%-36s  %-20s  %-30s  %s\n", "ID", "TYPE", "NOM", "STATUT")
		fmt.Println(strings.Repeat("-", 95))
		for _, c := range channels {
			id, _ := c["id"].(string)
			typ, _ := c["type"].(string)
			name, _ := c["name"].(string)
			status, _ := c["status"].(string)
			fmt.Printf("%-36s  %-20s  %-30s  %s\n", id, typ, name, status)
		}

	case "get":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert channels get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var channel map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/alert-channels/"+url.PathEscape(id), nil, &channel); err != nil {
			fmt.Fprintf(os.Stderr, "alert channels get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(channel, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert channels create -file <channel.json>")
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
		if _, err := client.DoJSON("POST", "/api/v1/alert-channels", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "alert channels create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		name, _ := result["name"].(string)
		fmt.Printf("Canal créé : %s (%s)\n", rid, name)

	case "update":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		file := flagValue(args, "-file", "")
		if id == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert channels update <id> -file <channel.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/alert-channels/"+url.PathEscape(id), payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "alert channels update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Canal %s mis à jour.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert channels delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le canal %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/alert-channels/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "alert channels delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Canal %s supprimé.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande alert channels inconnue : %q\n", sub)
		os.Exit(1)
	}
}

func runAlertRules() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var rules []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/alert-rules", nil, &rules); err != nil {
			fmt.Fprintf(os.Stderr, "alert rules list : %v\n", err)
			os.Exit(1)
		}
		if len(rules) == 0 {
			fmt.Println("(aucune règle)")
			return
		}
		fmt.Printf("%-36s  %-30s  %-20s  %s\n", "ID", "NOM", "TYPE", "ACTIF")
		fmt.Println(strings.Repeat("-", 95))
		for _, r := range rules {
			id, _ := r["id"].(string)
			name, _ := r["name"].(string)
			typ, _ := r["type"].(string)
			enabled := "non"
			if e, ok := r["enabled"].(bool); ok && e {
				enabled = "oui"
			}
			fmt.Printf("%-36s  %-30s  %-20s  %s\n", id, name, typ, enabled)
		}

	case "get":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert rules get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var rule map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/alert-rules/"+url.PathEscape(id), nil, &rule); err != nil {
			fmt.Fprintf(os.Stderr, "alert rules get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(rule, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert rules create -file <rule.json>")
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
		if _, err := client.DoJSON("POST", "/api/v1/alert-rules", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "alert rules create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		name, _ := result["name"].(string)
		fmt.Printf("Règle créée : %s (%s)\n", rid, name)

	case "update":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		file := flagValue(args, "-file", "")
		if id == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert rules update <id> -file <rule.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/alert-rules/"+url.PathEscape(id), payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "alert rules update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Règle %s mise à jour.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify alert rules delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer la règle %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/alert-rules/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "alert rules delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Règle %s supprimée.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande alert rules inconnue : %q\n", sub)
		os.Exit(1)
	}
}
