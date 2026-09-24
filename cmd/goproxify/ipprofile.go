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

func runIPProfile() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var profiles []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/ip-profiles", nil, &profiles); err != nil {
			fmt.Fprintf(os.Stderr, "ip-profile list : %v\n", err)
			os.Exit(1)
		}
		if len(profiles) == 0 {
			fmt.Println("(aucun profil)")
			return
		}
		fmt.Printf("%-36s  %-30s  %-15s  %-10s  %s\n", "ID", "NOM", "ACTION", "ETAT", "CIDRS")
		fmt.Println(strings.Repeat("-", 115))
		for _, p := range profiles {
			id, _ := p["id"].(string)
			name, _ := p["name"].(string)
			action, _ := p["action"].(string)
			cidrs := ""
			if c, ok := p["cidrs"].([]any); ok {
				parts := make([]string, 0, len(c))
				for _, v := range c {
					if s, ok := v.(string); ok {
						parts = append(parts, s)
					}
				}
				cidrs = strings.Join(parts, ", ")
				if len(cidrs) > 40 {
					cidrs = cidrs[:37] + "…"
				}
			}
			state := "ok"
			if n, _ := p["consecutive_failures"].(float64); n > 0 {
				state = fmt.Sprintf("échec x%d", int(n))
			}
			fmt.Printf("%-36s  %-30s  %-15s  %-10s  %s\n", id, name, action, state, cidrs)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify ip-profile get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var profile map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/ip-profiles/"+url.PathEscape(id), nil, &profile); err != nil {
			fmt.Fprintf(os.Stderr, "ip-profile get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(profile, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[3:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify ip-profile create -file <profile.json>")
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
		if _, err := client.DoJSON("POST", "/api/v1/ip-profiles", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "ip-profile create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		name, _ := result["name"].(string)
		fmt.Printf("Profil IP créé : %s (%s)\n", rid, name)

	case "update":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		file := flagValue(args, "-file", "")
		if id == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify ip-profile update <id> -file <profile.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/ip-profiles/"+url.PathEscape(id), payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "ip-profile update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Profil IP %s mis à jour.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify ip-profile delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le profil IP %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/ip-profiles/"+url.PathEscape(id),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "ip-profile delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Profil IP %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify ip-profile <sous-commande> [options]

Sous-commandes :
  list    Liste les profils IP (GeoIP, réputation, listes blanches/noires)
  get     Affiche un profil
  create  Crée un profil depuis un fichier JSON
  update  Met à jour un profil
  delete  Supprime un profil

goproxify ip-profile list   [-admin-url …] [-token …]
goproxify ip-profile get    <id> [-admin-url …] [-token …]
goproxify ip-profile create -file <profile.json> [-admin-url …] [-token …]
goproxify ip-profile update <id> -file <profile.json> [-admin-url …] [-token …]
goproxify ip-profile delete <id> [-y] [-admin-url …] [-token …]

Exemple de fichier profile.json :
  {
    "name": "blocklist-scanners",
    "action": "block",
    "cidrs": ["1.2.3.0/24", "5.6.7.8"],
    "countries": ["CN", "RU"],
    "description": "IPs de scanners connus"
  }
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande ip-profile inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify ip-profile help")
		os.Exit(1)
	}
}
