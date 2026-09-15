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

func runProxy() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var proxies []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies", nil, &proxies); err != nil {
			fmt.Fprintf(os.Stderr, "proxy list : %v\n", err)
			os.Exit(1)
		}
		if len(proxies) == 0 {
			fmt.Println("(aucun proxy)")
			return
		}
		fmt.Printf("%-40s  %-8s  %-10s  %s\n", "ID", "TYPE", "STATUT", "HOST")
		fmt.Println(strings.Repeat("-", 80))
		for _, p := range proxies {
			id, _ := p["id"].(string)
			typ, _ := p["type"].(string)
			if typ == "" {
				typ = "http"
			}
			enabled, _ := p["enabled"].(bool)
			status := "désactivé"
			if enabled {
				status = "actif"
			}
			host := proxyHost(p)
			fmt.Printf("%-40s  %-8s  %-10s  %s\n", id, typ, status, host)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify proxy get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var proxy map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(id), nil, &proxy); err != nil {
			fmt.Fprintf(os.Stderr, "proxy get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(proxy, "", "  ")
		fmt.Println(string(out))

	case "enable", "disable":
		enabled := sub == "enable"
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		if id == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify proxy %s <id>\n", sub)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PATCH", "/api/v1/proxies/"+url.PathEscape(id),
			map[string]any{"enabled": enabled}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "proxy %s : %v\n", sub, err)
			os.Exit(1)
		}
		word := "activé"
		if !enabled {
			word = "désactivé"
		}
		fmt.Printf("Proxy %s %s.\n", id, word)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify proxy delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le proxy %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/proxies/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "proxy delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Proxy %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify proxy <sous-commande> [options]

Sous-commandes :
  list    Liste tous les proxies
  get     Affiche la config complète d'un proxy
  enable  Active un proxy
  disable Désactive un proxy
  delete  Supprime un proxy

goproxify proxy list   [-admin-url …] [-token …]
goproxify proxy get    <id> [-admin-url …] [-token …]
goproxify proxy enable <id> [-admin-url …] [-token …]
goproxify proxy disable <id> [-admin-url …] [-token …]
goproxify proxy delete <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique (skip prompt)
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande proxy inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify proxy help")
		os.Exit(1)
	}
}

func proxyHost(p map[string]any) string {
	if cfg, ok := p["config"].(map[string]any); ok {
		if h, ok := cfg["host"].(string); ok && h != "" {
			return h
		}
	}
	if h, ok := p["host"].(string); ok && h != "" {
		return h
	}
	return ""
}
