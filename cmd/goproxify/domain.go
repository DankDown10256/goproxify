// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func runDomain() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var domains []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/domains", nil, &domains); err != nil {
			fmt.Fprintf(os.Stderr, "domain list : %v\n", err)
			os.Exit(1)
		}
		if len(domains) == 0 {
			fmt.Println("(aucun domaine)")
			return
		}
		now := time.Now()
		fmt.Printf("%-36s  %-40s  %-12s  %-10s  %s\n", "ID", "DOMAINE", "EXPIRATION", "STATUT", "EDGE")
		fmt.Println(strings.Repeat("-", 110))
		for _, d := range domains {
			id, _ := d["id"].(string)
			domain, _ := d["domain"].(string)
			status, _ := d["status"].(string)
			edgeID, _ := d["edge_id"].(string)
			expiryStr, _ := d["expires_at"].(string)
			expiry := ""
			warn := ""
			if expiryStr != "" {
				if t, err := time.Parse(time.RFC3339, expiryStr); err == nil {
					days := int(t.Sub(now).Hours() / 24)
					expiry = fmt.Sprintf("%dd", days)
					if days < 14 {
						warn = " ⚠"
					}
				}
			}
			fmt.Printf("%-36s  %-40s  %-12s  %-10s  %s%s\n", id, domain, expiry, status, edgeID, warn)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify domain get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var domain map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/domains/"+url.PathEscape(id), nil, &domain); err != nil {
			fmt.Fprintf(os.Stderr, "domain get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(domain, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[3:])
		domain := firstPositional(os.Args[3:], args)
		if domain == "" {
			domain = flagValue(args, "-domain", "")
		}
		if domain == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify domain create <domaine> [-edge <edge-id>]")
			os.Exit(1)
		}
		payload := map[string]any{"domain": domain}
		if edge := flagValue(args, "-edge", ""); edge != "" {
			payload["edge_id"] = edge
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/domains", payload, &result, 200, 201, 202); err != nil {
			fmt.Fprintf(os.Stderr, "domain create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		fmt.Printf("Domaine créé : %s (%s)\n", rid, domain)

	case "renew":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify domain renew <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/domains/"+url.PathEscape(id)+"/renew",
			nil, nil, 200, 202); err != nil {
			fmt.Fprintf(os.Stderr, "domain renew : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Renouvellement du domaine %s lancé.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify domain delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le domaine %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/domains/"+url.PathEscape(id),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "domain delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Domaine %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify domain <sous-commande> [options]

Sous-commandes :
  list    Liste les domaines gérés
  get     Affiche un domaine
  create  Ajoute un domaine (déclenche le challenge ACME)
  renew   Force le renouvellement du certificat d'un domaine
  delete  Supprime un domaine

goproxify domain list   [-admin-url …] [-token …]
goproxify domain get    <id> [-admin-url …] [-token …]
goproxify domain create <domaine> [-edge <edge-id>] [-admin-url …] [-token …]
goproxify domain renew  <id> [-admin-url …] [-token …]
goproxify domain delete <id> [-y] [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande domain inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify domain help")
		os.Exit(1)
	}
}
