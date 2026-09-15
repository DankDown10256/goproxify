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

func runAuthProvider() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var providers []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/auth-providers", nil, &providers); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider list : %v\n", err)
			os.Exit(1)
		}
		if len(providers) == 0 {
			fmt.Println("(aucun fournisseur)")
			return
		}
		fmt.Printf("%-36s  %-20s  %-30s  %s\n", "ID", "TYPE", "NOM", "ACTIF")
		fmt.Println(strings.Repeat("-", 95))
		for _, p := range providers {
			id, _ := p["id"].(string)
			typ, _ := p["type"].(string)
			name, _ := p["name"].(string)
			enabled := "non"
			if e, ok := p["enabled"].(bool); ok && e {
				enabled = "oui"
			}
			fmt.Printf("%-36s  %-20s  %-30s  %s\n", id, typ, name, enabled)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify auth-provider get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var provider map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/auth-providers/"+url.PathEscape(id), nil, &provider); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(provider, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[3:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify auth-provider create -file <provider.json>")
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
		if _, err := client.DoJSON("POST", "/api/v1/auth-providers", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider create : %v\n", err)
			os.Exit(1)
		}
		rid, _ := result["id"].(string)
		name, _ := result["name"].(string)
		fmt.Printf("Fournisseur créé : %s (%s)\n", rid, name)

	case "update":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		file := flagValue(args, "-file", "")
		if id == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify auth-provider update <id> -file <provider.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/auth-providers/"+url.PathEscape(id), payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Fournisseur %s mis à jour.\n", id)

	case "enable":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify auth-provider enable <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PATCH", "/api/v1/auth-providers/"+url.PathEscape(id),
			map[string]any{"enabled": true}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider enable : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Fournisseur %s activé.\n", id)

	case "disable":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify auth-provider disable <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PATCH", "/api/v1/auth-providers/"+url.PathEscape(id),
			map[string]any{"enabled": false}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider disable : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Fournisseur %s désactivé.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify auth-provider delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le fournisseur %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/auth-providers/"+url.PathEscape(id),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "auth-provider delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Fournisseur %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify auth-provider <sous-commande> [options]

Sous-commandes :
  list     Liste les fournisseurs d'authentification (OIDC, SAML, LDAP…)
  get      Affiche un fournisseur
  create   Crée un fournisseur depuis un fichier JSON
  update   Met à jour un fournisseur
  enable   Active un fournisseur
  disable  Désactive un fournisseur
  delete   Supprime un fournisseur

goproxify auth-provider list   [-admin-url …] [-token …]
goproxify auth-provider get    <id> [-admin-url …] [-token …]
goproxify auth-provider create -file <provider.json> [-admin-url …] [-token …]
goproxify auth-provider update <id> -file <provider.json> [-admin-url …] [-token …]
goproxify auth-provider enable  <id> [-admin-url …] [-token …]
goproxify auth-provider disable <id> [-admin-url …] [-token …]
goproxify auth-provider delete  <id> [-y] [-admin-url …] [-token …]

Exemple de fichier provider.json (OIDC) :
  {
    "name": "Google",
    "type": "oidc",
    "enabled": true,
    "config": {
      "client_id": "xxx.apps.googleusercontent.com",
      "client_secret": "GOCSPX-…",
      "issuer": "https://accounts.google.com"
    }
  }
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande auth-provider inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify auth-provider help")
		os.Exit(1)
	}
}
