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

func runUser() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var users []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/users", nil, &users); err != nil {
			fmt.Fprintf(os.Stderr, "user list : %v\n", err)
			os.Exit(1)
		}
		if len(users) == 0 {
			fmt.Println("(aucun utilisateur)")
			return
		}
		fmt.Printf("%-36s  %-30s  %-10s  %s\n", "ID", "EMAIL", "RÔLE", "STATUT")
		fmt.Println(strings.Repeat("-", 90))
		for _, u := range users {
			id, _ := u["id"].(string)
			email, _ := u["email"].(string)
			role, _ := u["platform_role"].(string)
			status, _ := u["status"].(string)
			fmt.Printf("%-36s  %-30s  %-10s  %s\n", id, email, role, status)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify user get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var user map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/users/"+url.PathEscape(id), nil, &user); err != nil {
			fmt.Fprintf(os.Stderr, "user get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(user, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[3:])
		email := flagValue(args, "-email", "")
		password := flagValue(args, "-password", "")
		role := flagValue(args, "-role", "viewer")
		if email == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify user create -email <email> [-password <mdp>] [-role admin|operator|viewer]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		payload := map[string]any{"email": email, "platform_role": role}
		if password != "" {
			payload["password"] = password
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/users", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "user create : %v\n", err)
			os.Exit(1)
		}
		uid, _ := result["id"].(string)
		fmt.Printf("Utilisateur créé : %s (%s)\n", uid, email)

	case "update":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify user update <id> [-role admin|operator|viewer] [-status active|disabled]")
			os.Exit(1)
		}
		patch := map[string]any{}
		if r := flagValue(args, "-role", ""); r != "" {
			patch["platform_role"] = r
		}
		if s := flagValue(args, "-status", ""); s != "" {
			patch["status"] = s
		}
		if len(patch) == 0 {
			fmt.Fprintln(os.Stderr, "rien à modifier : spécifier -role ou -status")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		// GET pour merger
		var existing map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/users/"+url.PathEscape(id), nil, &existing); err != nil {
			fmt.Fprintf(os.Stderr, "user get : %v\n", err)
			os.Exit(1)
		}
		for k, v := range patch {
			existing[k] = v
		}
		if _, err := client.DoJSON("PUT", "/api/v1/users/"+url.PathEscape(id), existing, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "user update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Utilisateur %s mis à jour.\n", id)

	case "passwd":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		password := flagValue(args, "-password", "")
		if id == "" || password == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify user passwd <id> -password <nouveau-mdp>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", "/api/v1/users/"+url.PathEscape(id)+"/password",
			map[string]any{"password": password}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "user passwd : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Mot de passe de %s mis à jour.\n", id)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify user delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer l'utilisateur %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/users/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "user delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Utilisateur %s supprimé.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify user <sous-commande> [options]

Sous-commandes :
  list    Liste les utilisateurs
  get     Affiche un utilisateur
  create  Crée un utilisateur
  update  Modifie le rôle ou le statut
  passwd  Change le mot de passe
  delete  Supprime un utilisateur

goproxify user list   [-admin-url …] [-token …]
goproxify user get    <id> [-admin-url …] [-token …]
goproxify user create -email <email> [-password <mdp>] [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify user update <id> [-role admin|operator|viewer] [-status active|disabled] [-admin-url …] [-token …]
goproxify user passwd <id> -password <nouveau-mdp> [-admin-url …] [-token …]
goproxify user delete <id> [-y] [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande user inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify user help")
		os.Exit(1)
	}
}

// firstPositional retourne le premier argument non-flag de la liste.
func firstPositional(args []string, parsed map[string]string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			// vérifier que ce n'est pas une valeur de flag
			found := false
			for _, v := range parsed {
				if v == a {
					found = true
					break
				}
			}
			if !found {
				return a
			}
		}
	}
	return ""
}
