// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func runSettings() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "smtp":
		runSettingsSMTP()
	case "help":
		fmt.Print(`Usage: goproxify settings <sous-commande> [options]

Sous-commandes :
  smtp  Configuration du serveur SMTP

goproxify settings smtp get  [-admin-url …] [-token …]
goproxify settings smtp set  -file <smtp.json> [-admin-url …] [-token …]
goproxify settings smtp test [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande settings inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify settings help")
		os.Exit(1)
	}
}

func runSettingsSMTP() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/settings/smtp", nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "settings smtp get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify settings smtp set -file <smtp.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/settings/smtp", payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "settings smtp set : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration SMTP mise à jour.")

	case "test":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/settings/smtp/test", nil, &result, 200, 202); err != nil {
			fmt.Fprintf(os.Stderr, "settings smtp test : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "sous-commande settings smtp inconnue : %q\n", sub)
		os.Exit(1)
	}
}
