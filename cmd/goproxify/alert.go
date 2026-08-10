// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func runAlert() {
	sub := subcommand(os.Args, 2)
	switch sub {
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
  test   Envoie un message de test sur un ou plusieurs canaux

goproxify alert test -channel <id> [-admin-url …] [-token …]
  -channel  Identifiant du canal (email, webhook, ntfy, gotify, jira,
            linear, github, gitlab, zammad, glpi…)

goproxify alert test -all [-admin-url …] [-token …]
  Teste tous les canaux activés en séquence
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
