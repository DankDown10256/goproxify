// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
)

func runContainers() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var containers []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/discovered-containers", nil, &containers); err != nil {
			fmt.Fprintf(os.Stderr, "containers list : %v\n", err)
			os.Exit(1)
		}
		if len(containers) == 0 {
			fmt.Println("(aucun conteneur découvert)")
			return
		}
		fmt.Printf("%-40s  %-10s  %-20s  %-20s  %s\n", "HOST", "TLS", "CORE", "AGENT", "BACKENDS")
		fmt.Println(strings.Repeat("-", 110))
		for _, c := range containers {
			host, _ := c["host"].(string)
			tls := "non"
			if t, ok := c["tls"].(bool); ok && t {
				tls = "oui"
			}
			core, _ := c["core_name"].(string)
			agent, _ := c["agent_name"].(string)
			backends := ""
			if b, ok := c["backends"].([]any); ok {
				parts := make([]string, 0, len(b))
				for _, v := range b {
					if s, ok := v.(string); ok {
						parts = append(parts, s)
					}
				}
				backends = strings.Join(parts, ", ")
				if len(backends) > 40 {
					backends = backends[:37] + "…"
				}
			}
			fmt.Printf("%-40s  %-10s  %-20s  %-20s  %s\n", host, tls, core, agent, backends)
		}

	case "help":
		fmt.Print(`Usage: goproxify containers [list] [options]

Affiche les conteneurs Docker découverts par les Agents (lecture seule).
Agrège les résultats de tous les Cores connectés.

goproxify containers list [-admin-url …] [-token …]
goproxify containers      [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande containers inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify containers help")
		os.Exit(1)
	}
}
