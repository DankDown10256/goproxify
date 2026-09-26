// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
)

func runArchitecture() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "versions":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var versions []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/architecture/versions", nil, &versions); err != nil {
			fmt.Fprintf(os.Stderr, "architecture versions : %v\n", err)
			os.Exit(1)
		}
		if len(versions) == 0 {
			fmt.Println("(aucune version conservée)")
			return
		}
		fmt.Printf("%-48s  %-25s  %s\n", "VERSION", "ENREGISTRÉE", "TAILLE")
		fmt.Println(strings.Repeat("-", 90))
		for _, v := range versions {
			fmt.Printf("%-48v  %-25v  %v\n", v["name"], v["saved_at"], v["size"])
		}

	case "restore":
		args := parseFlags(os.Args[3:])
		name := flagValue(args, "-name", "")
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify architecture restore -name <version>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var out map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/architecture/restore", map[string]string{"name": name}, &out, 200); err != nil {
			fmt.Fprintf(os.Stderr, "architecture restore : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("architecture.json restauré depuis %s (l'état précédent est conservé).\n", name)

	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify architecture versions | restore -name <version>")
		os.Exit(1)
	}
}
