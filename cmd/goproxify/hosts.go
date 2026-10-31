// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

// runHosts : hôtes déclarés dans architecture.json et leur installation par ticket (ADR 0019, étape 4).
func runHosts() {
	action := subcommand(os.Args, 2)
	switch action {
	case "list", "":
		client := mustAdminClient(parseFlags(os.Args[3:]))
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/hosts", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "hosts list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "join-ticket":
		args := parseFlags(os.Args[3:])
		host := flagValue(args, "-host", "")
		if host == "" {
			fmt.Fprintln(os.Stderr, "-host requis")
			os.Exit(1)
		}
		client := mustAdminClient(args)
		var out map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/hosts/"+host+"/join-ticket", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "hosts join-ticket : %v\n", err)
			os.Exit(1)
		}
		if _, noQR := args["-no-qr"]; noQR {
			delete(out, "qr_code")
		}
		printJSON(out)
	case "help", "-h", "--help":
		hostsUsage()
	default:
		fmt.Fprintf(os.Stderr, "action hosts inconnue : %q\n\n", action)
		hostsUsage()
		os.Exit(1)
	}
}

func hostsUsage() {
	fmt.Print(`Usage: goproxify hosts <action> [options]

Hôtes déclarés dans architecture.json et leur installation par ticket.

Actions :
  list                       Liste les hôtes : adresse, rôles, groupe HA, état
                             (pending, partial, joined), nœuds et ticket en cours
  join-ticket -host <nom>    Crée pour un hôte un ticket d'installation de 15 minutes
                             (remplace le précédent). Rend : jeton, spec_url, empreinte du
                             certificat de l'Admin, trigger_url et qr_code (le QR code à
                             scanner, vers le launcher de l'hôte en attente sur son port
                             8080), listen_command (lance ce launcher en attente) et
                             join_command (installe l'hôte tout de suite, sans QR code).
                             Refusé si l'hôte est déjà intégré.
                             -no-qr omet qr_code (base64) de la sortie.

Exemple :
  goproxify hosts list
  goproxify hosts join-ticket -host nas -no-qr

` + adminAuthHint() + "\n")
}
