// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func runCert() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var certs []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/certs", nil, &certs); err != nil {
			fmt.Fprintf(os.Stderr, "cert list : %v\n", err)
			os.Exit(1)
		}
		if len(certs) == 0 {
			fmt.Println("(aucun certificat)")
			return
		}
		now := time.Now()
		fmt.Printf("%-45s  %-10s  %-12s  %s\n", "DOMAINE", "STATUT", "EXPIRATION", "ÉMETTEUR")
		fmt.Println(strings.Repeat("-", 90))
		for _, c := range certs {
			domain, _ := c["domain"].(string)
			status, _ := c["status"].(string)
			issuer, _ := c["issuer"].(string)
			expiryStr, _ := c["expires_at"].(string)
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
			fmt.Printf("%-45s  %-10s  %-12s  %s%s\n", domain, status, expiry, issuer, warn)
		}

	case "obtain":
		args := parseFlags(os.Args[3:])
		domain := flagValue(args, "-domain", "")
		if domain == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			domain = os.Args[3]
		}
		if domain == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify cert obtain <domaine>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/certs",
			map[string]any{"domain": domain}, nil, 200, 201, 202); err != nil {
			fmt.Fprintf(os.Stderr, "cert obtain : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Demande de certificat pour %s lancée.\n", domain)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		domain := flagValue(args, "-domain", "")
		if domain == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			domain = os.Args[3]
		}
		if domain == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify cert delete <domaine>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/certs/"+url.PathEscape(domain),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "cert delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Certificat %s supprimé.\n", domain)

	case "help":
		fmt.Print(`Usage: goproxify cert <sous-commande> [options]

Sous-commandes :
  list    Liste les certificats TLS gérés
  obtain  Déclenche l'obtention d'un certificat (Let's Encrypt / ACME)
  delete  Supprime un certificat

goproxify cert list   [-admin-url …] [-token …]
goproxify cert obtain <domaine> [-admin-url …] [-token …]
goproxify cert delete <domaine> [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande cert inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify cert help")
		os.Exit(1)
	}
}
