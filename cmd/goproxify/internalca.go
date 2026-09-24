// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runInternalCA() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "create-ca":
		args := parseFlags(os.Args[3:])
		name := flagValue(args, "-name", "")
		cn := flagValue(args, "-cn", "")
		years := flagValue(args, "-years", "10")
		if name == "" || cn == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify internal-ca create-ca -name <nom> -cn <common-name> [-years N]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var ca map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/internal-ca",
			map[string]any{"name": name, "common_name": cn, "validity_years": atoiDefault(years, 10)}, &ca, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "internal-ca create-ca : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CA interne %q créée (id=%v, expire=%v).\n", name, ca["id"], ca["not_after"])

	case "list-ca":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var cas []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/internal-ca", nil, &cas); err != nil {
			fmt.Fprintf(os.Stderr, "internal-ca list-ca : %v\n", err)
			os.Exit(1)
		}
		if len(cas) == 0 {
			fmt.Println("(aucune CA interne)")
			return
		}
		fmt.Printf("%-34s  %-20s  %-30s  %s\n", "ID", "NOM", "SUBJECT", "EXPIRATION")
		fmt.Println(strings.Repeat("-", 100))
		for _, c := range cas {
			fmt.Printf("%-34v  %-20v  %-30v  %v\n", c["id"], c["name"], c["subject"], c["not_after"])
		}

	case "issue":
		args := parseFlags(os.Args[3:])
		caID := flagValue(args, "-ca", "")
		cn := flagValue(args, "-cn", "")
		sans := flagValue(args, "-sans", "")
		usage := flagValue(args, "-usage", "server")
		days := flagValue(args, "-days", "397")
		if caID == "" || cn == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify internal-ca issue -ca <id> -cn <common-name> [-sans a,b] [-usage server|client] [-days N]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var sansList []string
		if sans != "" {
			sansList = strings.Split(sans, ",")
		}
		var cert map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/internal-ca/"+url.PathEscape(caID)+"/certs",
			map[string]any{"common_name": cn, "sans": sansList, "usage": usage, "validity_days": atoiDefault(days, 397)},
			&cert, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "internal-ca issue : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Certificat émis pour %q (id=%v, serial=%v, expire=%v).\n", cn, cert["id"], cert["serial"], cert["not_after"])

	case "list-certs":
		args := parseFlags(os.Args[3:])
		caID := flagValue(args, "-ca", "")
		if caID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify internal-ca list-certs -ca <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var certs []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/internal-ca/"+url.PathEscape(caID)+"/certs", nil, &certs); err != nil {
			fmt.Fprintf(os.Stderr, "internal-ca list-certs : %v\n", err)
			os.Exit(1)
		}
		if len(certs) == 0 {
			fmt.Println("(aucun certificat émis)")
			return
		}
		fmt.Printf("%-34s  %-25s  %-8s  %-12s  %s\n", "ID", "COMMON NAME", "USAGE", "EXPIRATION", "RÉVOQUÉ")
		fmt.Println(strings.Repeat("-", 100))
		for _, c := range certs {
			fmt.Printf("%-34v  %-25v  %-8v  %-12v  %v\n", c["id"], c["common_name"], c["usage"], c["not_after"], c["revoked"])
		}

	case "revoke":
		args := parseFlags(os.Args[3:])
		caID := flagValue(args, "-ca", "")
		certID := flagValue(args, "-cert", "")
		if certID == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			certID = os.Args[3]
		}
		if caID == "" || certID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify internal-ca revoke -ca <id> <certID>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/internal-ca/"+url.PathEscape(caID)+"/certs/"+url.PathEscape(certID),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "internal-ca revoke : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Certificat %s révoqué.\n", certID)

	case "help", "":
		fmt.Print(`Usage: goproxify internal-ca <sous-commande> [options]

Génère et gère une autorité de certification (CA) interne pour émettre des
certificats serveur/client hors ACME.

Sous-commandes :
  create-ca    Crée une nouvelle CA racine
  list-ca      Liste les CA internes
  issue        Émet un certificat signé par une CA interne
  list-certs   Liste les certificats émis par une CA
  revoke       Révoque un certificat émis

goproxify internal-ca create-ca -name <nom> -cn <common-name> [-years N]
goproxify internal-ca list-ca
goproxify internal-ca issue -ca <id> -cn <cn> [-sans a,b] [-usage server|client] [-days N]
goproxify internal-ca list-certs -ca <id>
goproxify internal-ca revoke -ca <id> <certID>
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande internal-ca inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify internal-ca help")
		os.Exit(1)
	}
}

func atoiDefault(s string, def int) int {
	n := 0
	if s == "" {
		return def
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	return n
}
