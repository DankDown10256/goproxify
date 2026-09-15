// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runLogs() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		q := url.Values{}
		for _, f := range []string{"-level", "-domain", "-ip", "-method", "-status", "-path", "-search", "-from", "-to", "-limit", "-page"} {
			if v := flagValue(args, f, ""); v != "" {
				key := strings.TrimLeft(f, "-")
				if key == "from" {
					key = "date_from"
				} else if key == "to" {
					key = "date_to"
				}
				q.Set(key, v)
			}
		}
		path := "/api/v1/logs"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", path, nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "logs list : %v\n", err)
			os.Exit(1)
		}
		entries, _ := result["entries"].([]any)
		if len(entries) == 0 {
			fmt.Println("(aucune entrée)")
			return
		}
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			ts, _ := entry["timestamp"].(string)
			if len(ts) > 19 {
				ts = ts[:19]
			}
			level, _ := entry["level"].(string)
			domain, _ := entry["domain"].(string)
			method, _ := entry["method"].(string)
			reqPath, _ := entry["path"].(string)
			status := ""
			if s, ok := entry["status"].(float64); ok {
				status = fmt.Sprintf("%d", int(s))
			}
			ip, _ := entry["ip"].(string)
			fmt.Printf("%s  %-5s  %-3s  %-30s  %-7s  %-40s  %s\n",
				ts, level, status, domain, method, reqPath, ip)
		}

	case "export":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		output := flagValue(args, "-output", "logs-export.csv")
		format := flagValue(args, "-format", "csv")
		q := url.Values{}
		q.Set("format", format)
		for _, f := range []string{"-level", "-domain", "-ip", "-from", "-to"} {
			if v := flagValue(args, f, ""); v != "" {
				key := strings.TrimLeft(f, "-")
				if key == "from" {
					key = "date_from"
				} else if key == "to" {
					key = "date_to"
				}
				q.Set(key, v)
			}
		}
		data, _, _, err := client.DoRaw("GET", "/api/v1/logs/export?"+q.Encode(), nil, "", 200)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logs export : %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(output, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "écriture fichier : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Logs exportés : %s (%d octets)\n", output, len(data))

	case "help":
		fmt.Print(`Usage: goproxify logs <sous-commande> [options]

Sous-commandes :
  list    Recherche dans les logs d'accès et système
  export  Exporte les logs en CSV ou JSON

goproxify logs list
  [-level debug|info|warn|error]  Niveau de log
  [-domain <host>]                Filtrer par domaine/proxy
  [-ip <ip>]                      Filtrer par IP source
  [-method GET|POST|…]            Méthode HTTP
  [-status <code>]                Code HTTP (ex: 404, 5xx)
  [-path <préfixe>]               Chemin de la requête
  [-search <texte>]               Recherche libre
  [-from <RFC3339>]               Date de début
  [-to <RFC3339>]                 Date de fin
  [-limit <n>]                    Nombre de résultats (défaut: 50)
  [-page <n>]                     Page
  [-admin-url …] [-token …]

goproxify logs export
  [-format csv|json]  Format (défaut: csv)
  [-output <fichier>] Fichier de sortie (défaut: logs-export.csv)
  [-level …] [-domain …] [-ip …] [-from …] [-to …]
  [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande logs inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify logs help")
		os.Exit(1)
	}
}
