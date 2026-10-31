// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

func runProxy() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var proxies []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies", nil, &proxies); err != nil {
			fmt.Fprintf(os.Stderr, "proxy list : %v\n", err)
			os.Exit(1)
		}
		if len(proxies) == 0 {
			fmt.Println("(aucun proxy)")
			return
		}
		fmt.Printf("%-40s  %-8s  %-10s  %s\n", "ID", "TYPE", "STATUT", "HOST")
		fmt.Println(strings.Repeat("-", 80))
		for _, p := range proxies {
			id, _ := p["id"].(string)
			typ, _ := p["type"].(string)
			if typ == "" {
				typ = "http"
			}
			enabled, _ := p["enabled"].(bool)
			status := "désactivé"
			if enabled {
				status = "actif"
			}
			host := proxyHost(p)
			if implicit, _ := p["implicit"].(bool); implicit {
				host += "  (implicite)"
			}
			fmt.Printf("%-40s  %-8s  %-10s  %s\n", id, typ, status, host)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify proxy get <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var proxy map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(id), nil, &proxy); err != nil {
			fmt.Fprintf(os.Stderr, "proxy get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(proxy, "", "  ")
		fmt.Println(string(out))

	case "labels":
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify proxy labels <id> [-format compose|portainer|portainer_inline|docker_run|kubernetes]")
			os.Exit(1)
		}
		format := flagValue(args, "-format", "compose")
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var res struct {
			Unsupported []string `json:"unsupported"`
			Formats     map[string]struct {
				Text string `json:"text"`
				Env  string `json:"env"`
			} `json:"formats"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(id)+"/labels", nil, &res); err != nil {
			fmt.Fprintf(os.Stderr, "proxy labels : %v\n", err)
			os.Exit(1)
		}
		f, ok := res.Formats[format]
		if !ok {
			fmt.Fprintf(os.Stderr, "format inconnu %q (compose, portainer, portainer_inline, docker_run, kubernetes)\n", format)
			os.Exit(1)
		}
		fmt.Print(f.Text)
		if f.Env != "" {
			fmt.Printf("\n# Variables à renseigner :\n%s", f.Env)
		}
		for _, u := range res.Unsupported {
			fmt.Fprintf(os.Stderr, "sans label : %s\n", u)
		}

	case "metrics":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var res struct {
			Proxies []struct {
				Host      string  `json:"host"`
				RPS       float64 `json:"requests_per_second"`
				ErrorRate float64 `json:"error_rate"`
				P95ms     float64 `json:"p95_ms"`
			} `json:"proxies"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/metrics/proxies?points=1", nil, &res); err != nil {
			fmt.Fprintf(os.Stderr, "proxy metrics : %v\n", err)
			os.Exit(1)
		}
		if len(res.Proxies) == 0 {
			fmt.Println("(aucune mesure — l'Admin relève les passerelles toutes les 10 s)")
			return
		}
		fmt.Printf("%-40s  %10s  %8s  %10s\n", "HOST", "REQ/S", "ERREURS", "P95")
		fmt.Println(strings.Repeat("-", 74))
		for _, p := range res.Proxies {
			fmt.Printf("%-40s  %10.2f  %7.1f%%  %7.0f ms\n", p.Host, p.RPS, p.ErrorRate*100, p.P95ms)
		}

	case "enable", "disable":
		enabled := sub == "enable"
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		if id == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify proxy %s <id>\n", sub)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PATCH", "/api/v1/proxies/"+url.PathEscape(id),
			map[string]any{"enabled": enabled}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "proxy %s : %v\n", sub, err)
			os.Exit(1)
		}
		word := "activé"
		if !enabled {
			word = "désactivé"
		}
		fmt.Printf("Proxy %s %s.\n", id, word)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		_, force := args["-y"]
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify proxy delete <id> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le proxy %q ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/proxies/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "proxy delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Proxy %s supprimé.\n", id)

	case "cache-purge":
		args := parseFlags(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify proxy cache-purge <id> [-tag a,b] [-path /x,/y*]")
			os.Exit(1)
		}
		splitList := func(key string) []string {
			var out []string
			for _, s := range strings.Split(flagValue(args, key, ""), ",") {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var out struct {
			Purged int `json:"purged"`
		}
		body := map[string]any{"tags": splitList("-tag"), "paths": splitList("-path")}
		if _, err := client.DoJSON("POST", "/api/v1/proxies/"+url.PathEscape(id)+"/cache/purge", body, &out, 200); err != nil {
			fmt.Fprintf(os.Stderr, "proxy cache-purge : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%d entrée(s) supprimée(s) du cache de %s.\n", out.Purged, id)

	case "option":
		args := parseFlags(os.Args[3:])
		pos := positionalArgs(os.Args[3:])
		if len(pos) < 3 || !advancedProxyOptions[pos[1]] {
			fmt.Fprintf(os.Stderr, "usage: goproxify proxy option <id> <%s> <json|@fichier|off>\n", strings.Join(sortedKeys(advancedProxyOptions), "|"))
			os.Exit(1)
		}
		id, name, value := pos[0], pos[1], pos[2]
		var raw any
		switch {
		case value == "off":
		case strings.HasPrefix(value, "@"):
			data, err := os.ReadFile(value[1:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "lecture de %s : %v\n", value[1:], err)
				os.Exit(1)
			}
			value = string(data)
			fallthrough
		default:
			if err := json.Unmarshal([]byte(value), &raw); err != nil {
				fmt.Fprintf(os.Stderr, "valeur JSON invalide : %v\n", err)
				os.Exit(1)
			}
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var cur struct {
			Config  map[string]any `json:"config"`
			Enabled bool           `json:"enabled"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(id), nil, &cur); err != nil {
			fmt.Fprintf(os.Stderr, "proxy option : %v\n", err)
			os.Exit(1)
		}
		if raw == nil {
			delete(cur.Config, name)
		} else {
			cur.Config[name] = raw
		}
		if _, err := client.DoJSON("PUT", "/api/v1/proxies/"+url.PathEscape(id),
			map[string]any{"config": cur.Config, "enabled": cur.Enabled}, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "proxy option : %v\n", err)
			os.Exit(1)
		}
		if raw == nil {
			fmt.Printf("Option %s retirée de %s.\n", name, id)
		} else {
			fmt.Printf("Option %s posée sur %s.\n", name, id)
		}

	case "help":
		fmt.Print(`Usage: goproxify proxy <sous-commande> [options]

Sous-commandes :
  list    Liste tous les proxies
  get     Affiche la config complète d'un proxy
  labels  Affiche les labels qui reproduisent un proxy (Docker, Portainer, Kubernetes)
  enable  Active un proxy
  disable Désactive un proxy
  delete  Supprime un proxy
  metrics Débit, erreurs et p95 par host (dernier relevé)
  cache-purge Vide le cache HTTP d'un proxy (tout, par tag ou par chemin)
  option  Pose ou retire une option avancée (split, maintenance, signed_url, graphql, bandwidth, redact_json, html_inject, hedge, static, request_schema, surface, grpc_web, rate_limit, conditions)

goproxify proxy list   [-admin-url …] [-token …]
goproxify proxy get    <id> [-admin-url …] [-token …]
goproxify proxy labels <id> [-format compose|portainer|portainer_inline|docker_run|kubernetes] [-admin-url …] [-token …]
goproxify proxy enable <id> [-admin-url …] [-token …]
goproxify proxy disable <id> [-admin-url …] [-token …]
goproxify proxy metrics [-admin-url …] [-token …]
goproxify proxy cache-purge <id> [-tag a,b] [-path /x,/y*] [-admin-url …] [-token …]
  Sans -tag ni -path, tout le cache du proxy est vidé.
goproxify proxy option <id> <option> <json|@fichier|off> [-admin-url …] [-token …]
  ex. proxy option 7 maintenance '{"enabled":true,"bypass_cidrs":["10.0.0.0/8"]}'
goproxify proxy delete <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique (skip prompt)
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande proxy inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify proxy help")
		os.Exit(1)
	}
}

func proxyHost(p map[string]any) string {
	if cfg, ok := p["config"].(map[string]any); ok {
		if h, ok := cfg["host"].(string); ok && h != "" {
			return h
		}
	}
	if h, ok := p["host"].(string); ok && h != "" {
		return h
	}
	return ""
}

// advancedProxyOptions : clés de configuration posées par `proxy option` (même liste que l'outil MCP update_proxy).
var advancedProxyOptions = map[string]bool{
	"split": true, "maintenance": true, "signed_url": true, "graphql": true, "bandwidth": true,
	"redact_json": true, "html_inject": true, "hedge": true, "static": true, "request_schema": true, "openapi": true, "grpc_transcode": true, "grpc_web": true, "rate_limit": true, "conditions": true, "surface": true,
	"max_body_size": true, "ip_filter": true, "geo_ip": true, "cors": true, "waf": true,
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// positionalArgs retourne les arguments qui ne sont ni un flag (-x) ni sa valeur.
func positionalArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}
