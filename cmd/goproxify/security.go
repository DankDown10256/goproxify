// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

func runSecurity() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "threat":
		runSecurityThreat()
	case "bans":
		runSecurityBans()
	case "waf":
		runSecurityWAF()
	case "rules":
		runSecurityRules()
	case "help", "":
		fmt.Print(`Usage: goproxify security <sous-commande> [options]

Sous-commandes :
  threat   Config du moteur Sentinel (threat engine global)
  bans     Gestion des IPs bannies
  waf      Config WAF d'un proxy
  rules    Moteur de règles automatiques

goproxify security threat get  [-edge <id>] [-admin-url …] [-token …]
goproxify security threat set  [-edge <id>] -file <config.json> [-admin-url …] [-token …]

goproxify security bans list   [-admin-url …] [-token …]
goproxify security bans add    -ip <ip> [-reason <raison>] [-ttl <durée>] [-admin-url …] [-token …]
goproxify security bans delete -id <ban-id> [-admin-url …] [-token …]

goproxify security waf get  -proxy <id> [-admin-url …] [-token …]
goproxify security waf set  -proxy <id> -file <config.json> [-admin-url …] [-token …]

goproxify security rules list   [-admin-url …] [-token …]
goproxify security rules get    <id> [-admin-url …] [-token …]
goproxify security rules create -file <rule.json> [-admin-url …] [-token …]
goproxify security rules update <id> -file <rule.json> [-admin-url …] [-token …]
goproxify security rules delete <id> [-y] [-admin-url …] [-token …]
goproxify security rules run    <id> [-dry-run] [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande security inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify security help")
		os.Exit(1)
	}
}

// ── Threat (Sentinel) ─────────────────────────────────────────────────────────

func runSecurityThreat() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		edgeID := flagValue(args, "-edge", "")
		path := "/api/v1/security/threat-config"
		if edgeID != "" {
			path += "?edge=" + url.QueryEscape(edgeID)
		}
		var cfg json.RawMessage
		if _, err := client.DoJSON("GET", path, nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "threat get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security threat set -file <config.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var cfg json.RawMessage
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		edgeID := flagValue(args, "-edge", "")
		path := "/api/v1/security/threat-config"
		if edgeID != "" {
			path += "?edge=" + url.QueryEscape(edgeID)
		}
		if _, err := client.DoJSON("PUT", path, cfg, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "threat set : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Config Sentinel mise à jour.")

	default:
		fmt.Fprintf(os.Stderr, "sous-commande threat inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Bans ──────────────────────────────────────────────────────────────────────

func runSecurityBans() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var bans []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/security/bans", nil, &bans); err != nil {
			fmt.Fprintf(os.Stderr, "bans list : %v\n", err)
			os.Exit(1)
		}
		if len(bans) == 0 {
			fmt.Println("(aucun ban)")
			return
		}
		for _, b := range bans {
			id, _ := b["id"].(string)
			ip, _ := b["ip"].(string)
			reason, _ := b["reason"].(string)
			expires, _ := b["expires_at"].(string)
			line := fmt.Sprintf("%-36s  %-20s  %s", id, ip, reason)
			if expires != "" {
				line += "  (exp: " + expires + ")"
			}
			fmt.Println(line)
		}

	case "add":
		args := parseFlags(os.Args[4:])
		ip := flagValue(args, "-ip", "")
		if ip == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans add -ip <ip> [-reason …] [-ttl …]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		payload := map[string]any{"ip": ip}
		if r := flagValue(args, "-reason", ""); r != "" {
			payload["reason"] = r
		}
		if ttl := flagValue(args, "-ttl", ""); ttl != "" {
			payload["ttl"] = ttl
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/security/bans", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "bans add : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		fmt.Printf("Ban créé : %s → %s\n", id, ip)

	case "delete":
		args := parseFlags(os.Args[4:])
		id := flagValue(args, "-id", "")
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans delete -id <ban-id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/security/bans/"+id, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "bans delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Ban %s supprimé.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande bans inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── WAF (par proxy) ───────────────────────────────────────────────────────────

func runSecurityWAF() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[4:])
		proxyID := flagValue(args, "-proxy", "")
		if proxyID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security waf get -proxy <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var proxy map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(proxyID), nil, &proxy); err != nil {
			fmt.Fprintf(os.Stderr, "proxy get : %v\n", err)
			os.Exit(1)
		}
		cfg := proxyConfig(proxy)
		wafFields := map[string]any{}
		for _, k := range []string{"waf", "sentinel_whitelist"} {
			if v, ok := cfg[k]; ok {
				wafFields[k] = v
			}
		}
		out, _ := json.MarshalIndent(wafFields, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[4:])
		proxyID := flagValue(args, "-proxy", "")
		file := flagValue(args, "-file", "")
		if proxyID == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security waf set -proxy <id> -file <config.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var patch map[string]any
		if err := json.Unmarshal(data, &patch); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		// Lire la config existante et merger
		var proxy map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(proxyID), nil, &proxy); err != nil {
			fmt.Fprintf(os.Stderr, "proxy get : %v\n", err)
			os.Exit(1)
		}
		cfg := proxyConfig(proxy)
		for k, v := range patch {
			cfg[k] = v
		}
		proxy["config"] = cfg
		if _, err := client.DoJSON("PUT", "/api/v1/proxies/"+url.PathEscape(proxyID), proxy, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "proxy set : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config WAF/Sentinel du proxy %s mise à jour.\n", proxyID)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande waf inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Rules (moteur de règles automatiques) ────────────────────────────────────

func runSecurityRules() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var rules []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/rules-engine/rules", nil, &rules); err != nil {
			fmt.Fprintf(os.Stderr, "rules list : %v\n", err)
			os.Exit(1)
		}
		if len(rules) == 0 {
			fmt.Println("(aucune règle)")
			return
		}
		for _, r := range rules {
			id, _ := r["id"].(string)
			name, _ := r["name"].(string)
			enabled, _ := r["enabled"].(bool)
			status := "✓"
			if !enabled {
				status = "✗"
			}
			fmt.Printf("[%s] %-36s  %s\n", status, id, name)
		}

	case "get":
		ruleID := subcommand(os.Args, 4)
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules get <id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var rule json.RawMessage
		if _, err := client.DoJSON("GET", "/api/v1/rules-engine/rules/"+ruleID, nil, &rule); err != nil {
			fmt.Fprintf(os.Stderr, "rules get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(rule, "", "  ")
		fmt.Println(string(out))

	case "create":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules create -file <rule.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var body json.RawMessage
		if err := json.Unmarshal(data, &body); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/rules-engine/rules", body, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "rules create : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		fmt.Printf("Règle créée : %s\n", id)

	case "update":
		ruleID := subcommand(os.Args, 4)
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules update <id> -file <rule.json>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules update <id> -file <rule.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var body json.RawMessage
		if err := json.Unmarshal(data, &body); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", "/api/v1/rules-engine/rules/"+ruleID, body, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "rules update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Règle %s mise à jour.\n", ruleID)

	case "delete":
		ruleID := subcommand(os.Args, 4)
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules delete <id> [-y]")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		if flagValue(args, "-y", "") == "" {
			fmt.Printf("Supprimer la règle %s ? [y/N] ", ruleID)
			var ans string
			fmt.Scanln(&ans) //nolint:errcheck
			if ans != "y" && ans != "Y" {
				fmt.Println("Annulé.")
				return
			}
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/rules-engine/rules/"+ruleID, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "rules delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Règle %s supprimée.\n", ruleID)

	case "run":
		ruleID := subcommand(os.Args, 4)
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules run <id> [-dry-run]")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		dryRun := flagValue(args, "-dry-run", "true") != "false"
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		path := "/api/v1/rules-engine/rules/" + ruleID + "/run"
		if dryRun {
			path += "?dry_run=true"
		} else {
			path += "?dry_run=false"
		}
		var result json.RawMessage
		if _, err := client.DoJSON("POST", path, nil, &result, 200); err != nil {
			fmt.Fprintf(os.Stderr, "rules run : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "sous-commande rules inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// proxyConfig extrait la map config d'un proxy (config peut être JSON string ou map).
func proxyConfig(proxy map[string]any) map[string]any {
	switch v := proxy["config"].(type) {
	case map[string]any:
		return v
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(v), &m) == nil {
			return m
		}
	}
	return map[string]any{}
}

