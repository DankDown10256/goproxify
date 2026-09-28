// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	case "schedule":
		runSecuritySchedule()
	case "playbook":
		runSecurityPlaybook()
	case "cve":
		runSecurityCVE()
	case "help", "":
		fmt.Print(`Usage: goproxify security <sous-commande> [options]

Sous-commandes :
  threat   Config du moteur Sentinel (threat engine global)
  bans     Gestion des IPs bannies
  waf      Config WAF d'un proxy
  rules    Moteur de règles automatiques
  schedule Planifications (cron) : exécute une action à heure fixe
  playbook Enchaîne plusieurs étapes (action, attente, condition, approbation)
  cve      SLA de correction des CVE (délai attendu selon la gravité)

goproxify security threat get  [-edge <id>] [-admin-url …] [-token …]
goproxify security threat set  [-edge <id>] -file <config.json> [-admin-url …] [-token …]
goproxify security threat simulate -file <config.json> [-hours N] [-domain <d>] [-edge <id>]

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

goproxify security rules silence list   [-admin-url …] [-token …]
goproxify security rules silence add    -name <nom> -starts <RFC3339> -ends <RFC3339> [-rules <id1,id2>] [-admin-url …] [-token …]
goproxify security rules silence delete <id> [-y] [-admin-url …] [-token …]

goproxify security rules history list          [-admin-url …] [-token …]
goproxify security rules history replay <id>   [-admin-url …] [-token …]

goproxify security rules pending list            [-admin-url …] [-token …]
goproxify security rules pending approve <id>    [-admin-url …] [-token …]
goproxify security rules pending reject  <id>    [-admin-url …] [-token …]

goproxify security rules export [-out <fichier.yaml>] [-admin-url …] [-token …]
goproxify security rules import -file <automation.yaml> [-admin-url …] [-token …]

goproxify security rules versions list    <rule-id>            [-admin-url …] [-token …]
goproxify security rules versions restore <rule-id> <version>  [-admin-url …] [-token …]

goproxify security schedule list                       [-admin-url …] [-token …]
goproxify security schedule create -file <task.json>   [-admin-url …] [-token …]
goproxify security schedule update <id> -file <task.json> [-admin-url …] [-token …]
goproxify security schedule delete <id> [-y]           [-admin-url …] [-token …]
goproxify security schedule run    <id>                [-admin-url …] [-token …]
goproxify security schedule history <id>               [-admin-url …] [-token …]

goproxify security playbook list                         [-admin-url …] [-token …]
goproxify security playbook create -file <playbook.json> [-admin-url …] [-token …]
goproxify security playbook update <id> -file <playbook.json> [-admin-url …] [-token …]
goproxify security playbook delete <id> [-y]             [-admin-url …] [-token …]
goproxify security playbook run    <id>                  [-admin-url …] [-token …]
goproxify security playbook history <id>                 [-admin-url …] [-token …]
goproxify security playbook approve <run-id>             [-admin-url …] [-token …]
goproxify security playbook reject  <run-id>             [-admin-url …] [-token …]

goproxify security cve sla get [-admin-url …] [-token …]
goproxify security cve sla set -file <sla.json> [-admin-url …] [-token …]
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

	case "simulate":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security threat simulate -file <config.json> [-hours N] [-domain <d>] [-edge <id>]")
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
		hours, _ := strconv.Atoi(flagValue(args, "-hours", "1"))
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		path := "/api/v1/security/threat-config/simulate"
		if edgeID := flagValue(args, "-edge", ""); edgeID != "" {
			path += "?edge=" + url.QueryEscape(edgeID)
		}
		body := map[string]any{"config": cfg, "hours": hours, "domain": flagValue(args, "-domain", "")}
		var res json.RawMessage
		if _, err := client.DoJSON("POST", path, body, &res); err != nil {
			fmt.Fprintf(os.Stderr, "threat simulate : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "sous-commande threat inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Bans ──────────────────────────────────────────────────────────────────────

// bansListPath ajoute les filtres -edge, -source et -active (true|false) à la liste des bans.
func bansListPath(args map[string]string) string {
	q := url.Values{}
	for flag, param := range map[string]string{"-edge": "edge", "-source": "source", "-active": "active"} {
		if v := flagValue(args, flag, ""); v != "" {
			q.Set(param, v)
		}
	}
	if len(q) == 0 {
		return "/api/v1/security/bans"
	}
	return "/api/v1/security/bans?" + q.Encode()
}

func bansEdgeSuffix(b map[string]any) string {
	if edge, _ := b["edge_name"].(string); edge != "" {
		return "  [" + edge + "]"
	}
	return ""
}

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
		if _, err := client.DoJSON("GET", bansListPath(args), nil, &bans); err != nil {
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
			line := fmt.Sprintf("%-36s  %-20s  %s%s", id, ip, reason, bansEdgeSuffix(b))
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

	case "silence":
		runSecurityRulesSilence()

	case "history":
		runSecurityRulesHistory()

	case "pending":
		runSecurityRulesPending()

	case "versions":
		runSecurityRulesVersions()

	case "export":
		args := parseFlags(os.Args[4:])
		out := flagValue(args, "-out", "")
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		data, _, _, err := client.DoRaw("GET", "/api/v1/rules-engine/export", nil, "", 200)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules export : %v\n", err)
			os.Exit(1)
		}
		if out == "" {
			fmt.Print(string(data))
			return
		}
		if err := os.WriteFile(out, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "écriture fichier : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Exporté vers %s\n", out)

	case "import":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules import -file <automation.yaml>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		resData, _, _, err := client.DoRaw("POST", "/api/v1/rules-engine/import", data, "application/x-yaml", 200)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules import : %v\n", err)
			os.Exit(1)
		}
		var summary map[string]int
		_ = json.Unmarshal(resData, &summary)
		fmt.Printf("Règles : %d créées, %d mises à jour\n", summary["rules_created"], summary["rules_updated"])
		fmt.Printf("Canaux : %d créés, %d mis à jour\n", summary["channels_created"], summary["channels_updated"])
		fmt.Printf("Silences : %d créés\n", summary["silences_created"])

	default:
		fmt.Fprintf(os.Stderr, "sous-commande rules inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Silences (fenêtres de suspension des actions du moteur de règles) ───────

func runSecurityRulesSilence() {
	sub := subcommand(os.Args, 4)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var silences []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/rules-engine/silences", nil, &silences); err != nil {
			fmt.Fprintf(os.Stderr, "silence list : %v\n", err)
			os.Exit(1)
		}
		if len(silences) == 0 {
			fmt.Println("(aucun silence)")
			return
		}
		for _, s := range silences {
			id, _ := s["id"].(string)
			name, _ := s["name"].(string)
			starts, _ := s["starts_at"].(string)
			ends, _ := s["ends_at"].(string)
			ruleIDs, _ := s["rule_ids"].([]any)
			scope := "toutes les règles"
			if len(ruleIDs) > 0 {
				scope = fmt.Sprintf("%d règle(s)", len(ruleIDs))
			}
			fmt.Printf("[%s] %-24s  %s → %s  (%s)\n", id, name, starts, ends, scope)
		}

	case "add":
		args := parseFlags(os.Args[5:])
		name := flagValue(args, "-name", "")
		starts := flagValue(args, "-starts", "")
		ends := flagValue(args, "-ends", "")
		if name == "" || starts == "" || ends == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules silence add -name <nom> -starts <RFC3339> -ends <RFC3339> [-rules <id1,id2>]")
			os.Exit(1)
		}
		var ruleIDs []string
		if raw := flagValue(args, "-rules", ""); raw != "" {
			ruleIDs = strings.Split(raw, ",")
		}
		body := map[string]any{"name": name, "starts_at": starts, "ends_at": ends, "rule_ids": ruleIDs}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/rules-engine/silences", body, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "silence add : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		fmt.Printf("Silence créé : %s\n", id)

	case "delete":
		id := subcommand(os.Args, 5)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules silence delete <id> [-y]")
			os.Exit(1)
		}
		args := parseFlags(os.Args[6:])
		if flagValue(args, "-y", "") == "" {
			fmt.Printf("Supprimer le silence %s ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/rules-engine/silences/"+id, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "silence delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Silence %s supprimé.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande silence inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Historique d'exécution (journal) ─────────────────────────────────────────

func runSecurityRulesHistory() {
	sub := subcommand(os.Args, 4)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var hist []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/rules-engine/history", nil, &hist); err != nil {
			fmt.Fprintf(os.Stderr, "history list : %v\n", err)
			os.Exit(1)
		}
		if len(hist) == 0 {
			fmt.Println("(aucune entrée)")
			return
		}
		for _, h := range hist {
			id := int64(h["id"].(float64))
			ruleName, _ := h["rule_name"].(string)
			condResult, _ := h["cond_result"].(bool)
			actionTaken, _ := h["action_taken"].(bool)
			errMsg, _ := h["error"].(string)
			firedAt, _ := h["fired_at"].(string)
			status := "non déclenchée"
			if condResult {
				status = "déclenchée, sans action"
				if actionTaken {
					status = "exécutée"
				} else if errMsg == "silenced" {
					status = "silencée"
				} else if errMsg != "" {
					status = "échec : " + errMsg
				}
			}
			fmt.Printf("[%d] %-24s  %-36s  %s\n", id, firedAt, ruleName, status)
		}

	case "replay":
		id := subcommand(os.Args, 5)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules history replay <id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[6:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/rules-engine/history/"+id+"/replay", nil, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "history replay : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Entrée %s rejouée.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande history inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Approbation avant action ──────────────────────────────────────────────────

func runSecurityRulesPending() {
	sub := subcommand(os.Args, 4)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var pending []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/rules-engine/pending?status=pending", nil, &pending); err != nil {
			fmt.Fprintf(os.Stderr, "pending list : %v\n", err)
			os.Exit(1)
		}
		if len(pending) == 0 {
			fmt.Println("(aucune action en attente)")
			return
		}
		for _, p := range pending {
			id, _ := p["id"].(string)
			ruleName, _ := p["rule_name"].(string)
			createdAt, _ := p["created_at"].(string)
			action, _ := p["action"].(map[string]any)
			actionType, _ := action["type"].(string)
			fmt.Printf("[%s] %-24s  %-18s  %s\n", id, createdAt, ruleName, actionType)
		}

	case "approve", "reject":
		id := subcommand(os.Args, 5)
		if id == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify security rules pending %s <id>\n", sub)
			os.Exit(1)
		}
		args := parseFlags(os.Args[6:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/rules-engine/pending/"+id+"/"+sub, nil, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "pending %s : %v\n", sub, err)
			os.Exit(1)
		}
		verb := "approuvée"
		if sub == "reject" {
			verb = "refusée"
		}
		fmt.Printf("Action %s %s.\n", id, verb)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande pending inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Versionnage des règles (instantanés + retour arrière) ────────────────────

func runSecurityRulesVersions() {
	sub := subcommand(os.Args, 4)
	switch sub {
	case "list", "":
		ruleID := subcommand(os.Args, 5)
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules versions list <rule-id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[6:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var versions []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/rules-engine/rules/"+ruleID+"/versions", nil, &versions); err != nil {
			fmt.Fprintf(os.Stderr, "versions list : %v\n", err)
			os.Exit(1)
		}
		if len(versions) == 0 {
			fmt.Println("(aucune version)")
			return
		}
		for _, v := range versions {
			version := int(v["version"].(float64))
			name, _ := v["name"].(string)
			createdAt, _ := v["created_at"].(string)
			fmt.Printf("v%-4d %-24s  %s\n", version, createdAt, name)
		}

	case "restore":
		ruleID := subcommand(os.Args, 5)
		versionStr := subcommand(os.Args, 6)
		if ruleID == "" || versionStr == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security rules versions restore <rule-id> <version>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[7:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/rules-engine/rules/"+ruleID+"/versions/"+versionStr+"/restore", nil, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "versions restore : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Règle %s restaurée à la version %s.\n", ruleID, versionStr)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande versions inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Planifications (cron) ─────────────────────────────────────────────────────

func runSecuritySchedule() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var tasks []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/scheduled-tasks", nil, &tasks); err != nil {
			fmt.Fprintf(os.Stderr, "schedule list : %v\n", err)
			os.Exit(1)
		}
		if len(tasks) == 0 {
			fmt.Println("(aucune planification)")
			return
		}
		for _, tk := range tasks {
			id, _ := tk["id"].(string)
			name, _ := tk["name"].(string)
			cronExpr, _ := tk["cron_expr"].(string)
			enabled := "non"
			if e, ok := tk["enabled"].(bool); ok && e {
				enabled = "oui"
			}
			fmt.Printf("[%s] %-24s  %-18s  actif=%s\n", id, name, cronExpr, enabled)
		}

	case "create":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security schedule create -file <task.json>")
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
		if _, err := client.DoJSON("POST", "/api/v1/scheduled-tasks", body, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "schedule create : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		fmt.Printf("Planification créée : %s\n", id)

	case "update":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security schedule update <id> -file <task.json>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security schedule update <id> -file <task.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/scheduled-tasks/"+id, body, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "schedule update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Planification %s mise à jour.\n", id)

	case "delete":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security schedule delete <id> [-y]")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		if flagValue(args, "-y", "") == "" {
			fmt.Printf("Supprimer la planification %s ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/scheduled-tasks/"+id, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "schedule delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Planification %s supprimée.\n", id)

	case "run":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security schedule run <id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/scheduled-tasks/"+id+"/run", nil, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "schedule run : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Planification %s exécutée.\n", id)

	case "history":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security schedule history <id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var runs []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/scheduled-tasks/"+id+"/runs", nil, &runs); err != nil {
			fmt.Fprintf(os.Stderr, "schedule history : %v\n", err)
			os.Exit(1)
		}
		if len(runs) == 0 {
			fmt.Println("(aucune exécution)")
			return
		}
		for _, run := range runs {
			status := "OK"
			if s, ok := run["success"].(bool); ok && !s {
				status = "ÉCHEC"
			}
			fmt.Printf("%-24v %-6s %v\n", run["ran_at"], status, run["error"])
		}

	default:
		fmt.Fprintf(os.Stderr, "sous-commande schedule inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Playbooks (enchaîne action / attente / condition / approbation) ──────────

func runSecurityPlaybook() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var pbs []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/playbooks", nil, &pbs); err != nil {
			fmt.Fprintf(os.Stderr, "playbook list : %v\n", err)
			os.Exit(1)
		}
		if len(pbs) == 0 {
			fmt.Println("(aucun playbook)")
			return
		}
		for _, pb := range pbs {
			id, _ := pb["id"].(string)
			name, _ := pb["name"].(string)
			steps, _ := pb["steps"].([]any)
			enabled := "non"
			if e, ok := pb["enabled"].(bool); ok && e {
				enabled = "oui"
			}
			fmt.Printf("[%s] %-24s  %d étape(s)  actif=%s\n", id, name, len(steps), enabled)
		}

	case "create":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security playbook create -file <playbook.json>")
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
		if _, err := client.DoJSON("POST", "/api/v1/playbooks", body, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "playbook create : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		fmt.Printf("Playbook créé : %s\n", id)

	case "update":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security playbook update <id> -file <playbook.json>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security playbook update <id> -file <playbook.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/playbooks/"+id, body, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "playbook update : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Playbook %s mis à jour.\n", id)

	case "delete":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security playbook delete <id> [-y]")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		if flagValue(args, "-y", "") == "" {
			fmt.Printf("Supprimer le playbook %s ? [y/N] ", id)
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
		if _, err := client.DoJSON("DELETE", "/api/v1/playbooks/"+id, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "playbook delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Playbook %s supprimé.\n", id)

	case "run":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security playbook run <id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/playbooks/"+id+"/run", nil, &result, 200); err != nil {
			fmt.Fprintf(os.Stderr, "playbook run : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Playbook démarré, run %s.\n", result["run_id"])

	case "history":
		id := subcommand(os.Args, 4)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security playbook history <id>")
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var runs []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/playbooks/"+id+"/runs", nil, &runs); err != nil {
			fmt.Fprintf(os.Stderr, "playbook history : %v\n", err)
			os.Exit(1)
		}
		if len(runs) == 0 {
			fmt.Println("(aucune exécution)")
			return
		}
		for _, run := range runs {
			fmt.Printf("[%v] %-18s étape %v  %v\n", run["id"], run["status"], run["current_step"], run["started_at"])
		}

	case "approve", "reject":
		runID := subcommand(os.Args, 4)
		if runID == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify security playbook %s <run-id>\n", sub)
			os.Exit(1)
		}
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/playbooks/runs/"+runID+"/"+sub, nil, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "playbook %s : %v\n", sub, err)
			os.Exit(1)
		}
		verb := "approuvé"
		if sub == "reject" {
			verb = "refusé"
		}
		fmt.Printf("Run %s %s.\n", runID, verb)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande playbook inconnue : %q\n", sub)
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

// ── CVE : SLA de correction ───────────────────────────────────────────────────

func runSecurityCVE() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "sla":
		runSecurityCVESLA()
	default:
		fmt.Fprintf(os.Stderr, "sous-commande cve inconnue : %q\n", sub)
		os.Exit(1)
	}
}

func runSecurityCVESLA() {
	sub := subcommand(os.Args, 4)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var cfg json.RawMessage
		if _, err := client.DoJSON("GET", "/api/v1/security/sla-config", nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "cve sla get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[5:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security cve sla set -file <sla.json>")
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
		if _, err := client.DoJSON("PUT", "/api/v1/security/sla-config", cfg, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "cve sla set : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("SLA de correction des CVE mis à jour.")

	default:
		fmt.Fprintf(os.Stderr, "sous-commande cve sla inconnue : %q\n", sub)
		os.Exit(1)
	}
}
