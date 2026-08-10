// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func runNodes() {
	action := subcommand(os.Args, 2)
	switch action {
	case "list", "":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		path := "/api/v1/nodes"
		if role := flagValue(args, "-role", ""); role != "" {
			path += "?role=" + role
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "nodes list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "accept":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		id := requireFlag(args, "-id", "ID nœud")
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/nodes/"+id+"/accept", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "nodes accept : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "reject":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		id := requireFlag(args, "-id", "ID nœud")
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/nodes/"+id+"/reject", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "nodes reject : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "help", "-h", "--help":
		nodesUsage()
	default:
		fmt.Fprintf(os.Stderr, "action nodes inconnue : %q\n\n", action)
		nodesUsage()
		os.Exit(1)
	}
}

func nodesUsage() {
	fmt.Print(`Usage: goproxify nodes <action> [options]

Actions :
  list     Liste les nœuds (online, declared, pending)
  accept   Accepte un nœud en attente
  reject   Rejette un nœud en attente

Exemples :
  goproxify nodes list
  goproxify nodes list -role core
  goproxify nodes accept -id <pending-id>
  goproxify nodes reject -id <pending-id>

` + adminAuthHint() + "\n")
}

func runDeclared() {
	action := subcommand(os.Args, 2)
	switch action {
	case "list", "":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/declared-nodes", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "declared list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "create":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		role := requireFlag(args, "-role", "Rôle")
		name := requireFlag(args, "-name", "Nom")
		body := map[string]any{
			"role":        role,
			"name":        name,
			"region":      flagValue(args, "-region", ""),
			"environment": flagValue(args, "-environment", ""),
		}
		if cfgPath := flagValue(args, "-config-file", ""); cfgPath != "" {
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "config-file : %v\n", err)
				os.Exit(1)
			}
			var cfg any
			if err := json.Unmarshal(raw, &cfg); err != nil {
				fmt.Fprintf(os.Stderr, "config-file JSON : %v\n", err)
				os.Exit(1)
			}
			body["config"] = cfg
		} else if raw := flagValue(args, "-config", ""); raw != "" {
			var cfg any
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				fmt.Fprintf(os.Stderr, "-config JSON : %v\n", err)
				os.Exit(1)
			}
			body["config"] = cfg
		}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/declared-nodes", body, &out, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "declared create : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "delete":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("DELETE", "/api/v1/declared-nodes/"+id, nil, nil, 204, 200); err != nil {
			fmt.Fprintf(os.Stderr, "declared delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	case "help", "-h", "--help":
		declaredUsage()
	default:
		fmt.Fprintf(os.Stderr, "action declared inconnue : %q\n\n", action)
		declaredUsage()
		os.Exit(1)
	}
}

func declaredUsage() {
	fmt.Print(`Usage: goproxify declared <action> [options]

Actions :
  list     Liste les nœuds déclarés (wizard architecture)
  create   Déclare un nœud Core ou Agent (upsert rôle+nom)
  delete   Supprime un nœud déclaré

Exemples :
  goproxify declared list
  goproxify declared create -role core -name core-edge -region eu-west
  goproxify declared create -role agent -name agent-1 -config '{"target_core":"core-edge"}'
  goproxify declared delete -id dn_abc123

` + adminAuthHint() + "\n")
}

func runBootstrap() {
	action := subcommand(os.Args, 2)
	switch action {
	case "create", "":
		args := parseFlags(os.Args[3:])
		client := mustAdminClient(args)
		body := map[string]any{
			"host_name":     flagValue(args, "-host", ""),
			"core_endpoint": flagValue(args, "-core-endpoint", ""),
			"payload":       map[string]any{},
		}
		if ttl := flagValue(args, "-ttl", ""); ttl != "" {
			n, err := strconv.Atoi(strings.TrimSuffix(ttl, "h"))
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "-ttl invalide (heures, ex: 24)\n")
				os.Exit(1)
			}
			body["ttl_hours"] = n
		}
		if b, ok := parseBoolFlag(args, "-auto-accept"); ok {
			body["auto_accept"] = b
		}
		if raw := flagValue(args, "-node-names", ""); raw != "" {
			parts := strings.Split(raw, ",")
			out := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
			body["node_names"] = out
		}
		if cfgPath := flagValue(args, "-payload-file", ""); cfgPath != "" {
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "payload-file : %v\n", err)
				os.Exit(1)
			}
			var payload any
			if err := json.Unmarshal(raw, &payload); err != nil {
				fmt.Fprintf(os.Stderr, "payload-file JSON : %v\n", err)
				os.Exit(1)
			}
			body["payload"] = payload
		} else if raw := flagValue(args, "-payload", ""); raw != "" {
			var payload any
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				fmt.Fprintf(os.Stderr, "-payload JSON : %v\n", err)
				os.Exit(1)
			}
			body["payload"] = payload
		}
		var out map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/bootstrap-tickets", body, &out, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap create : %v\n", err)
			os.Exit(1)
		}
		if _, noQR := args["-no-qr"]; noQR {
			delete(out, "qr_code")
		}
		printJSON(out)
	case "help", "-h", "--help":
		bootstrapUsage()
	default:
		fmt.Fprintf(os.Stderr, "action bootstrap inconnue : %q\n\n", action)
		bootstrapUsage()
		os.Exit(1)
	}
}

func bootstrapUsage() {
	fmt.Print(`Usage: goproxify bootstrap create [options]

Crée un ticket d'intégration (QR + lien /i/{token} + curl|bash) ancré au Core.

Options :
  -host <nom>              Nom de l'hôte
  -core-endpoint <url>     Endpoint Core (ex: http://core:8000)
  -ttl <heures>            TTL du ticket (défaut 24, max 168)
  -auto-accept true|false  Auto-accept des nœuds liés (défaut true)
  -node-names a,b          Noms de nœuds pour l'auto-accept
  -payload '{...}'         Payload JSON
  -payload-file <path>     Payload depuis un fichier JSON
  -no-qr                   Omet le champ qr_code (base64) dans la sortie

Exemples :
  goproxify bootstrap create -host edge-1 -core-endpoint http://192.0.2.10:8000 -node-names core-edge -no-qr
  curl -fsSL "$(goproxify bootstrap create -host h1 -no-qr | jq -r .script_url)" | bash

` + adminAuthHint() + "\n")
}
