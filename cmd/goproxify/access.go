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

func runAccess() {
	resource := subcommand(os.Args, 2)
	switch resource {
	case "config":
		runAccessConfig()
	case "destinations":
		runAccessDestinations()
	case "users":
		runAccessUsers()
	case "audit":
		runAccessAudit()
	case "templates":
		runAccessTemplates()
	case "help", "-h", "--help", "":
		accessUsage()
	default:
		fmt.Fprintf(os.Stderr, "ressource Access inconnue : %q\n\n", resource)
		accessUsage()
		os.Exit(1)
	}
}

func accessUsage() {
	fmt.Print(`Usage: goproxify access <ressource> <action> [options]

Ressources :
  config         Options portail Access par Core
  destinations   Catalogue de destinations
  users          Utilisateurs Access (invite SMTP)
  audit          Journal d'audit Access
  templates      Templates HTML Access

Exemples :
  goproxify access config get -core core-a
  goproxify access config set -core core-a -enabled true -public-host access.example.com
  goproxify access config push -core core-a
  goproxify access destinations list -core core-a
  goproxify access destinations create -core core-a -name bastion -kind ssh -host 10.0.0.1 -port 22 -tags prod
  goproxify access destinations delete -id <uuid>
  goproxify access users list -core core-a
  goproxify access users invite -email user@ex.com -home-core core-a -tags prod
  goproxify access users update -id <uuid> -status disabled
  goproxify access users resend -id <uuid>
  goproxify access users delete -id <uuid>
  goproxify access audit list -core core-a -limit 50
  goproxify access templates list
  goproxify access templates get -key login
  goproxify access templates set -key login -body-file ./login.html
  goproxify access templates push

` + adminAuthHint() + "\n")
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func mustAdminClient(args map[string]string) *adminClient {
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	return client
}

func requireFlag(args map[string]string, key, label string) string {
	v := flagValue(args, key, "")
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s requis (%s)\n", label, key)
		os.Exit(1)
	}
	return v
}

func parseBoolFlag(args map[string]string, key string) (bool, bool) {
	v, ok := args[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		fmt.Fprintf(os.Stderr, "%s : valeur booléenne invalide %q\n", key, v)
		os.Exit(1)
		return false, false
	}
}

func parseTagsFlag(args map[string]string) []string {
	raw := flagValue(args, "-tags", "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runAccessConfig() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	switch action {
	case "get":
		core := requireFlag(args, "-core", "Core")
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal?core="+core, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access config get : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "set":
		core := requireFlag(args, "-core", "Core")
		var cur map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/portal?core="+core, nil, &cur); err != nil {
			fmt.Fprintf(os.Stderr, "access config get : %v\n", err)
			os.Exit(1)
		}
		if b, ok := parseBoolFlag(args, "-enabled"); ok {
			cur["enabled"] = b
		}
		if v := flagValue(args, "-ssh-port", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "-ssh-port invalide\n")
				os.Exit(1)
			}
			cur["ssh_port"] = n
		}
		if v := flagValue(args, "-http-port", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "-http-port invalide\n")
				os.Exit(1)
			}
			cur["http_port"] = n
		}
		if _, ok := args["-public-host"]; ok {
			cur["public_host"] = flagValue(args, "-public-host", "")
		}
		if b, ok := parseBoolFlag(args, "-allow-personal-targets"); ok {
			cur["allow_personal_targets"] = b
		}
		if b, ok := parseBoolFlag(args, "-require-2fa"); ok {
			cur["require_2fa"] = b
		}
		if v := flagValue(args, "-session-ttl", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "-session-ttl invalide\n")
				os.Exit(1)
			}
			cur["session_ttl_sec"] = n
		}
		if v := flagValue(args, "-session-mode", ""); v != "" {
			cur["session_mode"] = v
		}
		var out any
		if _, err := client.DoJSON("PUT", "/api/v1/portal?core="+core, cur, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access config set : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "push":
		core := requireFlag(args, "-core", "Core")
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/push?core="+core, map[string]any{}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access config push : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access config get|set|push -core <nom> ...")
		os.Exit(1)
	}
}

func runAccessDestinations() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	switch action {
	case "list":
		path := "/api/v1/portal/destinations"
		if core := flagValue(args, "-core", ""); core != "" {
			path += "?core=" + core
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access destinations list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "create":
		core := requireFlag(args, "-core", "Core")
		name := requireFlag(args, "-name", "Nom")
		kind := requireFlag(args, "-kind", "Kind (ssh|docker)")
		port := 22
		if v := flagValue(args, "-port", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "-port invalide\n")
				os.Exit(1)
			}
			port = n
		}
		body := map[string]any{
			"core_name":  core,
			"name":       name,
			"kind":       kind,
			"host":       flagValue(args, "-host", ""),
			"port":       port,
			"agent_name": flagValue(args, "-agent", ""),
			"container":  flagValue(args, "-container", ""),
			"tags":       parseTagsFlag(args),
		}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/destinations", body, &out, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "access destinations create : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "delete":
		id := requireFlag(args, "-id", "ID")
		var out any
		if _, err := client.DoJSON("DELETE", "/api/v1/portal/destinations/"+id, nil, &out, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "access destinations delete : %v\n", err)
			os.Exit(1)
		}
		if out != nil {
			printJSON(out)
		} else {
			fmt.Println("ok")
		}
	case "preview":
		core := requireFlag(args, "-core", "Core")
		path := "/api/v1/portal/destinations/preview?core=" + core
		if tags := flagValue(args, "-tags", ""); tags != "" {
			path += "&tags=" + tags
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access destinations preview : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access destinations list|create|delete|preview ...")
		os.Exit(1)
	}
}

func runAccessUsers() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	switch action {
	case "list":
		path := "/api/v1/portal/users"
		if core := flagValue(args, "-core", ""); core != "" {
			path += "?core=" + core
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access users list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "invite":
		email := requireFlag(args, "-email", "Email")
		home := requireFlag(args, "-home-core", "home-core")
		body := map[string]any{
			"email":     email,
			"home_core": home,
			"tags":      parseTagsFlag(args),
		}
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/users/invite", body, &out, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "access users invite : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "update":
		id := requireFlag(args, "-id", "ID")
		body := map[string]any{}
		if _, ok := args["-tags"]; ok {
			body["tags"] = parseTagsFlag(args)
		}
		if v := flagValue(args, "-status", ""); v != "" {
			body["status"] = v
		}
		if v := flagValue(args, "-home-core", ""); v != "" {
			body["home_core"] = v
		}
		if len(body) == 0 {
			fmt.Fprintln(os.Stderr, "aucun champ (-tags / -status / -home-core)")
			os.Exit(1)
		}
		var out any
		if _, err := client.DoJSON("PUT", "/api/v1/portal/users/"+id, body, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access users update : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "delete":
		id := requireFlag(args, "-id", "ID")
		var out any
		if _, err := client.DoJSON("DELETE", "/api/v1/portal/users/"+id, nil, &out, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "access users delete : %v\n", err)
			os.Exit(1)
		}
		if out != nil {
			printJSON(out)
		} else {
			fmt.Println("ok")
		}
	case "resend":
		id := requireFlag(args, "-id", "ID")
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/users/"+id+"/resend", map[string]any{}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access users resend : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access users list|invite|update|delete|resend ...")
		os.Exit(1)
	}
}

func runAccessAudit() {
	action := subcommand(os.Args, 3)
	var args map[string]string
	switch {
	case action == "list":
		args = parseFlags(os.Args[4:])
	case action == "" || strings.HasPrefix(action, "-"):
		args = parseFlags(os.Args[3:])
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access audit list [-core] [-limit]")
		os.Exit(1)
	}
	client := mustAdminClient(args)
	path := "/api/v1/portal/audit"
	q := []string{}
	if core := flagValue(args, "-core", ""); core != "" {
		q = append(q, "core="+core)
	}
	if lim := flagValue(args, "-limit", ""); lim != "" {
		q = append(q, "limit="+lim)
	}
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}
	var out any
	if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
		fmt.Fprintf(os.Stderr, "access audit list : %v\n", err)
		os.Exit(1)
	}
	printJSON(out)
}

func runAccessTemplates() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	switch action {
	case "list":
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal-page-templates", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access templates list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "get":
		key := requireFlag(args, "-key", "Clé")
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal-page-templates/"+key, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access templates get : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "set":
		key := requireFlag(args, "-key", "Clé")
		bodyHTML := flagValue(args, "-body", "")
		if f := flagValue(args, "-body-file", ""); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "lecture -body-file : %v\n", err)
				os.Exit(1)
			}
			bodyHTML = string(b)
		}
		name := flagValue(args, "-name", key)
		var out any
		if _, err := client.DoJSON("PUT", "/api/v1/portal-page-templates/"+key, map[string]any{
			"name": name,
			"body": bodyHTML,
		}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access templates set : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "delete":
		key := requireFlag(args, "-key", "Clé")
		var out any
		if _, err := client.DoJSON("DELETE", "/api/v1/portal-page-templates/"+key, nil, &out, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "access templates delete : %v\n", err)
			os.Exit(1)
		}
		if out != nil {
			printJSON(out)
		} else {
			fmt.Println("ok")
		}
	case "push":
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal-page-templates/push", map[string]any{}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access templates push : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access templates list|get|set|delete|push ...")
		os.Exit(1)
	}
}
