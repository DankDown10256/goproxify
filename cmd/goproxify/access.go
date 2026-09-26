// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
	case "recordings":
		runAccessRecordings()
	case "policy":
		runAccessPolicy()
	case "requests":
		runAccessRequests()
	case "sessions":
		runAccessSessions()
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
  config         Options portail Access par passerelle
  destinations   Catalogue de destinations
  users          Utilisateurs Access (invite SMTP)
  sessions       Connexions Access en cours (lister, observer, terminer)
  requests       Demandes d'accès temporaire (lister, approuver, refuser, révoquer)
  policy         Politique d'accès (plages horaires, IP autorisées, inactivité)
recordings     Enregistrements de sessions (lister, exporter, supprimer)
  audit          Journal d'audit Access
  templates      Templates HTML Access

Exemples :
  goproxify access config get -edge edge-a
  goproxify access config set -edge edge-a -enabled true -public-host access.example.com
  goproxify access config push -edge edge-a
  goproxify access destinations list -edge edge-a
  goproxify access destinations create -edge edge-a -name bastion -kind ssh -host 10.0.0.1 -port 22 -tags prod
  goproxify access destinations delete -id <uuid>
  goproxify access users list -edge edge-a
  goproxify access users invite -email user@ex.com -home-edge edge-a -tags prod
  goproxify access users update -id <uuid> -status disabled
  goproxify access users resend -id <uuid>
  goproxify access users delete -id <uuid>
  goproxify access policy get -edge edge-a
  goproxify access policy set -edge edge-a -hours true -days 1,2,3,4,5 -start 07:00 -end 20:00 -tz Europe/Paris -ip 10.0.0.0/8 -idle 15 -record true -retention 30
  goproxify access recordings list -edge edge-a
  goproxify access recordings get -edge edge-a -id <uuid> > session.cast
  goproxify access requests list -edge edge-a -status pending
  goproxify access requests approve -id <uuid> -minutes 60
  goproxify access requests deny -id <uuid>
  goproxify access sessions list -edge edge-a
  goproxify access sessions watch -edge edge-a -id <uuid>
  goproxify access sessions terminate -edge edge-a -id <uuid>
  goproxify access audit list -edge edge-a -limit 50
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
		edge := requireFlag(args, "-edge", "Passerelle")
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal?edge="+edge, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access config get : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "set":
		edge := requireFlag(args, "-edge", "Passerelle")
		var cur map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/portal?edge="+edge, nil, &cur); err != nil {
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
		if v := flagValue(args, "-ha-session-mode", ""); v != "" {
			if v != "sticky" && v != "shared" {
				fmt.Fprintln(os.Stderr, "-ha-session-mode : sticky ou shared")
				os.Exit(1)
			}
			cur["ha_session_mode"] = v
		}
		var out any
		if _, err := client.DoJSON("PUT", "/api/v1/portal?edge="+edge, cur, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access config set : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "push":
		edge := requireFlag(args, "-edge", "Passerelle")
		var out any
		if _, err := client.DoJSON("POST", "/api/v1/portal/push?edge="+edge, map[string]any{}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access config push : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access config get|set|push -edge <nom> ...")
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
		if edge := flagValue(args, "-edge", ""); edge != "" {
			path += "?edge=" + edge
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access destinations list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "create":
		edge := requireFlag(args, "-edge", "Passerelle")
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
			"edge_name":  edge,
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
		edge := requireFlag(args, "-edge", "Passerelle")
		path := "/api/v1/portal/destinations/preview?edge=" + edge
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
		if edge := flagValue(args, "-edge", ""); edge != "" {
			path += "?edge=" + edge
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access users list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "invite":
		email := requireFlag(args, "-email", "Email")
		home := requireFlag(args, "-home-edge", "home-edge")
		body := map[string]any{
			"email":     email,
			"home_edge": home,
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
		if v := flagValue(args, "-home-edge", ""); v != "" {
			body["home_edge"] = v
		}
		if len(body) == 0 {
			fmt.Fprintln(os.Stderr, "aucun champ (-tags / -status / -home-edge)")
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
		fmt.Fprintln(os.Stderr, "usage: goproxify access audit list [-edge] [-limit]")
		os.Exit(1)
	}
	client := mustAdminClient(args)
	path := "/api/v1/portal/audit"
	q := []string{}
	if edge := flagValue(args, "-edge", ""); edge != "" {
		q = append(q, "edge="+edge)
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

func runAccessSessions() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	edge := requireFlag(args, "-edge", "Passerelle")
	switch action {
	case "list":
		var out any
		if _, err := client.DoJSON("GET", "/api/v1/portal/sessions?edge="+edge, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access sessions list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "watch":
		watchAccessSession(client, edge, requireFlag(args, "-id", "ID"))
	case "terminate":
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("DELETE", "/api/v1/portal/sessions/"+id+"?edge="+edge, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "access sessions terminate : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access sessions list|watch|terminate -edge <passerelle> [-id <uuid>]")
		os.Exit(1)
	}
}

func runAccessRequests() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	switch action {
	case "list":
		edge := requireFlag(args, "-edge", "Passerelle")
		path := "/api/v1/portal/access-requests?edge=" + edge
		if st := flagValue(args, "-status", ""); st != "" {
			path += "&status=" + st
		}
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access requests list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "approve", "deny", "revoke":
		id := requireFlag(args, "-id", "ID")
		body := map[string]any{}
		if m := flagValue(args, "-minutes", ""); m != "" && action == "approve" {
			n, err := strconv.Atoi(m)
			if err != nil {
				fmt.Fprintln(os.Stderr, "access requests approve : -minutes doit être un entier")
				os.Exit(1)
			}
			body["duration_min"] = n
		}
		if _, err := client.DoJSON("POST", "/api/v1/portal/access-requests/"+id+"/"+action, body, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "access requests %s : %v\n", action, err)
			os.Exit(1)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access requests list|approve|deny|revoke [-edge <passerelle>] [-id <uuid>] [-status pending] [-minutes <n>]")
		os.Exit(1)
	}
}

func runAccessPolicy() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	edge := requireFlag(args, "-edge", "Passerelle")
	path := "/api/v1/portal/policy?edge=" + edge
	switch action {
	case "get":
		var out any
		if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access policy get : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "set":
		hours, _ := parseBoolFlag(args, "-hours")
		body := map[string]any{"hours_enabled": hours}
		if v := flagValue(args, "-days", ""); v != "" {
			days := []int{}
			for _, s := range strings.Split(v, ",") {
				n, err := strconv.Atoi(strings.TrimSpace(s))
				if err != nil {
					fmt.Fprintln(os.Stderr, "access policy set : -days attend des nombres 0-6 séparés par des virgules")
					os.Exit(1)
				}
				days = append(days, n)
			}
			body["days"] = days
		}
		for flag, key := range map[string]string{"-start": "start_time", "-end": "end_time", "-tz": "timezone"} {
			if v := flagValue(args, flag, ""); v != "" {
				body[key] = v
			}
		}
		if v := flagValue(args, "-ip", ""); v != "" {
			body["ip_allow"] = strings.Split(v, ",")
		}
		if v := flagValue(args, "-idle", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintln(os.Stderr, "access policy set : -idle doit être un entier (minutes)")
				os.Exit(1)
			}
			body["idle_timeout_min"] = n
		}
		if _, ok := parseBoolFlag(args, "-record"); ok {
			rec, _ := parseBoolFlag(args, "-record")
			body["record_sessions"] = rec
		}
		if v := flagValue(args, "-retention", ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintln(os.Stderr, "access policy set : -retention doit être un entier (jours)")
				os.Exit(1)
			}
			body["record_retention_days"] = n
		}
		var out any
		if _, err := client.DoJSON("PUT", path, body, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access policy set : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access policy get|set -edge <passerelle> [-hours true -days 1,2 -start 07:00 -end 20:00 -tz Europe/Paris -ip <cidr,…> -idle <min> -record true -retention <jours>]")
		os.Exit(1)
	}
}

func runAccessRecordings() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := mustAdminClient(args)
	edge := requireFlag(args, "-edge", "Passerelle")
	base := "/api/v1/portal/recordings"
	switch action {
	case "list":
		var out any
		if _, err := client.DoJSON("GET", base+"?edge="+edge, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "access recordings list : %v\n", err)
			os.Exit(1)
		}
		printJSON(out)
	case "get":
		id := requireFlag(args, "-id", "ID")
		data, _, _, err := client.DoRaw("GET", base+"/"+id+"?edge="+edge, nil, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "access recordings get : %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(data)
	case "delete":
		id := requireFlag(args, "-id", "ID")
		if _, err := client.DoJSON("DELETE", base+"/"+id+"?edge="+edge, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "access recordings delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify access recordings list|get|delete -edge <passerelle> [-id <uuid>]")
		os.Exit(1)
	}
}

// watchAccessSession affiche en direct la sortie d'une connexion Access en cours, jusqu'à sa fin ou Ctrl-C.
func watchAccessSession(client *adminClient, edge, id string) {
	req, err := http.NewRequest("GET", client.url("/api/v1/portal/sessions/"+id+"/watch?edge="+edge), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "access sessions watch : %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+client.token)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "access sessions watch : %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "access sessions watch : HTTP %d (session introuvable ou terminée ?)\n", resp.StatusCode)
		os.Exit(1)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: end") {
			return
		}
		if data, ok := strings.CutPrefix(line, "data: "); ok && data != "" {
			if raw, err := base64.StdEncoding.DecodeString(data); err == nil {
				os.Stdout.Write(raw)
			}
		}
	}
}
