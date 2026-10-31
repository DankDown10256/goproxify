// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// tracePath construit l'URL de GET /security/ip-trace à partir des flags.
func tracePath(args map[string]string) (string, error) {
	target := flagValue(args, "-target", flagValue(args, "-ip", ""))
	if target == "" && flagValue(args, "-asn", "") == "" {
		return "", fmt.Errorf("usage: goproxify security trace -target <ip|cidr> [-scope ip|asn] [-asn <ASN>] [-from <date>] [-to <date>] [-order desc|asc] [-limit N] [-offset N] [-json]")
	}
	q := url.Values{}
	if target != "" {
		q.Set("target", target)
	}
	for flag, param := range map[string]string{"-scope": "scope", "-asn": "asn", "-from": "from", "-to": "to", "-order": "order", "-limit": "limit", "-offset": "offset"} {
		if v := flagValue(args, flag, ""); v != "" {
			q.Set(param, v)
		}
	}
	return "/api/v1/security/ip-trace?" + q.Encode(), nil
}

func runSecurityTrace() {
	args := parseFlags(os.Args[3:])
	path, err := tracePath(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	var res map[string]any
	if _, err := client.DoJSON("GET", path, nil, &res); err != nil {
		fmt.Fprintf(os.Stderr, "trace : %v\n", err)
		os.Exit(1)
	}
	if _, ok := args["-json"]; ok {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatTrace(res))
}

func formatTrace(res map[string]any) string {
	var sb strings.Builder
	sum, _ := res["summary"].(map[string]any)
	num := func(m map[string]any, k string) int { v, _ := m[k].(float64); return int(v) }
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }

	fmt.Fprintf(&sb, "%s (%s)\n", str(res, "target"), str(res, "kind"))
	if label := str(res, "scope_label"); label != "" {
		fmt.Fprintf(&sb, "  étendue : %s — %s\n", str(res, "scope"), label)
	}
	if c, ok := res["asn_context"].(map[string]any); ok {
		if info, ok := c["asn"].(map[string]any); ok {
			n, _ := info["asn"].(float64)
			fmt.Fprintf(&sb, "  ASN : AS%.0f %s (%s)\n", n, str(info, "name"), str(info, "country"))
		}
	}
	fmt.Fprintf(&sb, "  première vue : %s   dernière vue : %s\n", orDash(str(sum, "first_seen")), orDash(str(sum, "last_seen")))
	fmt.Fprintf(&sb, "  %d requêtes (%d bloquées/détectées) · %d IP · %d épisodes · %d bans / %d débans · %d détections\n",
		num(sum, "requests"), num(sum, "blocked"), num(sum, "ip_count"), num(sum, "episodes"), num(sum, "bans"), num(sum, "unbans"), num(sum, "threats"))
	if bans, _ := sum["active_bans"].([]any); len(bans) > 0 {
		fmt.Fprintf(&sb, "  bans en cours : %d\n", len(bans))
	}
	if ps, _ := sum["profiles"].([]any); len(ps) > 0 {
		names := make([]string, 0, len(ps))
		for _, p := range ps {
			if m, ok := p.(map[string]any); ok {
				names = append(names, str(m, "name"))
			}
		}
		fmt.Fprintf(&sb, "  profils IP : %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintln(&sb)

	steps, _ := res["steps"].([]any)
	if len(steps) == 0 {
		sb.WriteString("(aucune activité, ban ni détection sur la période)\n")
		return sb.String()
	}
	for _, s := range steps {
		m, _ := s.(map[string]any)
		ts := str(m, "ts")
		switch kind := str(m, "kind"); kind {
		case "activity":
			b, _ := m["burst"].(map[string]any)
			fmt.Fprintf(&sb, "%s  ACTIVITÉ  %d req (%d bloquées) jusqu'à %s", ts, num(b, "requests"), num(b, "blocked"), str(m, "end"))
			if d, _ := b["domains"].([]any); len(d) > 0 {
				fmt.Fprintf(&sb, " · %v", d)
			}
			sb.WriteString("\n")
		default:
			fmt.Fprintf(&sb, "%s  %-8s  %s %s %s\n", ts, strings.ToUpper(kind), str(m, "ip"), str(m, "source"), str(m, "reason"))
			if ua := str(m, "user_agent"); ua != "" {
				fmt.Fprintf(&sb, "%s  User-Agent : %s\n", strings.Repeat(" ", len(ts)), ua)
			}
		}
	}
	if more, _ := res["has_more"].(bool); more {
		fmt.Fprintf(&sb, "\n… %d étapes au total, utilisez -offset/-limit pour la suite\n", num(res, "total_steps"))
	}
	return sb.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
