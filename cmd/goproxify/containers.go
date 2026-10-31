// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runContainers() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var containers []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/discovered-containers", nil, &containers); err != nil {
			fmt.Fprintf(os.Stderr, "containers list : %v\n", err)
			os.Exit(1)
		}
		if len(containers) == 0 {
			fmt.Println("(aucun conteneur découvert)")
			return
		}
		fmt.Printf("%-40s  %-10s  %-20s  %-20s  %-38s  %s\n", "HOST", "TLS", "EDGE", "AGENT", "REMPLACÉ PAR (proxy)", "BACKENDS")
		fmt.Println(strings.Repeat("-", 150))
		for _, c := range containers {
			host, _ := c["host"].(string)
			tls := "non"
			if t, ok := c["tls"].(bool); ok && t {
				tls = "oui"
			}
			edge, _ := c["edge_label"].(string)
			if edge == "" {
				edge, _ = c["edge_name"].(string)
			}
			if g, _ := c["group"].(string); g != "" {
				edge = g
			}
			agent, _ := c["agent_name"].(string)
			backends := ""
			if b, ok := c["backends"].([]any); ok {
				parts := make([]string, 0, len(b))
				for _, v := range b {
					if s, ok := v.(string); ok {
						parts = append(parts, s)
					}
				}
				backends = strings.Join(parts, ", ")
				if len(backends) > 40 {
					backends = backends[:37] + "…"
				}
			}
			shadowed, _ := c["shadowed_by"].(string)
			if shadowed == "" {
				shadowed = "-"
			}
			if disabled, _ := c["disabled"].(bool); disabled {
				backends = "désactivé"
			}
			if inactive, _ := c["inactive"].(bool); inactive {
				state, _ := c["state"].(string)
				backends = "inactif"
				if state != "" {
					backends += " (" + state + ")"
				}
			}
			fmt.Printf("%-40s  %-10s  %-20s  %-20s  %-38s  %s\n", host, tls, edge, agent, shadowed, backends)
		}

	case "convert":
		args := parseFlags(os.Args[3:])
		pos := positionalArgs(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(pos) > 0 {
			id = pos[0]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify containers convert <id> [-edge <passerelle>]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var out struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		body := map[string]any{"id": id, "edge": flagValue(args, "-edge", "")}
		if _, err := client.DoJSON("POST", "/api/v1/proxies/from-discovered", body, &out, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "containers convert : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Proxy %s créé pour %s (modifiable avec « goproxify proxy »).\n", out.ID, out.Name)

	case "enable", "disable":
		enabled := sub == "enable"
		args := parseFlags(os.Args[3:])
		pos := positionalArgs(os.Args[3:])
		host := flagValue(args, "-host", "")
		if host == "" && len(pos) > 0 {
			host = pos[0]
		}
		if host == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify containers %s <hôte>\n", sub)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", "/api/v1/discovered-containers/enabled",
			map[string]any{"host": host, "enabled": enabled}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "containers %s : %v\n", sub, err)
			os.Exit(1)
		}
		word := "activée"
		if !enabled {
			word = "désactivée"
		}
		fmt.Printf("Route de %s %s.\n", host, word)

	case "show":
		args := parseFlags(os.Args[3:])
		pos := positionalArgs(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(pos) > 0 {
			id = pos[0]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify containers show <hôte|id> [-edge <passerelle>] [-format compose|portainer|portainer_inline|docker_run|kubernetes]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var d struct {
			Container struct {
				ID         string   `json:"id"`
				Host       string   `json:"host"`
				Backends   []string `json:"backends"`
				Source     string   `json:"source"`
				EdgeName   string   `json:"edge_name"`
				EdgeLabel  string   `json:"edge_label"`
				AgentName  string   `json:"agent_name"`
				ShadowedBy string   `json:"shadowed_by"`
			} `json:"container"`
			Audit struct {
				Score   int      `json:"score"`
				Grade   string   `json:"grade"`
				Missing []string `json:"missing"`
				Checks  []struct {
					Name    string `json:"name"`
					Present bool   `json:"present"`
				} `json:"checks"`
				Added []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"added"`
			} `json:"audit"`
			Labels struct {
				Formats map[string]struct {
					Text string `json:"text"`
				} `json:"formats"`
			} `json:"labels"`
			FixedLabels struct {
				Formats map[string]struct {
					Text string `json:"text"`
				} `json:"formats"`
			} `json:"fixed_labels"`
		}
		q := "?id=" + url.QueryEscape(id) + "&edge=" + url.QueryEscape(flagValue(args, "-edge", ""))
		if _, err := client.DoJSON("GET", "/api/v1/discovered-containers/detail"+q, nil, &d); err != nil {
			fmt.Fprintf(os.Stderr, "containers show : %v\n", err)
			os.Exit(1)
		}
		if format := flagValue(args, "-format", ""); format != "" {
			src := d.FixedLabels.Formats
			if len(src) == 0 {
				src = d.Labels.Formats
			}
			f, ok := src[format]
			if !ok {
				fmt.Fprintf(os.Stderr, "format inconnu %q\n", format)
				os.Exit(1)
			}
			fmt.Print(f.Text)
			return
		}
		c := d.Container
		fmt.Printf("%s  (%s, passerelle %s, Agent %s)\n", c.Host, c.Source, c.EdgeName, c.AgentName)
		fmt.Printf("Backends : %s\n", strings.Join(c.Backends, ", "))
		if c.ShadowedBy != "" {
			fmt.Printf("Remplacé par le proxy : %s\n", c.ShadowedBy)
		}
		fmt.Printf("Sécurité : %d/100 (%s)\n", d.Audit.Score, d.Audit.Grade)
		for _, ck := range d.Audit.Checks {
			mark := "✗"
			if ck.Present {
				mark = "✓"
			}
			fmt.Printf("  %s %s\n", mark, ck.Name)
		}
		if len(d.Audit.Added) == 0 {
			fmt.Println("Rien à ajouter : TLS, WAF et rate limit sont en place.")
			return
		}
		fmt.Println("Labels à ajouter (modèle de sécurité) :")
		for _, l := range d.Audit.Added {
			fmt.Printf("  %s=%s\n", l.Key, l.Value)
		}
		fmt.Println("Tout le jeu corrigé : goproxify containers show <hôte> -format compose")

	case "orphans":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var orphans []struct {
			ProxyID string `json:"proxy_id"`
			Host    string `json:"host"`
			Enabled bool   `json:"enabled"`
			Origin  struct {
				ID   string `json:"id"`
				Edge string `json:"edge"`
			} `json:"origin"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/discovered-containers/orphans", nil, &orphans); err != nil {
			fmt.Fprintf(os.Stderr, "containers orphans : %v\n", err)
			os.Exit(1)
		}
		if len(orphans) == 0 {
			fmt.Println("(aucun proxy orphelin)")
			return
		}
		fmt.Printf("%-40s  %-38s  %-8s  %s\n", "HOST", "PROXY", "ACTIF", "CONTENEUR D'ORIGINE (passerelle)")
		for _, o := range orphans {
			active := "non"
			if o.Enabled {
				active = "oui"
			}
			fmt.Printf("%-40s  %-38s  %-8s  %s (%s)\n", o.Host, o.ProxyID, active, o.Origin.ID, o.Origin.Edge)
		}

	case "help":
		fmt.Print(`Usage: goproxify containers [list] [options]

Affiche les conteneurs découverts par les Agents et les convertit en proxys.
Agrège les résultats de toutes les passerelles connectées.

goproxify containers list [-admin-url …] [-token …]
goproxify containers      [-admin-url …] [-token …]
goproxify containers convert <id> [-edge <passerelle>] [-admin-url …] [-token …]
goproxify containers enable|disable <hôte> [-admin-url …] [-token …]
goproxify containers show <hôte|id> [-edge <passerelle>] [-format compose|portainer|portainer_inline|docker_run|kubernetes]
goproxify containers orphans [-admin-url …] [-token …]

  show affiche le bilan de sécurité (score, TLS / WAF / rate limit) et les labels à ajouter ;
  avec -format, le jeu de labels corrigé prêt à coller (Compose, Portainer, docker run, Kubernetes).
  orphans liste les proxys convertis dont le conteneur d'origine n'est plus annoncé.

  enable / disable réactive ou désactive la route issue des labels d'un hôte (Docker, Portainer, Podman,
  Kubernetes, annuaires) : désactivée, elle ne sert plus de trafic sur aucune passerelle mais reste listée.
  Un proxy configuré s'active avec « goproxify proxy enable ».

  convert crée un proxy modifiable à partir de la route issue des labels (<id> : l'hôte,
  ex. app.example.fr, ou l'id de l'API). Le proxy prend la place de la route des labels
  sur son hôte ; désactivé ou supprimé, il la lui rend.
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande containers inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify containers help")
		os.Exit(1)
	}
}
