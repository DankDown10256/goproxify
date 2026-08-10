// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

func runImport() {
	sub := subcommand(os.Args, 2)
	if sub == "help" {
		fmt.Print(`Usage: goproxify import [options]

goproxify import -file <chemin> [-format <format>] [-dry-run] [-select <domaines>] [-overwrite]

Options :
  -file       Fichier source (ou répertoire)
  -format     Format source (défaut: détection par extension)
              nginx | traefik-yaml | traefik-toml | caddy | haproxy |
              goproxify | json
  -dry-run    Parse et affiche sans écrire (pas besoin d'Admin)
  -select     Domaines à importer (virgules)
  -overwrite  on_conflict=overwrite (défaut: skip)
  -admin-url  URL Admin (requis sauf -dry-run)
  -token      Token/PAT Admin (requis sauf -dry-run)

Exemples :
  goproxify import -file nginx.conf -dry-run
  goproxify import -file traefik.yml -format traefik-yaml
  goproxify import -file configs/ -select "app.example.fr,api.example.fr"
`)
		return
	}

	args := parseFlags(os.Args[2:])
	file := flagValue(args, "-file", "")
	format := flagValue(args, "-format", "")
	_, dryRun := args["-dry-run"]
	selected := flagValue(args, "-select", "")
	_, overwrite := args["-overwrite"]
	if file == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify import -file <chemin> [-format <format>] [-dry-run]")
		fmt.Fprintln(os.Stderr, "       goproxify import help")
		os.Exit(1)
	}

	paths, err := collectImportFiles(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import : %v\n", err)
		os.Exit(1)
	}
	var all []importer.DetectedProxy
	for _, p := range paths {
		content, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture %s : %v\n", p, err)
			os.Exit(1)
		}
		fmtDetected := format
		if fmtDetected == "" {
			fmtDetected = detectImportFormat(p)
		}
		proxies, err := importer.ParseConfig(fmtDetected, string(content))
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s (%s) : %v\n", p, fmtDetected, err)
			os.Exit(1)
		}
		fmt.Printf("%s [%s] : %d proxy(s)\n", p, fmtDetected, len(proxies))
		all = append(all, proxies...)
	}

	all = filterProxiesBySelect(all, selected)
	if len(all) == 0 {
		fmt.Println("Aucun proxy à importer après filtrage.")
		return
	}

	for _, p := range all {
		tls := ""
		if p.TLS {
			tls = " tls"
		}
		backends := strings.Join(p.Backends, ", ")
		fmt.Printf("  • %s → [%s]%s (%s)\n", p.Host, backends, tls, p.Source)
	}

	if dryRun {
		fmt.Printf("\nDry-run : %d proxy(s) détecté(s), aucune écriture.\n", len(all))
		return
	}

	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		fmt.Fprintln(os.Stderr, "(utilisez -dry-run pour parser sans Admin)")
		os.Exit(1)
	}
	onConflict := "skip"
	if overwrite {
		onConflict = "overwrite"
	}
	body := map[string]any{
		"proxies":     all,
		"on_conflict": onConflict,
	}
	var result map[string]any
	if _, err := client.DoJSON("POST", "/api/v1/import/config/apply", body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "import apply : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nImport OK : %v\n", result)
}

func collectImportFiles(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		out = append(out, filepath.Join(path, name))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("répertoire vide : %s", path)
	}
	return out, nil
}

// detectImportFormat aligne la détection UI (extensions).
func detectImportFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	switch {
	case ext == ".conf" || strings.Contains(base, "nginx"):
		return "nginx"
	case ext == ".yml" || ext == ".yaml":
		return "traefik-yaml"
	case ext == ".toml":
		return "traefik-toml"
	case base == "caddyfile" || ext == ".caddy":
		return "caddy"
	case ext == ".cfg" || strings.Contains(base, "haproxy"):
		return "haproxy"
	case ext == ".json":
		return "json"
	case strings.HasSuffix(base, ".gpx-admin-backup"):
		return "goproxify"
	default:
		return "json"
	}
}

func filterProxiesBySelect(proxies []importer.DetectedProxy, selectCSV string) []importer.DetectedProxy {
	selectCSV = strings.TrimSpace(selectCSV)
	if selectCSV == "" {
		return proxies
	}
	want := map[string]struct{}{}
	for _, h := range strings.Split(selectCSV, ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			want[h] = struct{}{}
		}
	}
	var out []importer.DetectedProxy
	for _, p := range proxies {
		if _, ok := want[strings.ToLower(p.Host)]; ok {
			out = append(out, p)
		}
	}
	return out
}
