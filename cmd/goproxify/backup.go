// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type cliSnapshot struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ScheduleID string    `json:"schedule_id,omitempty"`
	SizeBytes  int64     `json:"size_bytes"`
	CreatedAt  time.Time `json:"created_at"`
}

func runBackup() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "create":
		args := parseFlags(os.Args[3:])
		target := flagValue(args, "-target", "all")
		output := flagValue(args, "-output", ".")
		if target != "admin" && target != "edge" && target != "all" && target != "full" {
			fmt.Fprintf(os.Stderr, "-target doit être 'admin', 'edge', 'all' ou 'full' (reçu: %q)\n", target)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(output, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "output : %v\n", err)
			os.Exit(1)
		}
		if target == "full" {
			adminConfig := flagValue(args, "-config-admin", "")
			edgeConfig := flagValue(args, "-config-edge", "")
			agentConfig := flagValue(args, "-config-agent", "")
			if err := backupCreateFull(client, output, adminConfig, edgeConfig, agentConfig); err != nil {
				fmt.Fprintf(os.Stderr, "backup full : %v\n", err)
				os.Exit(1)
			}
			return
		}
		if target == "admin" || target == "all" {
			if err := backupCreateAdmin(client, output); err != nil {
				fmt.Fprintf(os.Stderr, "backup admin : %v\n", err)
				os.Exit(1)
			}
		}
		if target == "edge" || target == "all" {
			if err := backupCreateEdge(client, output); err != nil {
				fmt.Fprintf(os.Stderr, "backup edge : %v\n", err)
				os.Exit(1)
			}
		}

	case "restore":
		args := parseFlags(os.Args[3:])
		file := flagValue(args, "-file", "")
		id := flagValue(args, "-id", "")
		_, yes := args["-yes"]
		// Compat : goproxify backup restore <id>
		if file == "" && id == "" && len(os.Args) >= 4 && !strings.HasPrefix(os.Args[3], "-") {
			id = os.Args[3]
			args = parseFlags(os.Args[4:])
			_, yes = args["-yes"]
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if file != "" {
			// Détecter si c'est un full backup (contient des configs)
			if isFullBackup(file) {
				adminConfig := flagValue(args, "-config-admin", "")
				edgeConfig := flagValue(args, "-config-edge", "")
				agentConfig := flagValue(args, "-config-agent", "")
				if err := backupRestoreFull(client, file, yes, adminConfig, edgeConfig, agentConfig); err != nil {
					fmt.Fprintf(os.Stderr, "backup restore : %v\n", err)
					os.Exit(1)
				}
				return
			}
			if err := backupRestoreFile(client, file, yes); err != nil {
				fmt.Fprintf(os.Stderr, "backup restore : %v\n", err)
				os.Exit(1)
			}
			return
		}
		if id != "" {
			if !yes && !confirm(fmt.Sprintf("Restaurer le snapshot %s (overwrite) ?", id)) {
				fmt.Println("annulé")
				return
			}
			var result map[string]any
			if _, err := client.DoJSON("POST", "/api/v1/backups/snapshots/"+id+"/restore", map[string]any{}, &result); err != nil {
				fmt.Fprintf(os.Stderr, "backup restore : %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Snapshot %s restauré : %v\n", id, result)
			return
		}
		fmt.Fprintln(os.Stderr, "usage: goproxify backup restore -file <chemin> [-yes]")
		fmt.Fprintln(os.Stderr, "       goproxify backup restore -id <snapshot-id> [-yes]")
		os.Exit(1)

	case "list":
		args := parseFlags(os.Args[3:])
		target := flagValue(args, "-target", "all")
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if target == "edge" {
			fmt.Println("Les exports edge (.gpx-edge-backup) ne sont pas listés en base — utilisez « backup create -target edge ».")
			return
		}
		var snaps []cliSnapshot
		if _, err := client.DoJSON("GET", "/api/v1/backups/snapshots", nil, &snaps); err != nil {
			fmt.Fprintf(os.Stderr, "backup list : %v\n", err)
			os.Exit(1)
		}
		if len(snaps) == 0 {
			fmt.Println("(aucun snapshot)")
			return
		}
		fmt.Printf("%-36s  %-28s  %10s  %s\n", "ID", "NAME", "SIZE", "CREATED")
		for _, s := range snaps {
			fmt.Printf("%-36s  %-28s  %10s  %s\n",
				s.ID, truncate(s.Name, 28), formatBytes(s.SizeBytes), s.CreatedAt.Format(time.RFC3339))
		}

	case "help", "":
		fmt.Print(`Usage: goproxify backup <sous-commande> [options]

Sous-commandes :
  create   Crée un snapshot / export
  restore  Restaure depuis un fichier ou un snapshot stocké
  list     Liste les snapshots Admin

goproxify backup create [-target admin|edge|all|full] [-output <dir>] [-admin-url …] [-token …]
  -target  admin : snapshot SQLite Admin (.gpx-admin-backup JSON)
           edge  : export table de routage (.gpx-edge-backup JSON)
           all   : les deux (défaut)
           full  : DB + fichiers config JSON (.gpx-full-backup JSON)
  -output           Répertoire de destination (défaut: .)
  -config-admin     Chemin admin.json (full uniquement, défaut: auto-détecté)
  -config-edge      Chemin edge.json  (full uniquement)
  -config-agent     Chemin agent.json (full uniquement)

goproxify backup restore -file <chemin> [-yes] [-config-admin …] [-config-edge …] [-config-agent …]
  Restaure un .gpx-admin-backup ou .gpx-full-backup.
  Pour un full backup, -config-admin/-config-edge/-config-agent indiquent où écrire les configs.

goproxify backup restore -id <snapshot-id> [-yes]
  Restaure un snapshot déjà stocké côté Admin.

goproxify backup list [-admin-url …] [-token …]
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande backup inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify backup help")
		os.Exit(1)
	}
}

func backupCreateAdmin(client *adminClient, output string) error {
	name := "cli-" + time.Now().Format("20060102-150405")
	if _, err := client.DoJSON("POST", "/api/v1/backups/snapshots", map[string]string{"name": name}, nil, 200, 201); err != nil {
		return err
	}
	var snaps []cliSnapshot
	if _, err := client.DoJSON("GET", "/api/v1/backups/snapshots", nil, &snaps); err != nil {
		return err
	}
	var id string
	for _, s := range snaps {
		if s.Name == name {
			id = s.ID
			break
		}
	}
	if id == "" && len(snaps) > 0 {
		// fallback : plus récent
		id = snaps[0].ID
		name = snaps[0].Name
	}
	if id == "" {
		return fmt.Errorf("snapshot créé mais introuvable à la liste")
	}
	data, fname, _, err := client.DoRaw("GET", "/api/v1/backups/snapshots/"+id, nil, "")
	if err != nil {
		return err
	}
	if fname == "" {
		fname = strings.ReplaceAll(name, " ", "-") + ".gpx-admin-backup"
	}
	path := filepath.Join(output, fname)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("Snapshot admin écrit : %s (%s)\n", path, formatBytes(int64(len(data))))
	return nil
}

func backupCreateEdge(client *adminClient, output string) error {
	data, fname, _, err := client.DoRaw("GET", "/api/v1/backups/edge", nil, "")
	if err != nil {
		return err
	}
	if fname == "" {
		fname = "goproxify-routing-" + time.Now().Format("20060102-150405") + ".gpx-edge-backup"
	}
	path := filepath.Join(output, fname)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("Export routage écrit : %s (%s)\n", path, formatBytes(int64(len(data))))
	return nil
}

func backupRestoreFile(client *adminClient, file string, yes bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sumRaw, _, _, err := client.DoRaw("POST", "/api/v1/import/backup/preview", data, "application/json")
	if err != nil {
		return fmt.Errorf("preview : %w", err)
	}
	var sum map[string]any
	_ = json.Unmarshal(sumRaw, &sum)
	fmt.Printf("Prévisualisation %s : %v\n", file, sum)
	if !yes && !confirm("Appliquer cette sauvegarde (overwrite) ?") {
		fmt.Println("annulé")
		return nil
	}
	body := map[string]any{
		"data": json.RawMessage(data),
		"selection": map[string]any{
			"import_users":           true,
			"import_tokens":          true,
			"import_snippets":        true,
			"import_alert_channels":  true,
			"import_alert_rules":     true,
			"on_conflict":            "overwrite",
		},
	}
	var result map[string]any
	if _, err := client.DoJSON("POST", "/api/v1/import/backup/apply", body, &result); err != nil {
		return err
	}
	fmt.Printf("Restauration OK : %v\n", result)
	return nil
}

// ─── Full backup (DB + configs) ───────────────────────────────────────────────

// fullBackup est le format .gpx-full-backup : DB + fichiers config JSON.
type fullBackup struct {
	Version   string                     `json:"version"`
	CreatedAt time.Time                  `json:"created_at"`
	DB        json.RawMessage            `json:"db"`      // contenu .gpx-admin-backup
	Configs   map[string]json.RawMessage `json:"configs"` // "admin", "edge", "agent:<name>"
}

func backupCreateFull(client *adminClient, output, adminCfg, edgeCfg, agentCfg string) error {
	// 1. Export DB via API
	dbData, _, _, err := client.DoRaw("GET", "/api/v1/import/export", nil, "")
	if err != nil {
		return fmt.Errorf("export DB : %w", err)
	}

	// 2. Lire les fichiers config locaux
	configs := make(map[string]json.RawMessage)
	readConfig := func(key, path, defaultPath string) {
		p := path
		if p == "" {
			p = defaultPath
		}
		if p == "" {
			return
		}
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Printf("  avertissement : impossible de lire %s (%s) : %v\n", key, p, err)
			return
		}
		configs[key] = json.RawMessage(data)
		fmt.Printf("  config %s : %s\n", key, p)
	}
	readConfig("admin", adminCfg, defaultConfigPath("admin"))
	readConfig("edge", edgeCfg, defaultConfigPath("edge"))
	if agentCfg != "" {
		readConfig("agent", agentCfg, "")
	}

	fb := fullBackup{
		Version:   "1",
		CreatedAt: time.Now().UTC(),
		DB:        json.RawMessage(dbData),
		Configs:   configs,
	}
	data, err := json.MarshalIndent(fb, "", "  ")
	if err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	fname := filepath.Join(output, "goproxify-full-"+ts+".gpx-full-backup")
	if err := os.WriteFile(fname, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("Full backup écrit : %s (%s)\n", fname, formatBytes(int64(len(data))))
	return nil
}

func isFullBackup(file string) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	var probe struct {
		DB      json.RawMessage            `json:"db"`
		Configs map[string]json.RawMessage `json:"configs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return len(probe.DB) > 0
}

func backupRestoreFull(client *adminClient, file string, yes bool, adminCfg, edgeCfg, agentCfg string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var fb fullBackup
	if err := json.Unmarshal(data, &fb); err != nil {
		return fmt.Errorf("parse full backup : %w", err)
	}

	// Preview DB
	sumRaw, _, _, err := client.DoRaw("POST", "/api/v1/import/backup/preview", fb.DB, "application/json")
	if err != nil {
		return fmt.Errorf("preview DB : %w", err)
	}
	var sum map[string]any
	_ = json.Unmarshal(sumRaw, &sum)
	fmt.Printf("Prévisualisation DB : %v\n", sum)

	// Preview configs
	if len(fb.Configs) > 0 {
		fmt.Println("Configs incluses dans ce backup :")
		for key := range fb.Configs {
			fmt.Printf("  • %s\n", key)
		}
	}

	if !yes && !confirm("Appliquer ce full backup (DB + configs) ?") {
		fmt.Println("annulé")
		return nil
	}

	// Restaurer DB
	body := map[string]any{
		"data": json.RawMessage(fb.DB),
		"selection": map[string]any{
			"import_users":          true,
			"import_tokens":         true,
			"import_snippets":       true,
			"import_alert_channels": true,
			"import_alert_rules":    true,
			"on_conflict":           "overwrite",
		},
	}
	var result map[string]any
	if _, err := client.DoJSON("POST", "/api/v1/import/backup/apply", body, &result); err != nil {
		return fmt.Errorf("restauration DB : %w", err)
	}
	fmt.Printf("DB restaurée : %v\n", result)

	// Restaurer configs localement
	if len(fb.Configs) == 0 {
		return nil
	}
	paths := map[string]string{}
	if p := coalesce(adminCfg, defaultConfigPath("admin")); p != "" {
		paths["admin"] = p
	}
	if p := coalesce(edgeCfg, defaultConfigPath("edge")); p != "" {
		paths["edge"] = p
	}
	if agentCfg != "" {
		paths["agent"] = agentCfg
	}
	for key, cfgData := range fb.Configs {
		path, ok := paths[key]
		if !ok || path == "" {
			fmt.Printf("  config %s : chemin non fourni, ignoré\n", key)
			continue
		}
		if err := atomicWriteFile(path, cfgData); err != nil {
			fmt.Printf("  avertissement : impossible d'écrire %s → %s : %v\n", key, path, err)
			continue
		}
		fmt.Printf("  config %s restaurée → %s\n", key, path)
	}
	return nil
}

func defaultConfigPath(component string) string {
	// Chemins par défaut utilisés par bootstrap
	base := "/etc/goproxify"
	switch component {
	case "admin":
		return filepath.Join(base, "admin.json")
	case "edge":
		return filepath.Join(base, "edge.json")
	case "agent":
		return filepath.Join(base, "agent.json")
	}
	return ""
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func atomicWriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".restore-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, path)
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
