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
		if target != "admin" && target != "core" && target != "all" {
			fmt.Fprintf(os.Stderr, "-target doit être 'admin', 'core' ou 'all' (reçu: %q)\n", target)
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
		if target == "admin" || target == "all" {
			if err := backupCreateAdmin(client, output); err != nil {
				fmt.Fprintf(os.Stderr, "backup admin : %v\n", err)
				os.Exit(1)
			}
		}
		if target == "core" || target == "all" {
			if err := backupCreateCore(client, output); err != nil {
				fmt.Fprintf(os.Stderr, "backup core : %v\n", err)
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
		if target == "core" {
			fmt.Println("Les exports core (.gpx-core-backup) ne sont pas listés en base — utilisez « backup create -target core ».")
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

goproxify backup create [-target admin|core|all] [-output <dir>] [-admin-url …] [-token …]
  -target  admin : snapshot SQLite Admin (.gpx-admin-backup JSON)
           core  : export table de routage (.gpx-core-backup JSON)
           all   : les deux (défaut)
  -output  Répertoire de destination (défaut: .)

goproxify backup restore -file <chemin> [-yes]
  Restaure un fichier .gpx-admin-backup via l'API import (preview + apply).

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

func backupCreateCore(client *adminClient, output string) error {
	data, fname, _, err := client.DoRaw("GET", "/api/v1/backups/core", nil, "")
	if err != nil {
		return err
	}
	if fname == "" {
		fname = "goproxify-routing-" + time.Now().Format("20060102-150405") + ".gpx-core-backup"
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
