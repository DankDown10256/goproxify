// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/gdpr"
	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/pairing"

	_ "modernc.org/sqlite"
)

// adminLogs est ce que les commandes locales de l'Admin utilisent pour exporter et geler les logs de son volume de logs
// (ADR 0018), sans passer par le serveur : il peut être éteint.
type adminLogs struct {
	Vault   *edgelogs.Vault
	Cache   *edgecache.Store
	Audit   logexport.Audit
	KeyPath string
	Node    string
}

func adminLogEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// openAdminLogs ouvre le volume de logs de l'Admin en lecture seule, avec sa clé de pseudonymisation (celle de admin.db). La
// clé de signature et le journal d'audit vivent dans state/, que la sauvegarde de l'Admin reprend : sans la clé, les exports déjà
// remis ne se vérifieraient plus avec la clé publique relevée.
func openAdminLogs(cfg *config.AdminConfig, writable bool) (*adminLogs, error) {
	dir := adminLogEnv("GPX_ADMIN_LOG_DIR", filepath.Join(cfg.Storage.BasePath, "edge-logs"))
	db, err := sql.Open("sqlite", cfg.Storage.SQLiteDSN)
	if err != nil {
		return nil, fmt.Errorf("base de l'Admin : %w", err)
	}
	defer db.Close()
	key, err := gdpr.LoadKey(db)
	if err != nil {
		return nil, fmt.Errorf("clé de pseudonymisation de l'Admin : %w", err)
	}
	open := edgelogs.OpenReadOnly
	if writable {
		open = edgelogs.Open
	}
	vault, err := open(dir, key, slog.Default())
	if err != nil {
		return nil, err
	}
	secret := pairing.Secret("GPX_PAIRING_SECRET")
	if secret == "" {
		secret = cfg.Security.JWTSecret
	}
	state := filepath.Join(cfg.Storage.BasePath, "state")
	keyPath := adminLogEnv("GPX_ADMIN_LOG_SIGN_KEY_PATH", filepath.Join(state, "log-sign-key.gpx"))
	node := cfg.HA.NodeID
	if node == "" {
		node = "admin"
	}
	return &adminLogs{
		Vault: vault, Cache: edgecache.New(keyPath, secret), KeyPath: keyPath, Node: node,
		Audit: logexport.Audit{Path: adminLogEnv("GPX_ADMIN_LOG_EXPORT_AUDIT_PATH", filepath.Join(state, "log-export-audit.jsonl"))},
	}, nil
}

// runAdminLogs : commandes locales de l'Admin sur l'historique complet de son volume de logs, utilisables serveur éteint
// ou en marche (ADR 0018) : export signé, gel légal, clé de signature, journal d'audit.
func runAdminLogs() {
	sub := subcommand(os.Args, 3)
	if sub == "verify" {
		runEdgeLogsVerify()
		return
	}
	args := parseFlags(os.Args[min(4, len(os.Args)):])
	cfg, err := config.LoadAdmin(configPath("admin", args))
	if err != nil {
		edgeLogsFail("configuration de l'Admin : %v (option -config)", err)
	}
	local, err := openAdminLogs(cfg, sub == "import")
	if err != nil {
		edgeLogsFail("%v", err)
	}
	defer local.Vault.Close()
	now := time.Now

	switch sub {
	case "export":
		reason := flagValue(args, "-reason", "")
		from, to := flagValue(args, "-from", ""), flagValue(args, "-to", "")
		output := flagValue(args, "-output", "")
		if reason == "" || from == "" || to == "" || output == "" {
			edgeLogsFail("usage: goproxify admin logs export -reason \"motif\" -from <date> -to <date> -output <base> [-node <passerelle>|all] [-kind access|system] [-ip <ip>] [-domain <hôte>] [-format ndjson|csv] [-password-file <fichier> | -no-encrypt]")
		}
		req := logexport.Request{Node: local.Node, Operator: edgeLogsOperator(), Reason: reason, Kind: logstore.Kind(flagValue(args, "-kind", "access")),
			Domain: flagValue(args, "-domain", ""), IP: flagValue(args, "-ip", ""), Format: flagValue(args, "-format", logexport.FormatNDJSON)}
		if req.From, err = parseExportTime(from, false); err != nil {
			edgeLogsFail("%v", err)
		}
		if req.To, err = parseExportTime(to, true); err != nil {
			edgeLogsFail("%v", err)
		}
		if _, clear := args["-no-encrypt"]; clear {
			fmt.Fprintln(os.Stderr, "ATTENTION : sortie en clair, l'IP réelle est lisible par quiconque obtient le fichier.")
		} else if req.Password = exportPassword(args); req.Password == "" {
			edgeLogsFail("mot de passe requis : -password-file <fichier> ou GPX_EXPORT_PASSWORD (ou -no-encrypt pour une sortie en clair)")
		}
		sources, err := local.Vault.Sources(flagValue(args, "-node", "all"))
		if err != nil {
			edgeLogsFail("%v", err)
		}
		priv, err := logexport.LoadOrCreateKey(local.Cache, local.KeyPath)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		res, err := logexport.RunSources(sources, priv, req, output, now)
		if err != nil {
			edgeLogsFail("export : %v", err)
		}
		names := make([]string, len(sources))
		for i, s := range sources {
			names[i] = s.Name
		}
		detail := map[string]any{"nodes": names, "kind": string(req.Kind), "from": res.Manifest.From, "to": res.Manifest.To, "domain": req.Domain, "ip_sha256": res.Manifest.Filters.IPSHA256,
			"rows": res.Manifest.Rows, "encrypted": res.Manifest.Encrypted, "file": res.Manifest.File, "file_sha256": res.Manifest.FileSHA256, "reason": reason}
		if err := local.Audit.Append(now(), req.Operator, "export", detail); err != nil {
			fmt.Fprintf(os.Stderr, "AVERTISSEMENT : journal d'audit non écrit : %v\n", err)
		}
		fmt.Printf("%d ligne(s) exportée(s) de %d passerelle(s)\n  données   : %s\n  manifeste : %s\n  clé de signature : %s\n", res.Manifest.Rows, len(sources), res.DataPath, res.ManifestPath, res.Manifest.KeyID)

	case "hold":
		runAdminLogsHold(local)

	case "import":
		node, manifest, data := flagValue(args, "-node", ""), flagValue(args, "-manifest", ""), flagValue(args, "-data", "")
		if node == "" || manifest == "" || data == "" {
			edgeLogsFail("usage: goproxify admin logs import -node <passerelle> -manifest <fichier> -data <fichier> [-password-file <fichier>] [-pubkey <base64>] [-dry-run]")
		}
		var pinned ed25519.PublicKey
		if k := flagValue(args, "-pubkey", ""); k != "" {
			raw, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				edgeLogsFail("clé publique invalide")
			}
			pinned = raw
		}
		_, dry := args["-dry-run"]
		rep, err := local.Vault.ImportExport(node, manifest, data, exportPassword(args), pinned, dry)
		if rep != nil {
			fmt.Printf("export de %s (type %s) : %d ligne(s) lue(s), %d sans numéro d'origine lisible\n", rep.FromNode, rep.Kind, rep.Read, rep.Skipped)
			if dry {
				fmt.Println("Essai à blanc : rien n'a été écrit.")
			} else {
				fmt.Printf("%d ligne(s) nouvelle(s) rangée(s) dans le store de %s (les lignes déjà reprises ne sont pas rangées deux fois)\n", rep.Added, rep.Node)
			}
		}
		if err != nil {
			edgeLogsFail("reprise : %v", err)
		}
		if !dry {
			detail := map[string]any{"node": node, "kind": rep.Kind, "from_node": rep.FromNode, "read": rep.Read, "added": rep.Added, "manifest": filepath.Base(manifest), "first_ts": rep.FirstTS, "last_ts": rep.LastTS}
			if err := local.Audit.Append(now(), edgeLogsOperator(), "import", detail); err != nil {
				fmt.Fprintf(os.Stderr, "AVERTISSEMENT : journal d'audit non écrit : %v\n", err)
			}
		}

	case "nodes":
		for _, n := range local.Vault.Nodes() {
			fmt.Printf("%s  %s\n", n.ID, n.Name)
		}

	case "key":
		priv, err := logexport.LoadOrCreateKey(local.Cache, local.KeyPath)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("Clé publique de signature : %s\nEmpreinte : %s\n", base64.StdEncoding.EncodeToString(pub), logexport.KeyID(pub))

	case "audit":
		entries, err := local.Audit.Read()
		for _, e := range entries {
			fmt.Printf("%s  %-8s  %-13s  %v\n", e.Ts, e.Operator, e.Op, e.Detail)
		}
		if err != nil {
			edgeLogsFail("%v", err)
		}
		fmt.Printf("%d ligne(s), chaîne intacte\n", len(entries))

	default:
		edgeLogsFail("usage: goproxify admin logs export | verify | hold | nodes | key | audit")
	}
}

func runAdminLogsHold(local *adminLogs) {
	action := subcommand(os.Args, 4)
	args := parseFlags(os.Args[min(5, len(os.Args)):])
	op := edgeLogsOperator()
	switch action {
	case "add":
		reason, from, to := flagValue(args, "-reason", ""), flagValue(args, "-from", ""), flagValue(args, "-to", "")
		if reason == "" || from == "" || to == "" {
			edgeLogsFail("usage: goproxify admin logs hold add -reason \"motif\" -from <date> -to <date> [-ip <ip>] [-domain <hôte>]")
		}
		f, err := parseExportTime(from, false)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		t, err := parseExportTime(to, true)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		h, err := local.Vault.AddHold(logstore.Hold{Reason: reason, From: f, To: t, By: op, IP: flagValue(args, "-ip", ""), Domain: flagValue(args, "-domain", "")})
		if err != nil {
			edgeLogsFail("gel : %v", err)
		}
		detail := map[string]any{"id": h.ID, "from": h.From.Format(time.RFC3339), "to": h.To.Format(time.RFC3339), "reason": reason, "domain": h.Domain}
		if h.IP != "" {
			sum := sha256.Sum256([]byte(h.IP))
			detail["ip_sha256"] = hex.EncodeToString(sum[:])
		}
		_ = local.Audit.Append(time.Now(), op, "hold_add", detail)
		if h.IP != "" || h.Domain != "" {
			fmt.Printf("Gel %s posé : les lignes de %s → %s qui visent %s sont gardées au-delà de la rétention, pour toutes les passerelles (archive held/%s de chaque store, lisibles par l'export seulement).\n", h.ID, h.From.Format(time.RFC3339), h.To.Format(time.RFC3339), holdTarget(h), h.ID)
		} else {
			fmt.Printf("Gel %s posé : aucun fichier de logs recoupant %s → %s ne sera purgé, pour aucune passerelle.\n", h.ID, h.From.Format(time.RFC3339), h.To.Format(time.RFC3339))
		}
	case "release":
		id := flagValue(args, "-id", "")
		if id == "" {
			edgeLogsFail("usage: goproxify admin logs hold release -id <identifiant>")
		}
		if err := local.Vault.RemoveHold(id); err != nil {
			edgeLogsFail("gel : %v", err)
		}
		_ = local.Audit.Append(time.Now(), op, "hold_release", map[string]any{"id": id})
		fmt.Printf("Gel %s levé : la rétention reprend à la prochaine purge.\n", id)
	case "list", "":
		holds, err := local.Vault.Holds()
		if err != nil {
			edgeLogsFail("%v", err)
		}
		if len(holds) == 0 {
			fmt.Println("Aucun gel légal.")
		}
		for _, h := range holds {
			fmt.Printf("%s  %s → %s  %s  posé le %s par %s : %s\n", h.ID, h.From.Format(time.RFC3339), h.To.Format(time.RFC3339), holdTarget(h), h.CreatedAt.Format(time.RFC3339), h.By, h.Reason)
		}
	default:
		edgeLogsFail("usage: goproxify admin logs hold add | release | list")
	}
}
