// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge"
	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func edgeLogsFail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func edgeLogsOperator() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "inconnu"
}

// parseExportTime lit une date RFC 3339, ou un jour « 2026-10-20 » : début de journée pour une borne de début, fin de
// journée pour une borne de fin (UTC).
func parseExportTime(s string, end bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("date invalide %q (RFC 3339 ou AAAA-MM-JJ)", s)
	}
	if end {
		return d.Add(24*time.Hour - time.Microsecond), nil
	}
	return d, nil
}

func exportPassword(args map[string]string) string {
	if f := flagValue(args, "-password-file", ""); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			edgeLogsFail("lecture du mot de passe : %v", err)
		}
		return strings.TrimRight(string(raw), "\r\n")
	}
	return os.Getenv("GPX_EXPORT_PASSWORD")
}

// runEdgeLogs : commandes locales de la passerelle sur ses logs, utilisables Admin éteint (ADR 0012).
func runEdgeLogs() {
	sub := subcommand(os.Args, 3)
	if sub == "verify" {
		runEdgeLogsVerify()
		return
	}
	args := parseFlags(os.Args[min(4, len(os.Args)):])
	cfg, err := config.LoadEdge(configPath("edge", args))
	if err != nil {
		edgeLogsFail("configuration de la passerelle : %v (option -config)", err)
	}
	local, err := edge.OpenLocalLogs(cfg)
	if err != nil {
		edgeLogsFail("%v", err)
	}
	defer local.Store.Close()
	now := time.Now

	switch sub {
	case "export":
		reason := flagValue(args, "-reason", "")
		from, to := flagValue(args, "-from", ""), flagValue(args, "-to", "")
		output := flagValue(args, "-output", "")
		if reason == "" || from == "" || to == "" || output == "" {
			edgeLogsFail("usage: goproxify edge logs export -reason \"motif\" -from <date> -to <date> -output <base> [-kind access|system] [-ip <ip>] [-domain <hôte>] [-origin <pair>] [-format ndjson|csv] [-password-file <fichier> | -no-encrypt]")
		}
		req := logexport.Request{Node: nodeName(cfg), Operator: edgeLogsOperator(), Reason: reason, Kind: logstore.Kind(flagValue(args, "-kind", "access")),
			Domain: flagValue(args, "-domain", ""), IP: flagValue(args, "-ip", ""), Origin: flagValue(args, "-origin", ""), Format: flagValue(args, "-format", logexport.FormatNDJSON)}
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
		priv, err := logexport.LoadOrCreateKey(local.Cache, local.KeyPath)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		res, err := logexport.Run(local.Store, priv, req, output, now)
		if err != nil {
			edgeLogsFail("export : %v", err)
		}
		detail := map[string]any{"kind": string(req.Kind), "from": res.Manifest.From, "to": res.Manifest.To, "domain": req.Domain, "ip_sha256": res.Manifest.Filters.IPSHA256,
			"rows": res.Manifest.Rows, "encrypted": res.Manifest.Encrypted, "file": res.Manifest.File, "file_sha256": res.Manifest.FileSHA256, "reason": reason, "origin": req.Origin}
		if err := local.Audit.Append(now(), req.Operator, "export", detail); err != nil {
			fmt.Fprintf(os.Stderr, "AVERTISSEMENT : journal d'audit non écrit : %v\n", err)
		}
		fmt.Printf("%d ligne(s) exportée(s)\n  données   : %s\n  manifeste : %s\n  clé de signature : %s\n", res.Manifest.Rows, res.DataPath, res.ManifestPath, res.Manifest.KeyID)

	case "hold":
		runEdgeLogsHold(local, args)

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
		edgeLogsFail("usage: goproxify edge logs export | verify | hold | key | audit")
	}
}

func nodeName(cfg *config.EdgeConfig) string {
	if n := os.Getenv("GPX_NODE_NAME"); n != "" {
		return n
	}
	if cfg.Identity.NodeName != "" {
		return cfg.Identity.NodeName
	}
	h, _ := os.Hostname()
	return h
}

func runEdgeLogsHold(local *edge.LocalLogs, args map[string]string) {
	action := subcommand(os.Args, 4)
	args = parseFlags(os.Args[min(5, len(os.Args)):])
	op := edgeLogsOperator()
	switch action {
	case "add":
		reason, from, to := flagValue(args, "-reason", ""), flagValue(args, "-from", ""), flagValue(args, "-to", "")
		if reason == "" || from == "" || to == "" {
			edgeLogsFail("usage: goproxify edge logs hold add -reason \"motif\" -from <date> -to <date> [-ip <ip>] [-domain <hôte>]")
		}
		f, err := parseExportTime(from, false)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		t, err := parseExportTime(to, true)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		h, err := local.Store.AddHold(logstore.Hold{Reason: reason, From: f, To: t, By: op, IP: flagValue(args, "-ip", ""), Domain: flagValue(args, "-domain", "")})
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
			fmt.Printf("Gel %s posé : les lignes de %s → %s qui visent %s sont gardées au-delà de la rétention (archive held/%s, lisibles par l'export seulement).\n", h.ID, h.From.Format(time.RFC3339), h.To.Format(time.RFC3339), holdTarget(h), h.ID)
		} else {
			fmt.Printf("Gel %s posé : aucun fichier de logs recoupant %s → %s ne sera purgé.\n", h.ID, h.From.Format(time.RFC3339), h.To.Format(time.RFC3339))
		}
	case "release":
		id := flagValue(args, "-id", "")
		if id == "" {
			edgeLogsFail("usage: goproxify edge logs hold release -id <identifiant>")
		}
		if err := local.Store.RemoveHold(id); err != nil {
			edgeLogsFail("gel : %v", err)
		}
		_ = local.Audit.Append(time.Now(), op, "hold_release", map[string]any{"id": id})
		fmt.Printf("Gel %s levé : la rétention reprend à la prochaine purge.\n", id)
	case "list", "":
		holds, err := local.Store.Holds()
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
		edgeLogsFail("usage: goproxify edge logs hold add | release | list")
	}
}

// holdTarget décrit ce qu'un gel vise.
func holdTarget(h logstore.Hold) string {
	var parts []string
	if h.IP != "" {
		parts = append(parts, "ip "+h.IP)
	}
	if h.Domain != "" {
		parts = append(parts, "domaine "+h.Domain)
	}
	if len(parts) == 0 {
		return "fichiers entiers"
	}
	return strings.Join(parts, " + ")
}

// runEdgeLogsVerify vérifie un export sans rien ouvrir de la passerelle : il se fait n'importe où, par qui reçoit le
// fichier, avec la clé publique relevée à la remise.
func runEdgeLogsVerify() {
	args := parseFlags(os.Args[4:])
	manifest := flagValue(args, "-manifest", "")
	if manifest == "" {
		edgeLogsFail("usage: goproxify edge logs verify -manifest <fichier> [-data <fichier>] [-password-file <fichier>] [-pubkey <base64>] [-decrypt-to <fichier>]")
	}
	var pinned ed25519.PublicKey
	if k := flagValue(args, "-pubkey", ""); k != "" {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			edgeLogsFail("clé publique invalide")
		}
		pinned = raw
	}
	var plain *os.File
	if out := flagValue(args, "-decrypt-to", ""); out != "" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			edgeLogsFail("%v", err)
		}
		defer f.Close()
		plain = f
	}
	var w io.Writer
	if plain != nil {
		w = plain
	}
	rep, err := logexport.Verify(manifest, flagValue(args, "-data", ""), exportPassword(args), pinned, w)
	if rep != nil {
		m := rep.Manifest
		fmt.Printf("Manifeste signé : passerelle %s, %d ligne(s) du %s au %s, établi le %s par %s\n  motif : %s\n  clé de signature : %s\n", m.Node, m.Rows, m.From, m.To, m.CreatedAt, m.Operator, m.Reason, m.KeyID)
		if pinned == nil {
			fmt.Println("  La signature prouve que le manifeste est intact ; comparez la clé à celle relevée à la remise (ou passez -pubkey) pour savoir qui l'a signé.")
		}
		if rep.FileChecked {
			fmt.Println("  fichier de données : empreinte conforme")
		}
		if rep.PlainChecked {
			fmt.Println("  contenu déchiffré : empreinte conforme")
		}
	}
	if err != nil {
		edgeLogsFail("VÉRIFICATION ÉCHOUÉE : %v", err)
	}
}
