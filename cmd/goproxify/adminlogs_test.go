// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/gdpr"
	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// La commande locale de l'Admin ouvre le volume de logs avec la clé de pseudonymisation de admin.db et exporte l'IP réelle
// d'une ligne pseudonymisée, serveur éteint.
func TestOpenAdminLogsUsesTheAdminKeyAndExportsRealIPs(t *testing.T) {
	root := t.TempDir()
	cfg := &config.AdminConfig{}
	cfg.Storage.BasePath = root
	cfg.Storage.SQLiteDSN = filepath.Join(root, "admin.db")
	cfg.Security.JWTSecret = "secret-de-test"

	db, err := admindb.Open(cfg.Storage.SQLiteDSN)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gdpr.EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Le serveur a rangé une ligne pseudonymisée dans son volume de logs, puis s'est arrêté.
	vault, err := edgelogs.Open(filepath.Join(root, "edge-logs"), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := vault.Store("node-1", "gw-1")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	e := logstore.Entry{Ts: at, Level: "info", Component: "edge", Domain: "a.example.com", Status: 200, Path: "/x", IP: "203.0.113.0", RealIP: "203.0.113.77", IPTruncated: true}
	if _, err := st.AddShipped(logstore.KindAccess, []logstore.ShippedRow{{Seq: 7, Entry: e}}, 7); err != nil {
		t.Fatal(err)
	}
	vault.Close()

	local, err := openAdminLogs(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Vault.Close()
	sources, err := local.Vault.Sources("gw-1")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := logexport.LoadOrCreateKey(local.Cache, local.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	res, err := logexport.RunSources(sources, priv, logexport.Request{Node: local.Node, Operator: "test", Reason: "motif", Kind: logstore.KindAccess,
		From: at.Add(-time.Hour), To: at.Add(time.Hour), Format: logexport.FormatNDJSON}, filepath.Join(root, "export"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Rows != 1 || res.Manifest.Node != "admin" {
		t.Fatalf("manifeste : %d ligne(s), nœud %q", res.Manifest.Rows, res.Manifest.Node)
	}
	if filepath.Dir(local.KeyPath) != filepath.Join(root, "state") {
		t.Errorf("la clé de signature n'est pas dans state/ : %s", local.KeyPath)
	}
}
