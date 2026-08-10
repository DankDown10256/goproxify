// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package crowdsec_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/crowdsec"
	_ "modernc.org/sqlite"
)

func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:crowdsec_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE security_threats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			scenario TEXT NOT NULL DEFAULT '',
			origin TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT 'ban',
			duration TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX idx_threats_ip_scenario ON security_threats (ip, scenario)`,
		`CREATE TABLE security_bans (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL,
			domain TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'native',
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE crowdsec_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '{}')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSyncStartupCreatesBans(t *testing.T) {
	db := setupDB(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/stream" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("startup") != "true" {
			t.Errorf("expected startup=true, got %q", r.URL.Query().Get("startup"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"new": []map[string]string{
				{"value": "203.0.113.50", "scenario": "crowdsecurity/http-probing", "origin": "crowdsec", "type": "ban", "duration": "4h"},
				{"value": "198.51.100.1", "scenario": "crowdsecurity/ssh-bf", "origin": "crowdsec", "type": "ban", "duration": "-1"},
			},
			"deleted": []any{},
		})
	}))
	defer srv.Close()

	b := crowdsec.New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	changed := 0
	b.OnChange = func() { changed++ }
	newCount := 0
	b.OnNewDecision = func(d crowdsec.Decision) { newCount++ }

	if err := b.SaveConfig(crowdsec.Config{Enabled: true, APIURL: srv.URL, APIKey: "k"}); err != nil {
		t.Fatal(err)
	}
	b.SyncNow(context.Background())

	var bans, threats int
	db.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE source='crowdsec'`).Scan(&bans) //nolint:errcheck
	db.QueryRow(`SELECT COUNT(*) FROM security_threats`).Scan(&threats)                   //nolint:errcheck
	if bans != 2 {
		t.Fatalf("bans=%d want 2", bans)
	}
	if threats != 2 {
		t.Fatalf("threats=%d want 2", threats)
	}
	if changed == 0 {
		t.Fatal("OnChange not called")
	}
	if newCount != 2 {
		t.Fatalf("OnNewDecision count=%d want 2", newCount)
	}

	var permanent int
	db.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE source='crowdsec' AND expires_at IS NULL`).Scan(&permanent) //nolint:errcheck
	if permanent != 1 {
		t.Fatalf("permanent bans=%d want 1", permanent)
	}
}

func TestDisableClearsBans(t *testing.T) {
	db := setupDB(t)
	calls := 0
	// Seed existing crowdsec state
	db.Exec(`INSERT INTO security_threats (ip, scenario, origin, type, duration) VALUES ('1.2.3.4','s','o','ban','4h')`) //nolint:errcheck
	db.Exec(`INSERT INTO security_bans (id, ip, reason, source) VALUES ('crowdsec:1.2.3.4','1.2.3.4','s','crowdsec')`)   //nolint:errcheck

	b := crowdsec.New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.OnChange = func() { calls++ }
	if err := b.SaveConfig(crowdsec.Config{Enabled: false, APIURL: "http://example.invalid"}); err != nil {
		t.Fatal(err)
	}
	b.SyncNow(context.Background())

	var bans, threats int
	db.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE source='crowdsec'`).Scan(&bans) //nolint:errcheck
	db.QueryRow(`SELECT COUNT(*) FROM security_threats`).Scan(&threats)                   //nolint:errcheck
	if bans != 0 || threats != 0 {
		t.Fatalf("expected purge, bans=%d threats=%d", bans, threats)
	}
	if calls == 0 {
		t.Fatal("OnChange expected after disable purge")
	}
}
