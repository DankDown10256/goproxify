// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestBansAddPayloadConvertsTTLToExpiresAt(t *testing.T) {
	now := time.Date(2026, 10, 1, 22, 30, 0, 0, time.FixedZone("CEST", 2*3600))
	for ttl, want := range map[string]string{
		"30m": "2026-10-01T21:00:00Z",
		"1h":  "2026-10-01T21:30:00Z",
		"24h": "2026-10-02T20:30:00Z",
		"7d":  "2026-10-08T20:30:00Z",
	} {
		p, err := bansAddPayload(map[string]string{"-ip": "203.0.113.7", "-ttl": ttl}, now)
		if err != nil {
			t.Fatalf("-ttl %s : %v", ttl, err)
		}
		if p["expires_at"] != want {
			t.Errorf("-ttl %s : expires_at=%v, attendu %s", ttl, p["expires_at"], want)
		}
		if _, ok := p["ttl"]; ok {
			t.Errorf("-ttl %s : le champ ttl, ignoré par l'API, ne doit plus être envoyé", ttl)
		}
	}

	p, err := bansAddPayload(map[string]string{"-ip": "203.0.113.7", "-reason": "scan"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p["expires_at"]; ok || p["reason"] != "scan" {
		t.Errorf("sans -ttl : %v, attendu un ban permanent avec motif", p)
	}

	for _, ttl := range []string{"demain", "0", "0d", "1.5d", "1h-", "-2h"} {
		if _, err := bansAddPayload(map[string]string{"-ip": "203.0.113.7", "-ttl": ttl}, now); err == nil {
			t.Errorf("-ttl %q : erreur attendue", ttl)
		}
	}
}

func TestBansAddTTLReachesTheAPI(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := httptest.NewServer(&api.SecurityHandler{DB: db})
	defer srv.Close()
	c := &adminClient{base: srv.URL, token: "t", client: srv.Client()}

	now := time.Now()
	payload, err := bansAddPayload(map[string]string{"-ip": "203.0.113.7", "-ttl": "1h"}, now)
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	if _, err := c.DoJSON("POST", "/api/v1/security/bans", payload, &res, 200, 201); err != nil {
		t.Fatal(err)
	}
	var exp sql.NullString
	var active bool
	if err := db.QueryRow(`SELECT expires_at, datetime(expires_at) > CURRENT_TIMESTAMP FROM security_bans WHERE id=?`, res["id"]).
		Scan(&exp, &active); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(time.Hour).UTC().Format(time.RFC3339); exp.String != want || !active {
		t.Errorf("expires_at=%v (actif=%v), attendu %s et actif", exp, active, want)
	}
}

func TestTracePath(t *testing.T) {
	if _, err := tracePath(map[string]string{}); err == nil {
		t.Error("-target est requis")
	}
	p, err := tracePath(map[string]string{"-target": "203.0.113.0/24", "-from": "2026-01-01", "-order": "desc"})
	if err != nil {
		t.Fatal(err)
	}
	if p != "/api/v1/security/ip-trace?from=2026-01-01&order=desc&target=203.0.113.0%2F24" {
		t.Errorf("chemin : %s", p)
	}
}

func TestFormatTraceShowsTheUserAgentOfABan(t *testing.T) {
	out := formatTrace(map[string]any{
		"target": "203.0.113.7", "kind": "ip", "summary": map[string]any{},
		"steps": []any{map[string]any{"kind": "ban", "ts": "2026-10-25T10:00:00Z", "ip": "203.0.113.7", "source": "threat", "reason": "threat: ua", "user_agent": "sqlmap/1.7"}},
	})
	if !strings.Contains(out, "User-Agent : sqlmap/1.7") {
		t.Errorf("User-Agent absent :\n%s", out)
	}
}
