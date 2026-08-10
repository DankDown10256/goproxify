// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func TestNodeAutoAcceptDeclaredAndBootstrap(t *testing.T) {
	db, err := sql.Open("sqlite", "file:auto_accept_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`CREATE TABLE declared_nodes (
		id TEXT PRIMARY KEY, role TEXT, name TEXT, region TEXT DEFAULT '',
		environment TEXT DEFAULT '', config TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE bootstrap_tickets (
		token TEXT PRIMARY KEY, host_name TEXT, core_endpoint TEXT,
		payload TEXT, expires_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}

	if api.NodeAutoAccept(db, "agent-x") {
		t.Fatal("expected no auto-accept before declare")
	}

	_, err = db.Exec(`INSERT INTO declared_nodes(id, role, name, config) VALUES('dn1','agent','agent-x','{"auto_accept":true}')`)
	if err != nil {
		t.Fatal(err)
	}
	if !api.DeclaredAutoAccept(db, "agent-x") {
		t.Fatal("expected declared auto-accept")
	}
	if !api.NodeAutoAccept(db, "agent-x") {
		t.Fatal("expected NodeAutoAccept via declared")
	}

	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	payload := `{"auto_accept":true,"node_names":["agent-y","core-1"]}`
	_, err = db.Exec(`INSERT INTO bootstrap_tickets(token, host_name, core_endpoint, payload, expires_at)
		VALUES('tok1','H','http://c:8000',?,?)`, payload, exp)
	if err != nil {
		t.Fatal(err)
	}
	if !api.BootstrapTicketAutoAccept(db, "agent-y") {
		t.Fatal("expected bootstrap auto-accept for agent-y")
	}
	if api.BootstrapTicketAutoAccept(db, "agent-z") {
		t.Fatal("agent-z should not match")
	}
}

func TestLinkBootstrapToDeclared(t *testing.T) {
	db, err := sql.Open("sqlite", "file:link_boot_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, _ = db.Exec(`CREATE TABLE declared_nodes (
		id TEXT PRIMARY KEY, role TEXT, name TEXT, region TEXT DEFAULT '',
		environment TEXT DEFAULT '', config TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	_, _ = db.Exec(`INSERT INTO declared_nodes(id, role, name, config) VALUES('dn1','agent','ag1','{"docker":true}')`)

	api.LinkBootstrapToDeclared(db, "abc123token", []string{"ag1"})

	var cfg string
	if err := db.QueryRow(`SELECT config FROM declared_nodes WHERE name='ag1'`).Scan(&cfg); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		t.Fatal(err)
	}
	if m["auto_accept"] != true || m["bootstrap_token"] != "abc123token" {
		t.Fatalf("config not linked: %s", cfg)
	}
	if !api.DeclaredAutoAccept(db, "ag1") {
		t.Fatal("expected auto_accept after link")
	}
}

func TestBootstrapCreateLinksDeclared(t *testing.T) {
	db, err := sql.Open("sqlite", "file:boot_link_create?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, _ = db.Exec(`CREATE TABLE declared_nodes (
		id TEXT PRIMARY KEY, role TEXT, name TEXT, region TEXT DEFAULT '',
		environment TEXT DEFAULT '', config TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	_, _ = db.Exec(`INSERT INTO declared_nodes(id, role, name, config) VALUES('dn1','agent','my-agent','{}')`)

	h := &api.BootstrapHandler{
		DB: db,
		ResolvePublicURL: func(r *http.Request) string {
			return "https://admin.example"
		},
	}
	body := `{"host_name":"H","auto_accept":true,"node_names":["my-agent"],"payload":{"compose_text":"x: 1\n"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap-tickets", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	tok, _ := created["token"].(string)
	if tok == "" {
		t.Fatal("no token")
	}
	if !api.DeclaredAutoAccept(db, "my-agent") {
		t.Fatal("declared should be linked with auto_accept")
	}
	var cfg string
	_ = db.QueryRow(`SELECT config FROM declared_nodes WHERE name='my-agent'`).Scan(&cfg)
	if !strings.Contains(cfg, tok) {
		t.Fatalf("bootstrap_token missing in %s", cfg)
	}
}
