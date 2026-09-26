// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

type pushRecorder struct{ pushed []string }

func (p *pushRecorder) PushPortal(_ context.Context, edge string, _ any) { p.pushed = append(p.pushed, edge) }

func TestPortalAccessRequestLifecycle(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "access.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO portal_destinations (id, edge_name, kind, name) VALUES ('d1','edge-a','ssh','srv-db')`)
	rec := &pushRecorder{}
	h := &PortalHandler{DB: db, Pusher: rec}

	InsertPortalAccessRequest(db, "edge-a", "u1", "alice", "d1", "migration", 30)
	InsertPortalAccessRequest(db, "edge-a", "u1", "alice", "d1", "doublon", 30)

	list := func(status string) []PortalAccessRequest {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/portal/access-requests?edge=edge-a&status="+status, nil))
		var out struct {
			Requests []PortalAccessRequest `json:"requests"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("list: %v %s", err, w.Body.String())
		}
		return out.Requests
	}
	pending := list("pending")
	if len(pending) != 1 || pending[0].TargetName != "srv-db" || pending[0].Reason != "migration" {
		t.Fatalf("pending: %+v", pending)
	}
	id := pending[0].ID
	if g := listActiveGrants(db, []string{"edge-a"}); len(g) != 0 {
		t.Fatalf("aucun accès avant approbation: %+v", g)
	}

	post := func(path, body string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return w.Code
	}
	if c := post("/api/v1/portal/access-requests/"+id+"/approve", `{"duration_min":45}`); c != http.StatusNoContent {
		t.Fatalf("approve: %d", c)
	}
	grants := listActiveGrants(db, []string{"edge-a"})
	if len(grants) != 1 || grants[0].UserID != "u1" || grants[0].TargetID != "d1" {
		t.Fatalf("grants: %+v", grants)
	}
	exp, _ := time.Parse(time.RFC3339, grants[0].ExpiresAt)
	if d := time.Until(exp); d < 44*time.Minute || d > 46*time.Minute {
		t.Fatalf("expiration attendue dans 45 min, reçu %v", d)
	}
	if len(rec.pushed) != 1 || rec.pushed[0] != "edge-a" {
		t.Fatalf("push attendu vers edge-a: %v", rec.pushed)
	}
	if c := post("/api/v1/portal/access-requests/"+id+"/approve", `{}`); c != http.StatusConflict {
		t.Fatalf("double approbation: %d", c)
	}
	if c := post("/api/v1/portal/access-requests/"+id+"/revoke", ``); c != http.StatusNoContent {
		t.Fatalf("revoke: %d", c)
	}
	if g := listActiveGrants(db, []string{"edge-a"}); len(g) != 0 {
		t.Fatalf("accès révoqué encore actif: %+v", g)
	}

	InsertPortalAccessRequest(db, "edge-a", "u2", "bob", "d1", "audit", 10)
	var id2 string
	_ = db.QueryRow(`SELECT id FROM portal_access_requests WHERE user_id='u2'`).Scan(&id2)
	if c := post("/api/v1/portal/access-requests/"+id2+"/deny", ``); c != http.StatusNoContent {
		t.Fatalf("deny: %d", c)
	}
	if len(rec.pushed) != 2 {
		t.Fatalf("un refus ne pousse rien: %v", rec.pushed)
	}
	if c := post("/api/v1/portal/access-requests/inconnu/deny", ``); c != http.StatusNotFound {
		t.Fatalf("inconnu: %d", c)
	}
}

func TestPortalAccessGrantExpires(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "access-exp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	_, _ = db.Exec(`INSERT INTO portal_access_requests (id, edge_name, user_id, target_id, status, created_at, expires_at)
		VALUES ('x','edge-a','u1','d1','approved','2026-01-01T00:00:00Z',?)`, past)
	if g := listActiveGrants(db, []string{"edge-a"}); len(g) != 0 {
		t.Fatalf("accès expiré exclu attendu: %+v", g)
	}
}

func TestPortalAccessRequestNewnessAndRecipients(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "recipients.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !InsertPortalAccessRequest(db, "edge-a", "u1", "alice", "d1", "x", 30) {
		t.Fatal("première demande: nouvelle attendue")
	}
	if InsertPortalAccessRequest(db, "edge-a", "u1", "alice", "d1", "x", 30) {
		t.Fatal("doublon en attente: pas de nouvelle demande, donc pas de second email")
	}
	for _, u := range [][3]string{{"1", "admin@x.fr", "admin"}, {"2", "root@x.fr", "superadmin"}, {"3", "user@x.fr", "user"}, {"4", "pas-un-mail", "admin"}} {
		_, _ = db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?,?,?,?)`, u[0], u[1], "h", u[2])
	}
	got := PortalAccessRecipients(db)
	if len(got) != 2 || got[0] != "admin@x.fr" || got[1] != "root@x.fr" {
		t.Fatalf("destinataires: %v", got)
	}
}
