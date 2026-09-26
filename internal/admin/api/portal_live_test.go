// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

type fakeLive struct {
	sessions map[string][]portal.LiveSession
	killed   []string
}

func (f *fakeLive) PushPortal(context.Context, string, any) {}
func (f *fakeLive) PortalLive(edge string) []portal.LiveSession {
	return f.sessions[edge]
}
func (f *fakeLive) KillPortalSession(edge, id string) bool {
	for _, s := range f.sessions[edge] {
		if s.ID == id {
			f.killed = append(f.killed, id)
			return true
		}
	}
	return false
}

func TestPortalLiveSessionsListAndTerminate(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal-live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f := &fakeLive{sessions: map[string][]portal.LiveSession{
		"edge-a": {{ID: "s1", Actor: "alice", TargetID: "srv"}},
	}}
	h := &PortalHandler{DB: db, Pusher: f}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/portal/sessions?edge=edge-a", nil))
	var out struct {
		Sessions []portal.LiveSession `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Sessions) != 1 || out.Sessions[0].Actor != "alice" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/portal/sessions?edge=edge-b", nil))
	if rec.Code != http.StatusOK || rec.Body.String() == "" {
		t.Fatalf("edge vide: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/portal/sessions/s1?edge=edge-a", nil))
	if rec.Code != http.StatusNoContent || len(f.killed) != 1 {
		t.Fatalf("delete: %d killed=%v", rec.Code, f.killed)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/portal/sessions/zzz?edge=edge-a", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("inconnue: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/portal/sessions", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("edge manquant: %d", rec.Code)
	}
}
