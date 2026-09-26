// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
)

func TestMergePushPreservingFileProxies(t *testing.T) {
	root := t.TempDir()
	st := proxystore.New(root)
	cfg, _ := json.Marshal(map[string]any{
		"id": "file-1", "host": "file.example.fr", "type": "http",
		"backends": []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lb":       "round_robin",
	})
	if err := st.WriteProd(&proxystore.Envelope{
		SchemaVersion: 1, ID: "file-1", Host: "file.example.fr", Enabled: true, Config: cfg,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{table: &router.Table{}, proxyStore: st}
	s.table.Upsert(&router.Route{ID: "docker:abc", Host: "docker.local", Type: router.RouteHTTP})
	s.table.Upsert(&router.Route{ID: "file-1", Host: "stale.example.fr", Type: router.RouteHTTP})

	incoming := []*router.Route{
		{ID: "file-1", Host: "admin-copy.example.fr", Type: router.RouteHTTP},
		{ID: "manual-admin", Host: "admin.example.fr", Type: router.RouteHTTP},
	}
	merged := s.mergePushPreservingFileProxies(incoming)
	hosts := map[string]string{}
	for _, r := range merged {
		hosts[r.ID] = r.Host
	}
	if hosts["file-1"] != "file.example.fr" {
		t.Fatalf("file route should win from disk, got %q", hosts["file-1"])
	}
	if hosts["manual-admin"] != "admin.example.fr" {
		t.Fatalf("admin route missing")
	}
	if hosts["docker:abc"] != "docker.local" {
		t.Fatalf("agent route missing")
	}
}

func TestProxyAPICreateDryRunPromote(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_DATA_PATH", root)

	tokDir := t.TempDir()
	ts, err := edgetokens.Open(filepath.Join(tokDir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	token := "test-token-proxy-api"
	if err := ts.Bootstrap("admin-test", token, edgetokens.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		cfg:           &config.EdgeConfig{},
		table:         &router.Table{},
		tokenStore:    ts,
		log:           edgelog.New("error", "text", ""),
		certStore:     edgetls.NewCertStore(),
		snippetStore:  router.NewSnippetStore(),
		providerStore: router.NewAuthProviderStore(),
		cache:         edgecache.New(filepath.Join(root, "edge-cache.gpx"), "test"),
	}
	s.initProxyStore()

	cfgJSON, _ := json.Marshal(map[string]any{
		"host": "api.example.fr", "type": "http",
		"backends": []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lb":       "round_robin",
	})
	body, _ := json.Marshal(map[string]any{"config": json.RawMessage(cfgJSON)})
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/proxies/revisions", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleCreateProxyRevision(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created proxystore.Envelope
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Revision == "" || created.ID == "" {
		t.Fatalf("missing ids: %+v", created)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.SetPathValue("id", created.ID)
	req2.SetPathValue("rev", created.Revision)
	rr2 := httptest.NewRecorder()
	s.handleDryRunProxyRevision(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("dry-run status=%d body=%s", rr2.Code, rr2.Body.String())
	}

	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	req3.SetPathValue("id", created.ID)
	req3.SetPathValue("rev", created.Revision)
	rr3 := httptest.NewRecorder()
	s.handlePromoteProxyRevision(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("promote status=%d body=%s", rr3.Code, rr3.Body.String())
	}

	route, ok := s.table.ByHost("api.example.fr")
	if !ok || route.ID != created.ID {
		t.Fatalf("route not in memory: ok=%v route=%v", ok, route)
	}
	entries, err := os.ReadDir(filepath.Join(root, "proxies"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("prod files=%d", len(entries))
	}
}

func TestLoadProductionProxies(t *testing.T) {
	root := t.TempDir()
	st := proxystore.New(root)
	cfg, _ := json.Marshal(map[string]any{
		"id": "file-1", "host": "boot.example.fr", "type": "http",
		"backends": []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lb":       "round_robin",
	})
	if err := st.WriteProd(&proxystore.Envelope{
		SchemaVersion: 1, ID: "file-1", Host: "boot.example.fr", Enabled: true, Config: cfg,
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		table:      &router.Table{},
		proxyStore: st,
		log:        edgelog.New("error", "text", ""),
	}
	s.loadProductionProxies()
	if _, ok := s.table.ByHost("boot.example.fr"); !ok {
		t.Fatal("expected route loaded at boot")
	}
}
