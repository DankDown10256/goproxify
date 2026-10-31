// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func newConfigGateway(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_SERVER_CONFIG_PATH", filepath.Join(dir, "server-config.gpx"))
	t.Setenv("GPX_PORTAL_TEMPLATES_PATH", filepath.Join(dir, "portal-templates.gpx"))
	log := edgelog.New("error", "text", "")
	return &Server{
		cfg:    &config.EdgeConfig{},
		log:    log,
		cache:  edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
		portal: portal.NewService(log.Logger()),
	}
}

// Les timeouts poussés survivent à un redémarrage sans Admin, et un push partiel n'efface pas
// les autres valeurs.
func TestServerConfigSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newConfigGateway(t, dir)
	s.applyServerConfig(pushedServerConfig{ReadSeconds: 99, IdleSeconds: 200})
	s.applyServerConfig(pushedServerConfig{WriteSeconds: 77})

	raw, err := os.ReadFile(filepath.Join(dir, "server-config.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("read_seconds")) {
		t.Fatal("copie locale de la config serveur écrite en clair")
	}

	restarted := newConfigGateway(t, dir)
	restarted.loadServerConfigFromDisk()
	got := restarted.cfg.Timeouts
	if got.ReadSeconds != 99 || got.IdleSeconds != 200 || got.WriteSeconds != 77 {
		t.Fatalf("timeouts après redémarrage sans Admin : %+v", got)
	}
}

// Un timeout non poussé garde la valeur de edge.json ; edge.json lui-même n'est jamais réécrit
// (sa sérialisation JSON perdait l'identité et les ports).
func TestServerConfigKeepsBootstrapValuesAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")
	orig := `{"identity":{"node_name":"edge-1","token_id":"tok-1"},"network":{"http_port":8080},"timeouts":{"read_header_seconds":10}}`
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadEdge(path)
	if err != nil {
		t.Fatal(err)
	}
	s := newConfigGateway(t, dir)
	s.cfg = cfg
	s.applyServerConfig(pushedServerConfig{ReadSeconds: 99})

	if cfg.Timeouts.ReadHeaderSeconds != 10 {
		t.Fatalf("read_header_seconds écrasé : %d", cfg.Timeouts.ReadHeaderSeconds)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != orig {
		t.Fatalf("edge.json réécrit : %s", after)
	}
}

func TestLoadServerConfigWithoutFile(t *testing.T) {
	s := newConfigGateway(t, t.TempDir())
	s.loadServerConfigFromDisk()
	if s.cfg.Timeouts.ReadSeconds != 0 {
		t.Fatalf("sans copie locale : %+v", s.cfg.Timeouts)
	}
}

func TestPortalTemplatesSurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newConfigGateway(t, dir)
	s.applyPortalTemplates([]portal.PageTemplate{{Key: portal.PageLogin, Body: "<section>connexion-perso</section>"}})

	raw, err := os.ReadFile(filepath.Join(dir, "portal-templates.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("connexion-perso")) {
		t.Fatal("copie locale des modèles écrite en clair")
	}

	restarted := newConfigGateway(t, dir)
	restarted.loadPortalTemplatesFromDisk()
	if body := restarted.portal.PageTemplatesSnapshot()[portal.PageLogin]; body != "<section>connexion-perso</section>" {
		t.Fatalf("modèle après redémarrage sans Admin : %q", body)
	}
}

func newPeersGateway(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_GATEWAY_PEERS_PATH", filepath.Join(dir, "gateway-peers.gpx"))
	s := newConfigGateway(t, dir)
	s.cfg.Identity.NodeName = "edge-1"
	s.peers = proxy.NewPeerRegistry()
	return s
}

func TestGatewayPeersSurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newPeersGateway(t, dir)
	s.applyGatewayPeers([]proxy.PeerInfo{
		{Name: "edge-1", Endpoint: "http://10.0.0.1:8000", Token: "moi"},
		{Name: "edge-2", Endpoint: "http://10.0.0.2:8000", Token: "jeton-secret"},
	})
	if len(s.peers.All()) != 1 {
		t.Fatalf("la passerelle s'est inscrite elle-même : %+v", s.peers.All())
	}

	raw, err := os.ReadFile(filepath.Join(dir, "gateway-peers.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("jeton-secret")) {
		t.Fatal("jeton d'un pair écrit en clair")
	}

	restarted := newPeersGateway(t, dir)
	restarted.loadGatewayPeersFromDisk()
	got := restarted.peers.All()
	if len(got) != 1 || got[0].Name != "edge-2" || got[0].Token != "jeton-secret" {
		t.Fatalf("pairs après redémarrage sans Admin : %+v", got)
	}
}

func TestLoadGatewayPeersWithoutFile(t *testing.T) {
	s := newPeersGateway(t, t.TempDir())
	s.loadGatewayPeersFromDisk()
	if got := s.peers.All(); len(got) != 0 {
		t.Fatalf("sans copie locale : %+v", got)
	}
}

func newHAGateway(t *testing.T, name, haKey string) *Server {
	t.Helper()
	dir := t.TempDir()
	s := newConfigGateway(t, dir)
	s.cfg.Identity.NodeName = name
	s.wsHub = edgews.NewHub("", s.log.Logger())
	s.wsHub.SetHMACStore(edgews.NewAgentHMACStore(filepath.Join(dir, "hmac.json")))
	if err := s.portal.ApplyConfig(portal.Config{HAGroup: "g", HAKey: haKey, HAMembers: []string{"edge-a", "edge-b"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

// Un Agent approuvé sur edge-a est accepté par edge-b après un échange via les routes internes.
func TestAgentReplicaBetweenGroupMembers(t *testing.T) {
	a := newHAGateway(t, "edge-a", "cle")
	b := newHAGateway(t, "edge-b", "cle")
	_ = a.wsHub.HMACStore().Set("agent-1", "hmac-secret")

	rec := httptest.NewRecorder()
	a.handleAgentReplicaExport(rec, httptest.NewRequest(http.MethodGet, agentReplicaPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export : %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("hmac-secret")) {
		t.Fatal("HMAC en clair dans l'échange")
	}

	in := httptest.NewRecorder()
	b.handleAgentReplicaImport(in, httptest.NewRequest(http.MethodPost, agentReplicaPath, bytes.NewReader(rec.Body.Bytes())))
	if in.Code != http.StatusNoContent {
		t.Fatalf("import : %d", in.Code)
	}
	if v, _ := b.wsHub.HMACStore().Get("agent-1"); v != "hmac-secret" {
		t.Fatalf("edge-b n'a pas reçu le HMAC : %q", v)
	}
}

// Une passerelle d'un autre groupe (autre clé) ne peut ni lire ni écrire les HMAC.
func TestAgentReplicaRejectsOtherGroup(t *testing.T) {
	a := newHAGateway(t, "edge-a", "cle")
	stranger := newHAGateway(t, "edge-x", "autre-cle")
	_ = a.wsHub.HMACStore().Set("agent-1", "hmac-secret")

	rec := httptest.NewRecorder()
	a.handleAgentReplicaExport(rec, httptest.NewRequest(http.MethodGet, agentReplicaPath, nil))
	in := httptest.NewRecorder()
	stranger.handleAgentReplicaImport(in, httptest.NewRequest(http.MethodPost, agentReplicaPath, bytes.NewReader(rec.Body.Bytes())))
	if in.Code != http.StatusBadRequest {
		t.Fatalf("un autre groupe doit être refusé : %d", in.Code)
	}
	if _, ok := stranger.wsHub.HMACStore().Get("agent-1"); ok {
		t.Fatal("HMAC reçu d'un autre groupe")
	}
}

// Sans groupe HA, la route n'expose rien.
func TestAgentReplicaWithoutGroup(t *testing.T) {
	s := newConfigGateway(t, t.TempDir())
	s.wsHub = edgews.NewHub("", s.log.Logger())
	rec := httptest.NewRecorder()
	s.handleAgentReplicaExport(rec, httptest.NewRequest(http.MethodGet, agentReplicaPath, nil))
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("sans groupe : %d %q", rec.Code, rec.Body.String())
	}
}

// L'Agent est informé des seuls autres membres du groupe HA : ni lui-même, ni une passerelle étrangère.
func TestGroupEdgeEndpoints(t *testing.T) {
	a := newHAGateway(t, "edge-a", "cle")
	a.peers = proxy.NewPeerRegistry()
	a.peers.Replace([]proxy.PeerInfo{
		{Name: "edge-a", Endpoint: "http://10.0.0.1:8000", Token: "t"},
		{Name: "edge-b", Endpoint: "http://10.0.0.2:8000", Token: "t"},
		{Name: "edge-ext", Endpoint: "http://10.0.0.9:8000", Token: "t"},
	})
	got := a.groupEdgeEndpoints()
	if len(got) != 1 || got[0] != "http://10.0.0.2:8000" {
		t.Fatalf("membres annoncés : %v", got)
	}

	alone := newConfigGateway(t, t.TempDir())
	alone.peers = proxy.NewPeerRegistry()
	alone.peers.Replace([]proxy.PeerInfo{{Name: "edge-b", Endpoint: "http://10.0.0.2:8000", Token: "t"}})
	if got := alone.groupEdgeEndpoints(); len(got) != 0 {
		t.Fatalf("hors groupe, rien à annoncer : %v", got)
	}
}
