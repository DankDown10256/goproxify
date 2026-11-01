// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge/bansdb"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type banNode struct {
	name string
	srv  *Server
	http *httptest.Server
}

func newBanNode(t *testing.T, name string) *banNode {
	t.Helper()
	db, err := bansdb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.EdgeConfig{}
	cfg.Identity.NodeName = name
	s := &Server{cfg: cfg, log: edgelog.New("error", "text", ""), bansDB: db, banStore: router.NewBanStore(), profileStore: router.NewIPProfileStore()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+bansGossipPath, s.handleBansGossip)
	mux.HandleFunc("GET /internal/v1/bans", s.handleListBans)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &banNode{name: name, srv: s, http: ts}
}

func (n *banNode) peerOf(others ...*banNode) {
	var peers []proxy.PeerInfo
	for _, o := range others {
		peers = append(peers, proxy.PeerInfo{Name: o.name, Endpoint: o.http.URL, Token: "tok-" + o.name})
	}
	n.srv.peers = proxy.NewPeerRegistry()
	n.srv.peers.Replace(peers)
}

func (n *banNode) blocked(ip string) bool {
	b, _ := n.srv.banStore.CheckBlocked(ip)
	return b
}

func TestLocalBanIsGossipedToPeersAndBlocksThere(t *testing.T) {
	a, b, c := newBanNode(t, "frontal"), newBanNode(t, "backup"), newBanNode(t, "troisieme")
	a.peerOf(b, c)
	exp := time.Now().Add(time.Hour)

	a.srv.gossipBanToPeers(&router.RuntimeBan{ID: "threat-203.0.113.9", IP: "203.0.113.9", Reason: "scan", Source: "threat", ExpiresAt: &exp})

	waitFor(t, "le ban atteint les deux pairs", func() bool { return b.blocked("203.0.113.9") && c.blocked("203.0.113.9") })
	if a.blocked("203.0.113.9") {
		t.Fatal("l'émetteur ne se ré-applique pas le ban (il l'a déjà par son propre chemin)")
	}
}

func TestReceivedBanIsNeverReGossipedAndIsIdempotent(t *testing.T) {
	a, b := newBanNode(t, "frontal"), newBanNode(t, "backup")
	// b a un pair : si le ban reçu de a était réémis, il finirait chez ce pair
	c := newBanNode(t, "troisieme")
	b.peerOf(c)
	exp := time.Now().Add(time.Hour)
	body, _ := json.Marshal([]router.RuntimeBan{{ID: "threat-203.0.113.9", IP: "203.0.113.9", Source: "threat", ExpiresAt: &exp}})
	for i := 0; i < 3; i++ {
		resp, err := http.Post(b.http.URL+bansGossipPath, "application/json", bytes.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusNoContent {
			t.Fatalf("POST: %v %v", err, resp)
		}
		resp.Body.Close()
	}
	if !b.blocked("203.0.113.9") {
		t.Fatal("le ban reçu doit bloquer")
	}
	rows, _ := b.srv.bansDB.ActiveBans()
	if len(rows) != 1 {
		t.Fatalf("un seul enregistrement attendu malgré 3 envois, reçu %d", len(rows))
	}
	time.Sleep(300 * time.Millisecond)
	if c.blocked("203.0.113.9") {
		t.Fatal("un ban reçu d'un pair ne doit jamais être réémis")
	}
	_ = a
}

func TestExpiredAndMalformedPeerBansAreIgnored(t *testing.T) {
	a := newBanNode(t, "frontal")
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	n := a.srv.mergePeerBans([]router.RuntimeBan{
		{ID: "old", IP: "203.0.113.1", ExpiresAt: &past},
		{ID: "", IP: "203.0.113.2", ExpiresAt: &future},
		{ID: "noip", IP: "", ExpiresAt: &future},
		{ID: "ok", IP: "203.0.113.3", ExpiresAt: &future},
	})
	if n != 1 || !a.blocked("203.0.113.3") || a.blocked("203.0.113.1") {
		t.Fatalf("seul le ban valide doit être retenu (n=%d)", n)
	}
	// même IP sous un autre identifiant : pas de doublon
	if n := a.srv.mergePeerBans([]router.RuntimeBan{{ID: "autre-id", IP: "203.0.113.3", ExpiresAt: &future}}); n != 0 {
		t.Fatalf("doublon d'IP retenu (n=%d)", n)
	}
}

func TestBansAreCaughtUpFromPeersWhenGossipWasMissed(t *testing.T) {
	a, b := newBanNode(t, "frontal"), newBanNode(t, "backup")
	exp := time.Now().Add(time.Hour)
	if err := a.srv.bansDB.UpsertBan("threat-203.0.113.7", "203.0.113.7", "", "scan", "threat", &exp); err != nil {
		t.Fatal(err)
	}
	a.srv.reloadBanStore()
	b.peerOf(a)
	p, _ := b.srv.peers.LookupByEndpoint(a.http.URL)
	b.srv.syncBansFromPeer(context.Background(), http.DefaultClient, p)
	if !b.blocked("203.0.113.7") {
		t.Fatal("le tirage périodique doit rattraper un envoi manqué")
	}
}

func TestScopedBanIsNotAdoptedFromPeersItDoesNotTarget(t *testing.T) {
	paris, lyon, nice := newBanNode(t, "paris"), newBanNode(t, "lyon"), newBanNode(t, "nice")
	exp := time.Now().Add(time.Hour)
	for id, scope := range map[string]string{"global": "", "pour-lyon": "lyon", "pour-paris": "paris"} {
		ip := map[string]string{"global": "203.0.113.1", "pour-lyon": "203.0.113.2", "pour-paris": "203.0.113.3"}[id]
		if err := paris.srv.bansDB.UpsertScopedBan(id, ip, "", "test", "native", scope, &exp); err != nil {
			t.Fatal(err)
		}
	}
	paris.srv.reloadBanStore()

	for _, n := range []*banNode{lyon, nice} {
		n.srv.syncBansFromPeer(context.Background(), http.DefaultClient, proxy.PeerInfo{Name: "paris", Endpoint: paris.http.URL, Token: "t"})
	}
	if !lyon.blocked("203.0.113.1") || !lyon.blocked("203.0.113.2") || lyon.blocked("203.0.113.3") {
		t.Errorf("lyon : global %v, pour lyon %v, pour paris %v (attendu true true false)",
			lyon.blocked("203.0.113.1"), lyon.blocked("203.0.113.2"), lyon.blocked("203.0.113.3"))
	}
	if !nice.blocked("203.0.113.1") || nice.blocked("203.0.113.2") || nice.blocked("203.0.113.3") {
		t.Errorf("nice : seul le ban global doit être adopté (%v %v %v)",
			nice.blocked("203.0.113.1"), nice.blocked("203.0.113.2"), nice.blocked("203.0.113.3"))
	}
}
