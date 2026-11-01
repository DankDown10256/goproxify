// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/threat"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestAdminUnbanLiftsBanPostedByTheGateway(t *testing.T) {
	n := newBanNode(t, "frontal")
	const ip = "203.0.113.20"
	if err := n.srv.bansDB.UpsertBan("threat-uuid", ip, "", "threat: seuil auth-fail", "threat", nil); err != nil {
		t.Fatal(err)
	}
	n.srv.reloadBanStore()

	// La liste de l'Admin ne remplace que ses propres bans : sans déban explicite, l'IP resterait bloquée.
	n.srv.applyBans(nil)
	if !n.blocked(ip) {
		t.Fatal("prérequis : un ban posé par la passerelle survit à la liste de l'Admin")
	}

	n.srv.applyUnbans([]edgews.UnbanEntry{{IP: ip}})
	n.srv.applyBans(nil)
	if n.blocked(ip) {
		t.Fatal("le déban Admin doit lever le ban local d'Ephor")
	}
	n.srv.loadBansFromDisk()
	if n.blocked(ip) {
		t.Fatal("le déban doit survivre à un redémarrage")
	}
}

func TestUnbanReplayKeepsBansPostedAfterIt(t *testing.T) {
	n := newBanNode(t, "frontal")
	const ip = "203.0.113.21"
	if err := n.srv.bansDB.UpsertBan("threat-recent", ip, "", "", "threat", nil); err != nil {
		t.Fatal(err)
	}
	n.srv.reloadBanStore()

	past := time.Now().Add(-time.Hour)
	n.srv.applyUnbans([]edgews.UnbanEntry{{IP: ip, At: &past}})
	if !n.blocked(ip) {
		t.Fatal("un ban posé après le déban rejoué doit rester")
	}
}

func TestWhitelistOverridesExistingAutomaticBans(t *testing.T) {
	n := newBanNode(t, "frontal")
	const ephorIP, pluginIP, manualIP = "203.0.113.31", "203.0.113.30", "203.0.113.32"
	for _, b := range []struct{ id, ip, src string }{
		{"plugin", pluginIP, edgews.PluginBanSourcePrefix + "demo"},
		{"threat-" + ephorIP, ephorIP, "threat"},
		{"manuel", manualIP, "admin"},
	} {
		if err := n.srv.bansDB.UpsertBan(b.id, b.ip, "", "", b.src, nil); err != nil {
			t.Fatal(err)
		}
	}
	n.srv.reloadBanStore()
	if !n.blocked(pluginIP) || !n.blocked(ephorIP) || !n.blocked(manualIP) {
		t.Fatal("prérequis : les trois IPs sont bannies")
	}

	n.srv.threatEngine = threat.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	n.srv.threatEngine.UpdateConfig(threat.Config{Whitelist: threat.Whitelist{IPs: []string{"203.0.113.31/32", "203.0.113.30/32", "203.0.113.32/32"}}})
	n.srv.reloadBanStore()

	if n.blocked(pluginIP) {
		t.Fatal("la liste blanche d'Ephor doit lever un ban de plugin déjà posé")
	}
	if n.blocked(ephorIP) {
		t.Fatal("la liste blanche Ephor doit lever un ban Ephor déjà posé")
	}
	if !n.blocked(manualIP) {
		t.Fatal("un ban manuel reste appliqué même si l'IP est en liste blanche d'Ephor")
	}
}

func TestPeerSyncDoesNotResurrectAnUnbannedIP(t *testing.T) {
	a, b := newBanNode(t, "frontal"), newBanNode(t, "backup")
	const ip = "203.0.113.50"
	if err := a.srv.bansDB.UpsertBan("threat-a", ip, "", "", "threat", nil); err != nil {
		t.Fatal(err)
	}
	// b a reçu le déban de l'Admin, a non (Admin injoignable pour lui).
	b.srv.applyUnbans([]edgews.UnbanEntry{{IP: ip}})
	b.peerOf(a)
	p, _ := b.srv.peers.LookupByEndpoint(a.http.URL)
	b.srv.syncBansFromPeer(context.Background(), http.DefaultClient, p)
	if b.blocked(ip) {
		t.Fatal("un ban antérieur au déban ne doit pas revenir par un pair")
	}

	// Un ban reposé par le pair après le déban, lui, se propage.
	time.Sleep(1100 * time.Millisecond)
	if err := a.srv.bansDB.UpsertBan("threat-a2", ip, "", "", "threat", nil); err != nil {
		t.Fatal(err)
	}
	b.srv.syncBansFromPeer(context.Background(), http.DefaultClient, p)
	if !b.blocked(ip) {
		t.Fatal("un nouveau ban après le déban doit être rattrapé")
	}
}
