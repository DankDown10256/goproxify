// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// vaultCount compte les lignes d'accès dont le chemin contient prefix, dans le store de la passerelle edgeID du volume de
// logs de l'Admin.
func (a *adminSide) vaultCount(t *testing.T, edgeID, prefix string) int {
	t.Helper()
	st, err := a.vault.Store(edgeID, "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := st.Search(t.Context(), logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Path: prefix, Limit: 5000})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Rows)
}

// L'Admin range toutes les lignes de la passerelle dans son volume de logs, ordinaires comprises ; sa table logs ne garde
// que les événements de sécurité. Rien ne se perd ni ne se double à travers une coupure.
func TestEveryLineReachesTheAdminVaultAndOnlySecurityEventsTheTable(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	gw.addAccess("ordinaire", 300, false)
	gw.addAccess("attaque", 5, true)
	gw.addAccess("ordinaire2", 100, false)
	admin.start(t, gw.url)
	waitUntil(t, "les 405 lignes dans le volume de logs", func() bool { return admin.vaultCount(t, streamEdgeID, "/") == 405 })
	waitUntil(t, "les 5 événements de sécurité dans la table", func() bool { return admin.count(t, `path LIKE '/attaque/%'`) == 5 })
	if n := admin.count(t, `path LIKE '/ordinaire%'`); n != 0 {
		t.Fatalf("%d accès ordinaires dans la table logs de l'Admin", n)
	}
	st, _ := admin.vault.Store(streamEdgeID, "")
	waitUntil(t, "la position du volume à la fin de la base", func() bool {
		c, _ := st.ShipCursor(logstore.KindAccess)
		return c == gw.logStore.LastID(logstore.KindAccess)
	})

	// Une coupure : des lignes arrivent pendant ce temps.
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })
	gw.addAccess("ordinaire3", 50, false)
	gw.addAccess("attaque2", 3, true)
	admin.start(t, gw.url)
	waitUntil(t, "les 458 lignes dans le volume de logs", func() bool { return admin.vaultCount(t, streamEdgeID, "/") == 458 })
	waitUntil(t, "les 3 événements de la coupure", func() bool { return admin.count(t, `path LIKE '/attaque2/%'`) == 3 })
	time.Sleep(300 * time.Millisecond)
	if n := admin.vaultCount(t, streamEdgeID, "/"); n != 458 {
		t.Errorf("%d lignes dans le volume de logs, attendu 458 (doublons ou pertes)", n)
	}
	if n := admin.count(t, `path LIKE '/attaque/%'`); n != 5 {
		t.Errorf("%d événements d'avant la coupure dans la table, attendu 5", n)
	}
	if n := admin.count(t, `path LIKE '/ordinaire%'`); n != 0 {
		t.Errorf("%d accès ordinaires dans la table après la reprise", n)
	}
}

// Deux passerelles qui reçoivent du trafic en même temps : l'Admin range les lignes de chacune dans son store, sans les
// mélanger, et la vue Live de l'Admin les montre toutes les deux.
func TestTwoGatewaysAreBothInTheAdminVaultAndTheLiveView(t *testing.T) {
	dir := t.TempDir()
	gwA := newNamedStreamGateway(t, filepath.Join(dir, "a"), "gw-a")
	gwB := newNamedStreamGateway(t, filepath.Join(dir, "b"), "gw-b")
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	admin.start(t, gwA.url)
	admin.manager.Register(streamEdgeID2, "gw-b", gwB.url, "admin")
	waitUntil(t, "la connexion des deux passerelles", func() bool {
		return gwA.wsHub.HasAdmin(streamEdgeID) && gwB.wsHub.HasAdmin(streamEdgeID2)
	})

	_, ch, cancel := admin.store.Subscribe()
	defer cancel()
	release := admin.manager.AcquireLive()
	defer release()
	gwA.addAccess("a-direct", 6, false)
	gwB.addAccess("b-direct", 4, false)

	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for len(seen) < 10 {
		select {
		case e := <-ch:
			seen[e.NodeName+e.Path] = true
		case <-deadline:
			t.Fatalf("%d lignes vues en direct sur 10 : %v", len(seen), seen)
		}
	}
	for i := 1; i <= 6; i++ {
		if !seen["gw-a/a-direct/"+string(rune('0'+i))] {
			t.Errorf("ligne %d de la passerelle A absente de la vue Live", i)
		}
	}
	for i := 1; i <= 4; i++ {
		if !seen["gw-b/b-direct/"+string(rune('0'+i))] {
			t.Errorf("ligne %d de la passerelle B absente de la vue Live", i)
		}
	}

	waitUntil(t, "les lignes de A dans son store", func() bool { return admin.vaultCount(t, streamEdgeID, "/a-direct") == 6 })
	waitUntil(t, "les lignes de B dans son store", func() bool { return admin.vaultCount(t, streamEdgeID2, "/b-direct") == 4 })
	if n := admin.vaultCount(t, streamEdgeID, "/b-direct"); n != 0 {
		t.Errorf("%d lignes de B dans le store de A", n)
	}
	if n := admin.vaultCount(t, streamEdgeID2, "/a-direct"); n != 0 {
		t.Errorf("%d lignes de A dans le store de B", n)
	}
}

// Le volume de logs se monte sur un Admin dont la base est neuve : l'historique y est, les lignes que la passerelle renvoie
// ne s'y écrivent pas deux fois, et la table logs retrouve ses événements de sécurité.
func TestAdminWithANewDatabaseKeepsTheLogVolumeHistory(t *testing.T) {
	root := t.TempDir()
	vaultDir := filepath.Join(root, "volume-logs")
	gw := newStreamGateway(t, filepath.Join(root, "gw"))
	gw.addAccess("ordinaire", 120, false)
	gw.addAccess("attaque", 4, true)

	first := newAdminSideWithVault(t, filepath.Join(root, "admin1"), vaultDir)
	first.start(t, gw.url)
	waitUntil(t, "les 124 lignes dans le volume de logs", func() bool { return first.vaultCount(t, streamEdgeID, "/") == 124 })
	first.stop()
	first.vault.Close()

	second := newAdminSideWithVault(t, filepath.Join(root, "admin2"), vaultDir)
	t.Cleanup(second.stop)
	if n := second.vaultCount(t, streamEdgeID, "/"); n != 124 {
		t.Fatalf("%d lignes dans le volume de logs monté sur le nouvel Admin, attendu 124", n)
	}
	second.start(t, gw.url)
	waitUntil(t, "les événements de sécurité dans la table neuve", func() bool { return second.count(t, `path LIKE '/attaque/%'`) == 4 })
	time.Sleep(500 * time.Millisecond)
	if n := second.vaultCount(t, streamEdgeID, "/"); n != 124 {
		t.Fatalf("%d lignes après le rejeu de la passerelle, attendu 124 (doublons)", n)
	}
}

// readerFor branche la lecture des logs de l'Admin sur son volume de logs, le temps d'un test.
func (a *adminSide) readerFor(t *testing.T, source string) {
	t.Helper()
	edgeproxy.SetLocalLogs(&edgelogs.Reader{Vault: a.vault, Source: func() string { return source }})
	t.Cleanup(func() { edgeproxy.SetLocalLogs(nil) })
}

func sameJSON(t *testing.T, what string, a, b any) {
	t.Helper()
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("%s diffère entre la copie et la passerelle :\ncopie      %s\npasserelle %s", what, ja, jb)
	}
}

// La copie de l'Admin répond comme la passerelle : mêmes lignes (avec leurs numéros chez la passerelle), mêmes histogrammes,
// mêmes facettes, mêmes classements, mêmes IP distinctes.
func TestAdminCopyAnswersLikeTheGateway(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	gw.mixed("parite", 90)
	gw.addAccess("attaque", 4, true)
	gw.logStore.Flush()
	admin.start(t, gw.url)
	waitUntil(t, "les 94 lignes dans la copie", func() bool { return admin.vaultCount(t, streamEdgeID, "/") == 94 })

	target := edgeproxy.Target{ID: streamEdgeID, NodeName: "gw-stream", Endpoint: gw.url}
	client := edgeproxy.NewClient()
	ctx := t.Context()
	params := logapi.Params{Kind: "access", Limit: 500}
	read := func(source string) (s *logapi.SearchResponse, h *logapi.HistogramResponse, f *logapi.FacetsResponse, top *logapi.TopResponse, u *logapi.UniqueIPsResponse) {
		admin.readerFor(t, source)
		var err error
		if s, err = client.LogSearch(ctx, target, params); err != nil {
			t.Fatalf("LogSearch (%s) : %v", source, err)
		}
		hp := params
		hp.Bucket = "day"
		if h, err = client.LogHistogram(ctx, target, hp); err != nil {
			t.Fatalf("LogHistogram (%s) : %v", source, err)
		}
		fp := params
		fp.Fields = "domain,method,level"
		if f, err = client.LogFacets(ctx, target, fp); err != nil {
			t.Fatalf("LogFacets (%s) : %v", source, err)
		}
		if top, err = client.LogTop(ctx, target, params, logapi.TopRequest{Dim: "domain", Mode: "best", K: 10}); err != nil {
			t.Fatalf("LogTop (%s) : %v", source, err)
		}
		if u, err = client.LogUniqueIPs(ctx, target, params); err != nil {
			t.Fatalf("LogUniqueIPs (%s) : %v", source, err)
		}
		return
	}
	cs, ch, cf, ctop, cu := read("admin")
	gs, gh, gf, gtop, gu := read("gateway")
	if len(cs.Entries) != 94 || len(gs.Entries) != 94 {
		t.Fatalf("%d lignes de la copie, %d de la passerelle, attendu 94", len(cs.Entries), len(gs.Entries))
	}
	// Les identifiants de la copie sont ceux de la passerelle : une référence de ligne reste valable chez elle.
	cs.Via, gs.Via = "", ""
	sameJSON(t, "la recherche", cs, gs)
	sameJSON(t, "l'histogramme", ch, gh)
	sameJSON(t, "les facettes", cf, gf)
	sameJSON(t, "le classement", ctop, gtop)
	sameJSON(t, "les IP distinctes", cu, gu)
}

// Passerelle éteinte, ses lignes restent lisibles dans la copie ; en mode « gateway », la lecture échoue.
func TestAdminCopyIsReadableWhenTheGatewayIsDown(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	gw.addAccess("avant-panne", 25, false)
	admin.start(t, gw.url)
	waitUntil(t, "les 25 lignes dans la copie", func() bool { return admin.vaultCount(t, streamEdgeID, "/avant-panne") == 25 })

	down := edgeproxy.Target{ID: streamEdgeID, NodeName: "gw-stream", Endpoint: "http://127.0.0.1:1"}
	client := edgeproxy.NewClient()
	admin.readerFor(t, "auto")
	resp, err := client.LogSearch(t.Context(), down, logapi.Params{Kind: "access", Limit: 100})
	if err != nil || len(resp.Entries) != 25 {
		t.Fatalf("passerelle éteinte, mode auto : %v, %d lignes, attendu 25", err, len(resp.Entries))
	}
	admin.readerFor(t, "gateway")
	if _, err := client.LogSearch(t.Context(), down, logapi.Params{Kind: "access", Limit: 100}); err == nil {
		t.Fatal("mode gateway : la lecture d'une passerelle éteinte aurait dû échouer")
	}
}

