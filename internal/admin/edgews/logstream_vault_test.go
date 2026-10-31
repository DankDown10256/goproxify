// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func newVaultIngestor(t *testing.T) (*LogStreamIngestor, *logs.Store, *edgelogs.Vault) {
	t.Helper()
	g, store := newIngestor(t)
	vault, err := edgelogs.Open(filepath.Join(t.TempDir(), "volume-logs"), nil, g.Log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Close)
	g.Vault = vault
	return g, store, vault
}

func vaultPaths(t *testing.T, vault *edgelogs.Vault, nodeID string, kind logstore.Kind) int {
	t.Helper()
	st, err := vault.Store(nodeID, "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := st.Search(t.Context(), logstore.Query{Kinds: []logstore.Kind{kind}, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Rows)
}

// flagged marque l'accès de rang n d'un lot comme un événement de sécurité.
func flagged(p edgeWS.LogStreamPayload, seqs ...int64) edgeWS.LogStreamPayload {
	for i := range p.Entries {
		for _, s := range seqs {
			if p.Entries[i].Seq == s {
				p.Entries[i].WAFMatches = []string{"sqli"}
			}
		}
	}
	return p
}

func TestHandleWithVaultStoresEveryLineAndTheTableOnlySecurityEvents(t *testing.T) {
	g, store, vault := newVaultIngestor(t)
	if g.Handle("edge-a", "gw", flagged(streamBatch("access", 0, 6), 2, 5)) {
		t.Fatal("un premier lot contigu ne demande pas de reprise")
	}
	if n := vaultPaths(t, vault, "edge-a", logstore.KindAccess); n != 6 {
		t.Fatalf("%d lignes dans le volume de logs, attendu 6", n)
	}
	if got := countPaths(t, store); len(got) != 2 {
		t.Fatalf("%d lignes dans la table, attendu 2 événements de sécurité : %v", len(got), got)
	}
	st, _ := vault.Store("edge-a", "")
	if c, _ := st.ShipCursor(logstore.KindAccess); c != 6 {
		t.Fatalf("position du volume = %d, attendu 6", c)
	}
	if c, _ := store.StreamCursor("edge-a", "access"); c != 6 {
		t.Fatalf("position de la table = %d, attendu 6 (elle avance sur les lignes ordinaires)", c)
	}
}

// Après une reconnexion la passerelle renvoie des lignes déjà reçues : aucune n'est écrite deux fois, ni dans le volume,
// ni dans la table.
func TestHandleWithVaultDropsLinesAlreadyReceived(t *testing.T) {
	g, store, vault := newVaultIngestor(t)
	g.Handle("edge-a", "gw", flagged(streamBatch("access", 0, 4), 3))
	if g.Handle("edge-a", "gw", flagged(streamBatch("access", 0, 4), 3)) {
		t.Fatal("un renvoi complet ne demande pas de reprise")
	}
	if g.Handle("edge-a", "gw", flagged(streamBatch("access", 2, 4), 3, 6)) {
		t.Fatal("un chevauchement ne demande pas de reprise")
	}
	if n := vaultPaths(t, vault, "edge-a", logstore.KindAccess); n != 6 {
		t.Fatalf("%d lignes dans le volume de logs, attendu 6 sans doublon", n)
	}
	if got := countPaths(t, store); len(got) != 2 {
		t.Fatalf("%d lignes dans la table, attendu 2 sans doublon : %v", len(got), got)
	}
}

// Un lot qui commence après la plus basse des deux positions saute des lignes : refusé.
func TestHandleWithVaultRefusesABatchThatSkipsLines(t *testing.T) {
	g, _, vault := newVaultIngestor(t)
	g.Handle("edge-a", "gw", streamBatch("access", 0, 2))
	if !g.Handle("edge-a", "gw", streamBatch("access", 5, 3)) {
		t.Fatal("un trou doit demander une reprise")
	}
	if n := vaultPaths(t, vault, "edge-a", logstore.KindAccess); n != 2 {
		t.Fatalf("le lot refusé a écrit des lignes : %d", n)
	}
}

// La passerelle reprend à la plus basse des deux positions : un volume de logs neuf (ou une base neuve) fait renvoyer
// l'historique, et chaque côté écarte ce qu'il a déjà.
func TestCursorsAnnounceTheLowestOfTheTableAndTheVault(t *testing.T) {
	g, store, vault := newVaultIngestor(t)
	g.Handle("edge-a", "gw", streamBatch("access", 0, 5))
	if cur := g.Cursors("edge-a"); cur["access"] != 5 {
		t.Fatalf("Cursors = %v, attendu 5", cur)
	}

	// Volume de logs neuf : la position de la table est à 5, celle du volume à 0.
	fresh, err := edgelogs.Open(filepath.Join(t.TempDir(), "autre-volume"), nil, g.Log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Close)
	g2 := &LogStreamIngestor{Store: store, Log: g.Log, Vault: fresh}
	if cur := g2.Cursors("edge-a"); cur["access"] != 0 {
		t.Fatalf("Cursors avec un volume neuf = %v, attendu 0", cur)
	}
	if g2.Handle("edge-a", "gw", streamBatch("access", 0, 5)) {
		t.Fatal("le rejeu complet ne demande pas de reprise")
	}
	if n := vaultPaths(t, fresh, "edge-a", logstore.KindAccess); n != 5 {
		t.Fatalf("%d lignes dans le volume neuf, attendu 5", n)
	}
	if got := countPaths(t, store); len(got) != 0 {
		t.Fatalf("%d lignes ordinaires dans la table", len(got))
	}
	_ = vault
}

// Une base de passerelle remplacée : la remise à zéro ramène les deux positions, et les lignes de la nouvelle base, qui
// reprennent les mêmes numéros, sont reçues.
func TestHandleWithVaultResetAcceptsTheLinesOfAReplacedBase(t *testing.T) {
	g, _, vault := newVaultIngestor(t)
	g.Handle("edge-a", "gw", streamBatch("access", 0, 4))
	if g.Handle("edge-a", "gw", edgeWS.LogStreamPayload{Stream: "access", After: 4, Reset: true}) {
		t.Fatal("une remise à zéro ne demande pas de reprise")
	}
	st, _ := vault.Store("edge-a", "")
	if c, _ := st.ShipCursor(logstore.KindAccess); c != 0 {
		t.Fatalf("position du volume après remise à zéro = %d", c)
	}
	// Mêmes numéros, autre date : la nouvelle base.
	p := streamBatch("access", 0, 2)
	for i := range p.Entries {
		p.Entries[i].Ts = "2026-10-22T10:00:00Z"
		p.Entries[i].Path = fmt.Sprintf("/nouvelle/%d", i+1)
	}
	if g.Handle("edge-a", "gw", p) {
		t.Fatal("un lot de la nouvelle base ne demande pas de reprise")
	}
	if n := vaultPaths(t, vault, "edge-a", logstore.KindAccess); n != 6 {
		t.Fatalf("%d lignes, attendu 6 (4 de l'ancienne base, 2 de la nouvelle)", n)
	}
}

// Les logs système vont dans le volume de logs et dans la table, comme avant.
func TestHandleWithVaultKeepsSystemLogsInBothPlaces(t *testing.T) {
	g, store, vault := newVaultIngestor(t)
	g.Handle("edge-a", "gw", streamBatch("system", 0, 3))
	if n := vaultPaths(t, vault, "edge-a", logstore.KindSystem); n != 3 {
		t.Fatalf("%d lignes système dans le volume de logs, attendu 3", n)
	}
	if got := countPaths(t, store); len(got) != 3 {
		t.Fatalf("%d lignes système dans la table, attendu 3", len(got))
	}
}

// Sans volume de logs, la table ne reçoit pas tous les accès : seuls les événements de sécurité, et la position avance.
func TestSecurityOnlyKeepsOrdinaryAccessOutOfTheTable(t *testing.T) {
	g, store := newIngestor(t)
	g.SecurityOnly = true
	if g.Handle("edge-a", "gw", flagged(streamBatch("access", 0, 5), 4)) {
		t.Fatal("un lot contigu ne demande pas de reprise")
	}
	if got := countPaths(t, store); len(got) != 1 {
		t.Fatalf("%d lignes dans la table, attendu 1 : %v", len(got), got)
	}
	if c, _ := store.StreamCursor("edge-a", "access"); c != 5 {
		t.Fatalf("position = %d, attendu 5", c)
	}
}
