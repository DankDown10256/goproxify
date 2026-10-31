// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgelogs

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

func addRows(t *testing.T, v *Vault, id, name string, at time.Time, rows ...logstore.Entry) {
	t.Helper()
	st, err := v.Store(id, name)
	if err != nil {
		t.Fatal(err)
	}
	shipped := make([]logstore.ShippedRow, len(rows))
	for i, e := range rows {
		e.Ts = at.Add(time.Duration(i) * time.Second)
		if e.Level == "" {
			e.Level, e.Component, e.Domain, e.Status, e.Path = "info", "edge", "app.example.com", 200, "/x"
		}
		shipped[i] = logstore.ShippedRow{Seq: int64(100 + i), Entry: e}
	}
	if _, err := st.AddShipped(logstore.KindAccess, shipped, int64(100+len(rows)-1)); err != nil {
		t.Fatal(err)
	}
}

// Un export de l'Admin couvre toutes les passerelles, nomme chacune dans le manifeste, numérote les lignes comme la passerelle
// et révèle l'IP réelle avec la clé de l'Admin.
func TestExportCoversEveryGatewayOfTheVolume(t *testing.T) {
	key, err := ipcrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v := testVault(t, key)
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	addRows(t, v, "id-a", "gw-a", at, logstore.Entry{IP: "203.0.113.1"}, logstore.Entry{IP: "203.0.113.0", RealIP: "203.0.113.77", IPTruncated: true})
	addRows(t, v, "id-b", "gw-b", at, logstore.Entry{IP: "198.51.100.5"})

	sources, err := v.Sources("all")
	if err != nil || len(sources) != 2 {
		t.Fatalf("Sources = %d, %v", len(sources), err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := filepath.Join(t.TempDir(), "export")
	res, err := logexport.RunSources(sources, priv, logexport.Request{Node: "admin", Operator: "test", Reason: "réquisition", Kind: logstore.KindAccess,
		From: at.Add(-time.Hour), To: at.Add(time.Hour), Format: logexport.FormatNDJSON}, base, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Rows != 3 || len(res.Manifest.Nodes) != 2 {
		t.Fatalf("manifeste : %d lignes, passerelles %v", res.Manifest.Rows, res.Manifest.Nodes)
	}
	if rep, err := logexport.Verify(res.ManifestPath, res.DataPath, "", nil, nil); err != nil || !rep.FileChecked {
		t.Fatalf("Verify = %+v, %v", rep, err)
	}

	f, err := os.Open(res.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids, ips []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row struct{ ID, IP string }
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		ids, ips = append(ids, row.ID), append(ips, row.IP)
	}
	joined := strings.Join(ids, " ") + " " + strings.Join(ips, " ")
	for _, want := range []string{"gw-a:access:100", "gw-a:access:101", "gw-b:access:100", "203.0.113.77"} {
		if !strings.Contains(joined, want) {
			t.Errorf("l'export ne contient pas %q : %s", want, joined)
		}
	}

	only, err := v.Sources("gw-b")
	if err != nil || len(only) != 1 || only[0].Name != "gw-b" {
		t.Fatalf("Sources(gw-b) = %v, %v", only, err)
	}
	if _, err := v.Sources("inconnue"); err == nil {
		t.Fatal("une passerelle inconnue a été acceptée")
	}
}

// Un gel légal sans filtre est un registre commun : toutes les passerelles le voient, et le lever le retire partout.
func TestHoldIsSharedByEveryStoreOfTheVolume(t *testing.T) {
	v := testVault(t, nil)
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	addRows(t, v, "id-a", "gw-a", at, logstore.Entry{IP: "203.0.113.1"})
	addRows(t, v, "id-b", "gw-b", at, logstore.Entry{IP: "203.0.113.2"})

	h, err := v.AddHold(logstore.Hold{Reason: "procédure 42", From: at.Add(-time.Hour), To: at.Add(time.Hour), By: "test"})
	if err != nil {
		t.Fatal(err)
	}
	holds, err := v.Holds()
	if err != nil || len(holds) != 1 || holds[0].ID != h.ID {
		t.Fatalf("registre = %+v, %v", holds, err)
	}
	for _, id := range []string{"id-a", "id-b"} {
		st, _ := v.Store(id, "")
		sh, err := st.Holds()
		if err != nil || len(sh) != 1 || sh[0].ID != h.ID {
			t.Errorf("le store %s ne voit pas le gel : %+v, %v", id, sh, err)
		}
	}
	// Une purge très postérieure ne supprime aucun fichier gelé, chez aucune passerelle.
	for _, id := range []string{"id-a", "id-b"} {
		st, _ := v.Store(id, "")
		st.Purge(at.Add(400 * 24 * time.Hour))
		if n := searchCount(t, st); n != 1 {
			t.Errorf("%s : %d ligne(s) après la purge, attendu 1 (gel)", id, n)
		}
	}
	if err := v.RemoveHold(h.ID); err != nil {
		t.Fatal(err)
	}
	if holds, _ := v.Holds(); len(holds) != 0 {
		t.Fatalf("le gel levé reste au registre : %+v", holds)
	}
	for _, id := range []string{"id-a", "id-b"} {
		st, _ := v.Store(id, "")
		st.Purge(at.Add(400 * 24 * time.Hour))
		if n := searchCount(t, st); n != 0 {
			t.Errorf("%s : %d ligne(s) après la purge, attendu 0 (gel levé)", id, n)
		}
	}
}

// Un gel filtré garde, dans chaque store, les lignes de l'IP visée au-delà de la rétention.
func TestFilteredHoldKeepsTheTargetedLinesInEveryStore(t *testing.T) {
	v := testVault(t, nil)
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	addRows(t, v, "id-a", "gw-a", at, logstore.Entry{IP: "203.0.113.9"}, logstore.Entry{IP: "203.0.113.1"})
	addRows(t, v, "id-b", "gw-b", at, logstore.Entry{IP: "203.0.113.9"})
	if _, err := v.AddHold(logstore.Hold{Reason: "enquête", From: at.Add(-time.Hour), To: at.Add(time.Hour), IP: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"id-a", "id-b"} {
		st, _ := v.Store(id, "")
		held := filepath.Join(v.Dir(), id, "held")
		if entries, err := os.ReadDir(held); err != nil || len(entries) != 1 {
			t.Errorf("%s : archive des lignes gardées absente (%v, %d)", id, err, len(entries))
		}
		_ = st
	}
	if _, err := v.AddHold(logstore.Hold{Reason: "", From: at, To: at}); err == nil {
		t.Error("un gel sans motif a été accepté")
	}
}

func searchCount(t *testing.T, st *logstore.Store) int {
	t.Helper()
	page, err := st.Search(t.Context(), logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Rows)
}

// Un gel sur un volume sans passerelle n'a rien à geler : refusé.
func TestHoldNeedsAGatewayInTheVolume(t *testing.T) {
	v := testVault(t, nil)
	if _, err := v.AddHold(logstore.Hold{Reason: "x", From: time.Now().Add(-time.Hour), To: time.Now()}); err == nil {
		t.Fatal("un gel a été posé sur un volume vide")
	}
}

// Le volume ouvert pour une commande locale n'écrit rien et ne purge rien.
func TestReadOnlyVaultCanExportButNotReceive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "volume")
	w, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	addRows(t, w, "id-a", "gw-a", time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC), logstore.Entry{IP: "203.0.113.1"})
	w.Close()
	ro, err := OpenReadOnly(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	st, err := ro.Store("id-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if n := searchCount(t, st); n != 1 {
		t.Fatalf("%d ligne(s) lues en lecture seule, attendu 1", n)
	}
	if _, err := st.AddShipped(logstore.KindAccess, []logstore.ShippedRow{{Seq: 999, Entry: logstore.Entry{Ts: time.Now(), Level: "info", Status: 200}}}, 999); err == nil {
		t.Fatal("un volume ouvert en lecture seule a reçu des lignes")
	}
	if _, err := OpenReadOnly(filepath.Join(dir, "absent"), nil, nil); err == nil {
		t.Fatal("un dossier absent a été ouvert")
	}
}

// La commande locale (volume ouvert en lecture seule) pose et lève un gel, serveur éteint ou en marche.
func TestReadOnlyVaultCanPlaceAndReleaseAHold(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "volume")
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	w, err := Open(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	addRows(t, w, "id-a", "gw-a", at, logstore.Entry{IP: "203.0.113.9"})
	addRows(t, w, "id-b", "gw-b", at, logstore.Entry{IP: "203.0.113.9"})
	w.Close()

	ro, err := OpenReadOnly(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	h, err := ro.AddHold(logstore.Hold{Reason: "enquête", From: at.Add(-time.Hour), To: at.Add(time.Hour), IP: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	if holds, err := ro.Holds(); err != nil || len(holds) != 1 {
		t.Fatalf("registre = %+v, %v", holds, err)
	}
	for _, id := range []string{"id-a", "id-b"} {
		if _, err := os.Stat(filepath.Join(dir, id, "held", h.ID)); err != nil {
			t.Errorf("%s : archive du gel absente : %v", id, err)
		}
	}
	if err := ro.RemoveHold(h.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"id-a", "id-b"} {
		if _, err := os.Stat(filepath.Join(dir, id, "held", h.ID)); !os.IsNotExist(err) {
			t.Errorf("%s : archive du gel levé encore là (%v)", id, err)
		}
	}
}
