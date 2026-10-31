// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgelogs

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

func testVault(t *testing.T, key []byte) *Vault {
	t.Helper()
	v, err := Open(filepath.Join(t.TempDir(), "volume-logs"), key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}

func seed(t *testing.T, v *Vault, nodeID string, n int) *logstore.Store {
	t.Helper()
	st, err := v.Store(nodeID, "gw")
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]logstore.ShippedRow, n)
	now := time.Now().UTC()
	for i := range rows {
		rows[i] = logstore.ShippedRow{Seq: int64(1000 + i + 1), Entry: logstore.Entry{
			Ts: now.Add(time.Duration(i) * time.Millisecond), Level: "info", Component: "edge", Domain: "app.example.com",
			Method: "GET", Path: "/p/" + string(rune('a'+i)), Status: 200, IP: "198.51.100.1",
		}}
	}
	if _, err := st.AddShipped(logstore.KindAccess, rows, int64(1000+n)); err != nil {
		t.Fatal(err)
	}
	return st
}

func search(t *testing.T, r *Reader, nodeID string) (int, logapi.SearchResponse, bool) {
	t.Helper()
	q := url.Values{"kind": {"access"}, "limit": {"50"}}
	status, data, ok := r.Serve(context.Background(), nodeID, "gw", http.MethodGet, logapi.PathSearch+"?"+q.Encode(), nil)
	var out logapi.SearchResponse
	if ok && status == http.StatusOK {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
	}
	return status, out, ok
}

// La copie répond comme la passerelle : mêmes lignes, et chaque ligne porte le numéro qu'elle a chez la passerelle.
func TestReaderServesSearchFromTheCopyWithTheGatewayIDs(t *testing.T) {
	v := testVault(t, nil)
	seed(t, v, "node-1", 3)
	r := &Reader{Vault: v}
	status, out, ok := search(t, r, "node-1")
	if !ok || status != http.StatusOK || len(out.Entries) != 3 {
		t.Fatalf("Serve = %d, %d lignes, ok=%v", status, len(out.Entries), ok)
	}
	for _, e := range out.Entries {
		if e.ID < 1001 || e.ID > 1003 {
			t.Errorf("l'identifiant %d n'est pas celui de la passerelle", e.ID)
		}
	}
}

func TestReaderLeavesUnknownGatewaysAndOtherPathsToTheGateway(t *testing.T) {
	v := testVault(t, nil)
	seed(t, v, "node-1", 2)
	r := &Reader{Vault: v}
	if _, _, ok := search(t, r, "node-inconnu"); ok {
		t.Error("une passerelle sans store a été servie")
	}
	for _, p := range []string{logapi.PathErase, logapi.PathEphorSim, logapi.PathSurface} {
		if _, _, ok := r.Serve(context.Background(), "node-1", "gw", http.MethodPost, p, []byte("{}")); ok {
			t.Errorf("%s ne doit pas être servi par la copie", p)
		}
	}
}

func TestReaderSourceSetting(t *testing.T) {
	v := testVault(t, nil)
	seed(t, v, "node-1", 2)
	for source, want := range map[string]bool{SourceAuto: true, SourceAdmin: true, SourceGateway: false} {
		r := &Reader{Vault: v, Source: func() string { return source }}
		if _, _, ok := search(t, r, "node-1"); ok != want {
			t.Errorf("source %q : servi = %v, attendu %v", source, ok, want)
		}
	}
}

// Tant que la copie n'a pas rattrapé ce que la passerelle annonce, la passerelle répond ; une passerelle muette est lue
// dans la copie.
func TestReaderAutoWaitsForTheCopyToCatchUp(t *testing.T) {
	v := testVault(t, nil)
	seed(t, v, "node-1", 2) // position 1002
	announce := func(access int64, known bool) func(string) (int64, int64, bool) {
		return func(string) (int64, int64, bool) { return access, 0, known }
	}
	cases := []struct {
		name string
		fn   func(string) (int64, int64, bool)
		want bool
	}{
		{"à jour", announce(1002, true), true},
		{"en avance", announce(900, true), true},
		{"en retard", announce(5000, true), false},
		{"passerelle muette", announce(5000, false), true},
	}
	for _, c := range cases {
		r := &Reader{Vault: v, Announced: c.fn}
		if _, _, ok := search(t, r, "node-1"); ok != c.want {
			t.Errorf("%s : servi = %v, attendu %v", c.name, ok, c.want)
		}
	}
	// En mode admin, la copie répond même en retard.
	r := &Reader{Vault: v, Announced: announce(5000, true), Source: func() string { return SourceAdmin }}
	if _, _, ok := search(t, r, "node-1"); !ok {
		t.Error("le mode admin doit lire la copie même en retard")
	}
}

// Une copie vide (rien reçu) n'est pas lue en mode auto : la copie n'est pas commencée.
func TestReaderAutoIgnoresAnEmptyCopy(t *testing.T) {
	v := testVault(t, nil)
	if _, err := v.Store("node-1", "gw"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := search(t, &Reader{Vault: v}, "node-1"); ok {
		t.Error("une copie vide a été lue")
	}
}

// La révélation désigne la ligne par son numéro chez la passerelle ; une ligne absente de la copie est laissée à la passerelle.
func TestReaderRevealUsesTheGatewayRowNumber(t *testing.T) {
	key, err := ipcrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v := testVault(t, key)
	st, _ := v.Store("node-1", "gw")
	e := logstore.Entry{Ts: time.Now().UTC(), Level: "info", Component: "edge", Domain: "a.example.com", Status: 200, Path: "/x",
		IP: "203.0.113.0", RealIP: "203.0.113.77", IPTruncated: true}
	if _, err := st.AddShipped(logstore.KindAccess, []logstore.ShippedRow{{Seq: 4242, Entry: e}}, 4242); err != nil {
		t.Fatal(err)
	}
	r := &Reader{Vault: v}
	body, _ := json.Marshal(logapi.RevealRequest{Kind: "access", ID: 4242})
	status, data, ok := r.Serve(context.Background(), "node-1", "gw", http.MethodPost, logapi.PathReveal, body)
	var out logapi.RevealResponse
	if !ok || status != http.StatusOK || json.Unmarshal(data, &out) != nil || out.IP != "203.0.113.77" {
		t.Fatalf("révélation = %d %s ok=%v", status, data, ok)
	}
	body, _ = json.Marshal(logapi.RevealRequest{Kind: "access", ID: 999})
	if _, _, ok := r.Serve(context.Background(), "node-1", "gw", http.MethodPost, logapi.PathReveal, body); ok {
		t.Error("une ligne absente de la copie doit retomber sur la passerelle")
	}
}

// L'effacement RGPD d'une IP vide tous les stores du volume, une passerelle retirée comprise, y compris les lignes
// pseudonymisées (retrouvées par leur empreinte).
func TestVaultEraseIPEmptiesEveryStore(t *testing.T) {
	key, err := ipcrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v := testVault(t, key)
	now := time.Now().UTC()
	add := func(node string, seq int64, ip, real string) {
		st, err := v.Store(node, node)
		if err != nil {
			t.Fatal(err)
		}
		e := logstore.Entry{Ts: now, Level: "info", Component: "edge", Domain: "a.example.com", Status: 200, Path: "/x", IP: ip, RealIP: real, IPTruncated: real != ""}
		if _, err := st.AddShipped(logstore.KindAccess, []logstore.ShippedRow{{Seq: seq, Entry: e}}, seq); err != nil {
			t.Fatal(err)
		}
	}
	add("gw-a", 1, "203.0.113.9", "")
	add("gw-b", 1, "203.0.113.0", "203.0.113.9") // pseudonymisée
	add("gw-b", 2, "198.51.100.1", "")           // une autre IP, à garder
	n, err := v.EraseIP("203.0.113.9")
	if err != nil || n != 2 {
		t.Fatalf("EraseIP = %d, %v, attendu 2", n, err)
	}
	for node, want := range map[string]int{"gw-a": 0, "gw-b": 1} {
		st, _ := v.Store(node, "")
		page, err := st.Search(context.Background(), logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Limit: 100})
		if err != nil || len(page.Rows) != want {
			t.Errorf("%s : %d lignes après effacement, attendu %d (%v)", node, len(page.Rows), want, err)
		}
	}
}

// Après Close, plus aucun store n'est rouvert : un acquittement différé ne doit pas reprendre un fichier du volume.
func TestClosedVaultReopensNothing(t *testing.T) {
	v := testVault(t, nil)
	seed(t, v, "node-1", 2)
	v.Close()
	if _, err := v.Store("node-1", "gw"); err == nil {
		t.Fatal("un volume fermé a rouvert un store")
	}
	if _, ok := v.Existing("node-1"); ok {
		t.Fatal("un volume fermé a servi un store existant")
	}
	if svc := v.Service("node-1", "gw"); svc != nil {
		t.Fatal("un volume fermé a rendu un service de lecture")
	}
}

// La conservation réglée vaut pour les stores déjà ouverts et pour ceux qui s'ouvriront ensuite.
func TestVaultRetentionAppliesToOpenAndFutureStores(t *testing.T) {
	v := testVault(t, nil)
	open, _ := v.Store("node-1", "gw")
	if got := open.Retention(logstore.KindAccess); got != logstore.DefaultAccessRetention {
		t.Fatalf("avant réglage : %v", got)
	}
	v.SetRetention(logstore.KindAccess, 10*24*time.Hour)
	v.SetRetention(logstore.KindSystem, 5*24*time.Hour)
	v.SetRetention(logstore.KindAccess, 0) // ignorée
	if got := open.Retention(logstore.KindAccess); got != 10*24*time.Hour {
		t.Errorf("store ouvert : %v, attendu 10 jours", got)
	}
	later, _ := v.Store("node-2", "gw-2")
	if a, s := later.Retention(logstore.KindAccess), later.Retention(logstore.KindSystem); a != 10*24*time.Hour || s != 5*24*time.Hour {
		t.Errorf("store ouvert ensuite : %v et %v", a, s)
	}
	if v.Retention(logstore.KindSystem) != 5*24*time.Hour {
		t.Errorf("Retention = %v", v.Retention(logstore.KindSystem))
	}
}
