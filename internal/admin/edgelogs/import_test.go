// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgelogs

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// gatewayWithReplicas fabrique la base d'une passerelle qui garde, d'une ancienne version, les copies des lignes d'un pair
// (origin « backup ») : l'une en clair, l'autre pseudonymisée avec la clé de cette passerelle.
func gatewayWithReplicas(t *testing.T, gwKey []byte) *logstore.Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gw-logs")
	own, err := logstore.Open(logstore.Options{Dir: dir, IPKey: gwKey})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC)
	own.Add(logstore.KindAccess, logstore.Entry{Ts: at, Level: "info", Component: "edge", Domain: "own.example.com", Status: 200, Path: "/propre", IP: "198.51.100.9"})
	own.Flush()
	if err := own.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "access-2026-10-19.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enc, err := ipcrypt.Encrypt(gwKey, ipcrypt.CanonicalIP("203.0.113.77"))
	if err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO entries (ts, level, component, domain, method, path, status, ip, ip_enc, ip_hmac, ip_truncated, user_agent, origin, origin_id)
		VALUES (?, 'info', 'edge', 'app.example.com', 'GET', ?, 200, ?, ?, ?, ?, 'curl/8', 'backup', ?)`
	// Mêmes numéros que ceux d'une base plus récente du pair : le décalage doit les séparer.
	if _, err := db.Exec(ins, at.Add(time.Second).Format("2006-01-02T15:04:05.000000Z"), "/en-clair", "203.0.113.5", "", "", 0, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ins, at.Add(2*time.Second).Format("2006-01-02T15:04:05.000000Z"), "/pseudonymisee", "203.0.113.0", enc, ipcrypt.IPIndex(gwKey, "203.0.113.77"), 1, 2); err != nil {
		t.Fatal(err)
	}
	st, err := logstore.Open(logstore.Options{Dir: dir, IPKey: gwKey, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func exportReplicas(t *testing.T, st *logstore.Store, password string) (manifest, data string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := filepath.Join(t.TempDir(), "replicas")
	at := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	res, err := logexport.Run(st, priv, logexport.Request{Node: "core", Operator: "test", Reason: "reprise", Kind: logstore.KindAccess,
		From: at, To: at.Add(48 * time.Hour), Format: logexport.FormatNDJSON, Origin: "backup", Password: password}, base, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Rows != 2 || res.Manifest.Origin != "backup" {
		t.Fatalf("export : %d ligne(s), origine %q, attendu 2 et backup", res.Manifest.Rows, res.Manifest.Origin)
	}
	return res.ManifestPath, res.DataPath
}

// La reprise verse les copies d'un pair dans le store de la passerelle de l'Admin : lignes lisibles, IP pseudonymisée
// rechiffrée avec la clé de l'Admin et révélable, numéros décalés, position du flux intacte, rejeu sans effet.
func TestImportExportBringsReplicatedRowsIntoTheVault(t *testing.T) {
	gwKey, _ := ipcrypt.NewKey()
	adminKey, _ := ipcrypt.NewKey()
	gw := gatewayWithReplicas(t, gwKey)
	manifest, data := exportReplicas(t, gw, "mot-de-passe-de-test")

	v := testVault(t, adminKey)
	st, err := v.Store("dn_backup", "backup")
	if err != nil {
		t.Fatal(err)
	}
	// Une ligne que le flux a déjà apportée, avec le même numéro d'origine que l'une des lignes reprises.
	live := logstore.Entry{Ts: time.Date(2026, 10, 24, 19, 49, 0, 0, time.UTC), Level: "info", Component: "edge", Domain: "live.example.com", Status: 200, Path: "/flux", IP: "192.0.2.1"}
	if _, err := st.AddShipped(logstore.KindAccess, []logstore.ShippedRow{{Seq: 1, Entry: live}}, 1); err != nil {
		t.Fatal(err)
	}

	if _, err := v.ImportExport("backup", manifest, data, "un-autre-mot-de-passe", nil, false); err == nil {
		t.Fatal("un mauvais mot de passe a été accepté")
	}
	dry, err := v.ImportExport("backup", manifest, data, "mot-de-passe-de-test", nil, true)
	if err != nil || dry.Read != 2 || dry.Added != 0 {
		t.Fatalf("essai à blanc = %+v, %v", dry, err)
	}
	if n := searchCount(t, st); n != 1 {
		t.Fatalf("l'essai à blanc a écrit des lignes : %d", n)
	}

	rep, err := v.ImportExport("backup", manifest, data, "mot-de-passe-de-test", nil, false)
	if err != nil || rep.Added != 2 || rep.Kind != "access" || rep.FromNode != "core" {
		t.Fatalf("reprise = %+v, %v", rep, err)
	}
	if n := searchCount(t, st); n != 3 {
		t.Fatalf("%d lignes dans le store, attendu 3", n)
	}
	if c, _ := st.ShipCursor(logstore.KindAccess); c != 1 {
		t.Fatalf("la reprise a touché la position du flux : %d, attendu 1", c)
	}
	again, err := v.ImportExport("backup", manifest, data, "mot-de-passe-de-test", nil, false)
	if err != nil || again.Added != 0 {
		t.Fatalf("rejeu = %+v, %v, attendu 0 ligne nouvelle", again, err)
	}

	// L'IP réelle de la ligne pseudonymisée se révèle avec la clé de l'Admin, par son numéro décalé ; celui d'origine
	// (2) ne désigne aucune ligne reprise, et le numéro 1 reste celui de la ligne du flux.
	ip, err := st.RevealSourceIP(logstore.KindAccess, ImportedIDBase+2)
	if err != nil || ip != "203.0.113.77" {
		t.Fatalf("RevealSourceIP = %q, %v", ip, err)
	}
	if _, err := st.RevealSourceIP(logstore.KindAccess, 2); err == nil {
		t.Fatal("le numéro d'origine non décalé désigne une ligne")
	}
	rows, err := st.ReadAfter(logstore.KindAccess, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var sawTruncated bool
	for _, r := range rows {
		if r.Path == "/pseudonymisee" {
			sawTruncated = r.IP == "203.0.113.0" && r.Pseudonymized && r.IPTruncated
		}
	}
	if !sawTruncated {
		t.Fatalf("la ligne pseudonymisée a perdu son IP tronquée : %+v", rows)
	}
}

// Un export modifié n'est jamais repris, et une passerelle inconnue est refusée.
func TestImportExportRefusesATamperedFileAndAnUnknownGateway(t *testing.T) {
	gwKey, _ := ipcrypt.NewKey()
	gw := gatewayWithReplicas(t, gwKey)
	manifest, data := exportReplicas(t, gw, "mot-de-passe-de-test")
	v := testVault(t, nil)
	if _, err := v.Store("dn_backup", "backup"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ImportExport("inconnue", manifest, data, "mot-de-passe-de-test", nil, false); err == nil {
		t.Fatal("une passerelle inconnue a été acceptée")
	}
	raw, err := os.ReadFile(data)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(data, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ImportExport("backup", manifest, data, "mot-de-passe-de-test", nil, false); err == nil {
		t.Fatal("un export modifié a été repris")
	}
}

// Un export des lignes propres d'une passerelle (sans -origin : une version qui ignore l'option, ou un oubli) n'est pas la
// copie d'un pair : la reprise le refuse, au lieu de ranger les lignes d'une passerelle sous le nom d'une autre. Un export
// des copies d'un pair ne se verse pas non plus chez une autre passerelle que ce pair.
func TestImportExportRefusesOwnRowsAndAnotherPeer(t *testing.T) {
	gwKey, _ := ipcrypt.NewKey()
	gw := gatewayWithReplicas(t, gwKey)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	at := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	own, err := logexport.Run(gw, priv, logexport.Request{Node: "core", Operator: "test", Reason: "essai", Kind: logstore.KindAccess,
		From: at, To: at.Add(48 * time.Hour), Format: logexport.FormatNDJSON, Password: "mot-de-passe-de-test"}, filepath.Join(t.TempDir(), "propres"), time.Now)
	if err != nil || own.Manifest.Rows != 1 || own.Manifest.Origin != "" {
		t.Fatalf("export des lignes propres : %+v, %v", own, err)
	}
	v := testVault(t, nil)
	st, err := v.Store("dn_backup", "backup")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Store("dn_autre", "autre"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ImportExport("backup", own.ManifestPath, own.DataPath, "mot-de-passe-de-test", nil, false); err == nil {
		t.Fatal("un export de lignes propres a été repris comme copie d'un pair")
	}
	manifest, data := exportReplicas(t, gw, "mot-de-passe-de-test")
	if _, err := v.ImportExport("autre", manifest, data, "mot-de-passe-de-test", nil, false); err == nil {
		t.Fatal("les copies du pair backup ont été reprises chez une autre passerelle")
	}
	if n := searchCount(t, st); n != 0 {
		t.Fatalf("%d ligne(s) rangées malgré les refus", n)
	}
	if _, err := v.ImportExport("dn_backup", manifest, data, "mot-de-passe-de-test", nil, false); err != nil {
		t.Fatalf("la reprise désignée par l'identifiant de la passerelle a échoué : %v", err)
	}
}
