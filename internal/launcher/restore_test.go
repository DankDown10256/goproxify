// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/importer"
	"github.com/vincamok/goproxify/internal/pairing"
)

const (
	restoreKey  = "cle-de-sauvegarde-de-test"
	restoreRoot = "root-de-l-ancien-admin"
)

// restoreArchitecture : une architecture avec un réglage (domaines) que la topologie ne porte pas.
const restoreArchitecture = `{
  "schema_version": 1,
  "nodes": [
    {"id": "dn_edge1", "role": "edge", "name": "main-edge", "endpoint": "http://10.0.0.1:8000",
     "config": {"host": "main", "reachable_host": "10.0.0.1:8000", "cluster": true, "cluster_group": "ha-main", "domains": "app.exemple.fr"}},
    {"id": "dn_agent1", "role": "agent", "name": "main-agent", "config": {"host": "main", "reachable_host": "10.0.0.1", "target_edge": "ha:ha-main"}},
    {"id": "dn_agent2", "role": "agent", "name": "nas-agent", "config": {"host": "nas", "reachable_host": "10.0.0.2", "target_edge": "ha:ha-main"}}
  ]
}
`

// makeBackup produit le fichier d'un snapshot tel que l'Admin le crée : partie secrets chiffrée avec restoreKey.
func makeBackup(t *testing.T, withRoot bool) (data []byte, cert *AdminCert) {
	t.Helper()
	t.Setenv("GPX_BACKUP_KEY", "")
	importer.SetFileKey(restoreKey)
	t.Cleanup(func() { importer.SetFileKey("") })

	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "architecture.json"), []byte(restoreArchitecture), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err = NewAdminCert([]string{"10.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	extra := map[string][]byte{"admin-tls.crt": []byte(cert.CertPEM), "admin-tls.key": []byte(cert.KeyPEM)}
	if withRoot {
		extra["admin-secrets.json"] = []byte(`{"GPX_PAIRING_SECRET": "` + restoreRoot + `", "GPX_PAIRING_SECRET_PREVIOUS": "ancien-1"}`)
	}
	bk := &importer.Backup{Version: "1"}
	if _, err := importer.AttachSecrets(db, bk, map[string]string{"state": state}, extra); err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(bk)
	if err != nil {
		t.Fatal(err)
	}
	return data, cert
}

func TestReadBackupGivesWhatTheAdminNeedsToBeRebuilt(t *testing.T) {
	data, cert := makeBackup(t, true)
	r, err := ReadBackup(data, restoreKey)
	if err != nil {
		t.Fatal(err)
	}
	if r.Root != restoreRoot || r.RootPrevious != "ancien-1" || r.BackupKey != restoreKey {
		t.Errorf("secret racine, précédent et clé : %+v", r)
	}
	if r.Cert == nil || r.Cert.Fingerprint != cert.Fingerprint || r.Cert.KeyPEM != cert.KeyPEM {
		t.Errorf("le certificat garde son empreinte : %+v", r.Cert)
	}
	if string(r.ArchitectureJSON) != restoreArchitecture || r.Architecture == nil || len(r.Architecture.Nodes) != 3 {
		t.Errorf("architecture.json tel que sauvegardé : %q", r.ArchitectureJSON)
	}
}

func TestReadBackupRefusesWhatCannotRebuildTheAdmin(t *testing.T) {
	data, _ := makeBackup(t, true)
	if _, err := ReadBackup(data, "une-autre-cle"); err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Errorf("une mauvaise clé doit être refusée : %v", err)
	}
	if _, err := ReadBackup(data, "  "); err == nil || !strings.Contains(err.Error(), "clé") {
		t.Errorf("sans clé : %v", err)
	}
	old, _ := makeBackup(t, false)
	if _, err := ReadBackup(old, restoreKey); err == nil || !strings.Contains(err.Error(), "secret racine") {
		t.Errorf("une sauvegarde sans secret racine ne reconstruit pas l'Admin : %v", err)
	}
	if _, err := ReadBackup([]byte("pas du json"), restoreKey); err == nil {
		t.Error("un fichier illisible doit être refusé")
	}
}

func TestTopologyFromBackupPutsTheAdminOnThisMachine(t *testing.T) {
	data, _ := makeBackup(t, true)
	r, err := ReadBackup(data, restoreKey)
	if err != nil {
		t.Fatal(err)
	}
	topo, err := r.TopologyFromBackup("main", "")
	if err != nil {
		t.Fatal(err)
	}
	local, _ := topo.Host(topo.Local)
	if local.Name != "main" || !local.Has(RoleAdmin) || !local.Has(RoleEdge) || !local.Has(RoleAgent) || local.Addr != "10.0.0.1" {
		t.Errorf("hôte local = %+v", local)
	}
	if err := topo.Validate(); err != nil {
		t.Errorf("la topologie doit être valide : %v", err)
	}
	if nas, _ := topo.Host("nas"); nas.Has(RoleAdmin) {
		t.Error("seul l'hôte de cette machine reçoit l'Admin")
	}

	moved, err := r.TopologyFromBackup("main", "192.168.1.99")
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := moved.Host("main"); h.Addr != "192.168.1.99" {
		t.Errorf("--addr remplace l'adresse déclarée : %q", h.Addr)
	}
	if byAddr, err := r.TopologyFromBackup("", "10.0.0.1"); err != nil || byAddr.Local != "main" {
		t.Errorf("l'hôte peut aussi se trouver par son adresse : %v %v", byAddr, err)
	}
	if _, err := r.TopologyFromBackup("", ""); err == nil || !strings.Contains(err.Error(), "main (10.0.0.1)") || !strings.Contains(err.Error(), "nas (10.0.0.2)") {
		t.Errorf("sans indication, l'erreur liste les hôtes de la sauvegarde : %v", err)
	}
	if _, err := r.TopologyFromBackup("inconnu", ""); err == nil {
		t.Error("un nom absent de la sauvegarde est refusé")
	}
}

func TestRunWithARestoreKeepsTheOldAdminsIdentity(t *testing.T) {
	data, cert := makeBackup(t, true)
	r, err := ReadBackup(data, restoreKey)
	if err != nil {
		t.Fatal(err)
	}
	topo, err := r.TopologyFromBackup("main", "")
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI()
	rep, err := Run(context.Background(), api, Options{Topology: topo, Restore: r, Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}

	env := envOf(t, api.bodies["goproxify-admin"])
	if env["GPX_PAIRING_SECRET"] != restoreRoot || env["GPX_PAIRING_SECRET_PREVIOUS"] != "ancien-1" || env["GPX_BACKUP_KEY"] != restoreKey {
		t.Errorf("l'Admin reprend le secret racine, son précédent et la clé de sauvegarde : %v", env)
	}
	if api.files["/etc/goproxify/tls/admin.crt"] != cert.CertPEM || api.files["/etc/goproxify/tls/admin.key"] != cert.KeyPEM {
		t.Error("l'Admin reprend son certificat")
	}
	if api.files["/etc/goproxify/state/architecture.json"] != restoreArchitecture {
		t.Errorf("architecture.json est déposé tel que sauvegardé, domaines compris : %q", api.files["/etc/goproxify/state/architecture.json"])
	}
	edge := envOf(t, api.bodies["goproxify-edge"])
	if edge["GPX_EDGE_CHANNEL_KEY"] != pairing.EdgeChannelKey(restoreRoot, "dn_edge1") {
		t.Error("la clé de canal de la passerelle est celle qu'elle avait, dérivée de l'identifiant du fichier et du secret racine")
	}
	if edge["GPX_AGENT_PAIRING_KEY"] != pairing.AgentKey(restoreRoot) {
		t.Error("la clé des Agents est dérivée du secret racine restauré")
	}
	if !rep.Restored || !rep.KeptCertificate || rep.Fingerprint != cert.Fingerprint || rep.AdminEmail != RestoreAdminEmail {
		t.Errorf("rapport = %+v", rep)
	}
	s := rep.Summary()
	for _, want := range []string{"Admin reconstruit", "même empreinte", RestoreAdminEmail, "Restaurer", "supprimez"} {
		if !strings.Contains(s, want) {
			t.Errorf("le résumé doit contenir %q : %s", want, s)
		}
	}
}

func TestRunWithoutARestoreStillGeneratesItsOwn(t *testing.T) {
	api := newFakeAPI()
	rep, err := Run(context.Background(), api, Options{Topology: twoHostTopology(t), Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Restored || rep.AdminEmail != DefaultAdminEmail || strings.Contains(rep.Summary(), "reconstruit") {
		t.Errorf("une installation neuve n'est pas une reconstruction : %+v", rep)
	}
	if _, ok := envOf(t, api.bodies["goproxify-admin"])["GPX_PAIRING_SECRET_PREVIOUS"]; ok {
		t.Error("pas de secret précédent sans sauvegarde")
	}
}

// envOf rend les variables d'environnement du corps de création d'un conteneur.
func envOf(t *testing.T, body map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	list, _ := body["Env"].([]any)
	for _, e := range list {
		k, v, _ := strings.Cut(e.(string), "=")
		out[k] = v
	}
	if len(out) == 0 {
		t.Fatal("aucune variable d'environnement dans le corps de création")
	}
	return out
}
