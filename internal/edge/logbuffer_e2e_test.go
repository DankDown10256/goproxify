// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/edgews"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func fastAcks(t *testing.T) {
	t.Helper()
	prev := edgews.AckDelay
	edgews.AckDelay = 50 * time.Millisecond
	t.Cleanup(func() { edgews.AckDelay = prev })
}

// gatewayLines compte les lignes d'accès que la passerelle garde dans sa base.
func gatewayLines(t *testing.T, gw *streamGateway) int {
	t.Helper()
	page, err := gw.logStore.Search(t.Context(), logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Limit: 5000})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Rows)
}

// Une fois que l'Admin a rangé les lignes et les a acquittées, la base de la passerelle n'est plus qu'un tampon : la
// période acquittée est supprimée après le délai court, et les lignes restent dans le volume de logs de l'Admin.
func TestGatewayBufferPurgesWhatTheAdminAcknowledged(t *testing.T) {
	fastAcks(t)
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	gw.mixed("tampon", 40)
	gw.logStore.Flush()
	if gw.logStore.BufferActive() {
		t.Fatal("le tampon est actif avant tout acquittement")
	}
	admin.start(t, gw.url)
	waitUntil(t, "les 40 lignes dans le volume de logs", func() bool { return admin.vaultCount(t, streamEdgeID, "/tampon") == 40 })
	waitUntil(t, "l'acquittement de l'Admin", func() bool {
		return gw.logStore.BufferActive() && gw.logStore.Acked("access") == gw.logStore.LastID(logstore.KindAccess) &&
			gw.logStore.Acked("minute") > 0
	})

	// Dans une semaine la période n'est pas finie depuis assez longtemps ; dans trois semaines, si.
	gw.logStore.Purge(time.Now().Add(2 * 24 * time.Hour))
	if n := gatewayLines(t, gw); n != 40 {
		t.Fatalf("%d lignes, attendu 40 : la période n'est pas finie depuis 7 jours", n)
	}
	gw.logStore.Purge(time.Now().Add(20 * 24 * time.Hour))
	if n := gatewayLines(t, gw); n != 0 {
		t.Fatalf("%d lignes dans le tampon, attendu 0 : tout est acquitté", n)
	}
	if n := admin.vaultCount(t, streamEdgeID, "/tampon"); n != 40 {
		t.Fatalf("%d lignes dans le volume de logs, attendu 40 : la purge de la passerelle ne les touche pas", n)
	}
}

// Un Admin qui n'a pas de volume de logs n'acquitte rien : la passerelle garde sa rétention ordinaire.
func TestGatewayKeepsEverythingWhenTheAdminHasNoLogVolume(t *testing.T) {
	fastAcks(t)
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	admin.vault = nil
	t.Cleanup(admin.stop)
	gw.addAccess("sans-volume", 30, true)
	admin.start(t, gw.url)
	waitUntil(t, "les lignes dans la table de l'Admin", func() bool { return admin.count(t, `path LIKE '/sans-volume/%'`) == 30 })
	time.Sleep(500 * time.Millisecond)
	if gw.logStore.BufferActive() {
		t.Fatal("le tampon est actif alors que l'Admin n'a pas rangé les lignes")
	}
	gw.logStore.Purge(time.Now().Add(20 * 24 * time.Hour))
	if n := gatewayLines(t, gw); n != 30 {
		t.Fatalf("%d lignes, attendu 30 : rien n'est acquitté", n)
	}
}

// Un Admin dont le volume de logs a été remplacé annonce des positions plus basses à sa connexion : la passerelle cesse de
// croire acquitté ce que l'Admin n'a plus, et le lui renvoie.
func TestAReplacedAdminLogVolumeLowersTheAckAndGetsTheLinesAgain(t *testing.T) {
	fastAcks(t)
	root := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(root, "gw"))
	gw.addAccess("histoire", 25, false)
	first := newAdminSideWithVault(t, filepath.Join(root, "admin1"), filepath.Join(root, "volume-1"))
	first.start(t, gw.url)
	waitUntil(t, "le premier volume", func() bool { return first.vaultCount(t, streamEdgeID, "/histoire") == 25 })
	waitUntil(t, "l'acquittement", func() bool { return gw.logStore.Acked("access") == gw.logStore.LastID(logstore.KindAccess) })
	first.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })

	// Un Admin neuf, sur un volume de logs neuf.
	second := newAdminSideWithVault(t, filepath.Join(root, "admin2"), filepath.Join(root, "volume-2"))
	t.Cleanup(second.stop)
	second.start(t, gw.url)
	waitUntil(t, "les lignes renvoyées au volume neuf", func() bool { return second.vaultCount(t, streamEdgeID, "/histoire") == 25 })
	last := gw.logStore.LastID(logstore.KindAccess)
	gw.logStore.Purge(time.Now().Add(20 * 24 * time.Hour))
	waitUntil(t, "la position acquittée à nouveau à la fin", func() bool {
		return gw.logStore.Acked("access") == last
	})
}
