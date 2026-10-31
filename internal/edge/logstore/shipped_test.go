// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func shipped(seq int64, ts time.Time, ip string) ShippedRow {
	return ShippedRow{Seq: seq, Entry: access(ts, ip)}
}

func openDir(t *testing.T, dir string, mutate ...func(*Options)) *Store {
	t.Helper()
	opts := Options{Dir: dir}
	for _, m := range mutate {
		m(&opts)
	}
	s, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Les lignes reçues d'une passerelle sont les lignes « propres » du store : les lectures n'ont rien de particulier à faire.
func TestShippedRowsAreReadLikeOwnRows(t *testing.T) {
	s := openTest(t)
	rows := []ShippedRow{
		shipped(10, at("2026-10-21T10:00:00Z"), "203.0.113.1"),
		shipped(11, at("2026-10-21T10:00:01Z"), "203.0.113.2"),
		shipped(12, at("2026-10-21T10:00:02Z"), "203.0.113.3"),
	}
	n, err := s.AddShipped(KindAccess, rows, 12)
	if err != nil || n != 3 {
		t.Fatalf("AddShipped = %d, %v", n, err)
	}
	if got := countGroup(t, s, Query{Kinds: []Kind{KindAccess}}); got != 3 {
		t.Fatalf("lecture ordinaire = %d lignes, attendu 3", got)
	}
	if c, err := s.ShipCursor(KindAccess); err != nil || c != 12 {
		t.Fatalf("position = %d, %v, attendu 12", c, err)
	}
	if c, _ := s.ShipCursor(KindSystem); c != 0 {
		t.Fatalf("la position d'un autre type a bougé : %d", c)
	}
}

// Un lot rejoué après une coupure n'écrit rien deux fois, et la position ne recule pas.
func TestShippedIsIdempotent(t *testing.T) {
	s := openTest(t)
	rows := []ShippedRow{
		shipped(1, at("2026-10-21T10:00:00Z"), "203.0.113.1"),
		shipped(2, at("2026-10-21T10:00:01Z"), "203.0.113.2"),
	}
	if _, err := s.AddShipped(KindAccess, rows, 2); err != nil {
		t.Fatal(err)
	}
	n, err := s.AddShipped(KindAccess, rows, 2)
	if err != nil || n != 0 {
		t.Fatalf("rejeu = %d lignes nouvelles, %v, attendu 0", n, err)
	}
	more := append(rows, shipped(3, at("2026-10-21T10:00:02Z"), "203.0.113.3"))
	if n, err := s.AddShipped(KindAccess, more, 3); err != nil || n != 1 {
		t.Fatalf("chevauchement = %d lignes nouvelles, %v, attendu 1", n, err)
	}
	if got := countGroup(t, s, Query{Kinds: []Kind{KindAccess}}); got != 3 {
		t.Fatalf("%d lignes, attendu 3 sans doublon", got)
	}
	if _, err := s.AddShipped(KindAccess, nil, 1); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.ShipCursor(KindAccess); c != 3 {
		t.Fatalf("la position a reculé : %d", c)
	}
}

// La position est écrite avec les lignes : rouvrir le dossier la retrouve, même quand un lot a touché deux semaines.
func TestShippedCursorSurvivesReopenAcrossPeriods(t *testing.T) {
	dir := t.TempDir()
	s := openDir(t, dir)
	rows := []ShippedRow{
		shipped(1, at("2026-10-14T10:00:00Z"), "203.0.113.1"), // semaine précédente
		shipped(2, at("2026-10-21T10:00:00Z"), "203.0.113.2"),
	}
	if _, err := s.AddShipped(KindAccess, rows, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openDir(t, dir)
	if c, err := s.ShipCursor(KindAccess); err != nil || c != 2 {
		t.Fatalf("position après réouverture = %d, %v, attendu 2", c, err)
	}
	if got := countGroup(t, s, Query{Kinds: []Kind{KindAccess}}); got != 2 {
		t.Fatalf("%d lignes, attendu 2", got)
	}
}

// Une base de passerelle remplacée repart de 1 : après la remise à zéro, ses lignes sont reçues (même numéro, autre date)
// et la position remise à zéro l'emporte sur celle, plus haute, d'un fichier plus ancien — y compris après réouverture.
func TestShippedResetAcceptsTheLinesOfAReplacedBase(t *testing.T) {
	dir := t.TempDir()
	s := openDir(t, dir)
	old := []ShippedRow{shipped(5, at("2026-10-14T10:00:00Z"), "203.0.113.1")}
	if _, err := s.AddShipped(KindAccess, old, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetShipCursor(KindAccess); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.ShipCursor(KindAccess); c != 0 {
		t.Fatalf("position après remise à zéro = %d", c)
	}
	fresh := []ShippedRow{shipped(5, at("2026-10-21T10:00:00Z"), "203.0.113.2")}
	if n, err := s.AddShipped(KindAccess, fresh, 5); err != nil || n != 1 {
		t.Fatalf("ligne de la nouvelle base = %d, %v, attendu 1", n, err)
	}
	if got := countGroup(t, s, Query{Kinds: []Kind{KindAccess}}); got != 2 {
		t.Fatalf("%d lignes, attendu 2 (l'ancienne base est gardée)", got)
	}

	if err := s.ResetShipCursor(KindAccess); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openDir(t, dir)
	if c, _ := s.ShipCursor(KindAccess); c != 0 {
		t.Fatalf("la remise à zéro n'a pas survécu à la réouverture : position %d", c)
	}
}

// L'IP réelle d'une passerelle en pseudonymisation est rechiffrée avec la clé de ce store, qui la révèle.
func TestShippedRealIPIsEncryptedWithTheStoreKey(t *testing.T) {
	k := key(t)
	s := openTest(t, func(o *Options) { o.IPKey = k })
	e := access(at("2026-10-21T10:00:00Z"), "203.0.113.0")
	e.IPTruncated, e.RealIP = true, "203.0.113.77"
	if _, err := s.AddShipped(KindAccess, []ShippedRow{{Seq: 1, Entry: e}}, 1); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ReadAfter(KindAccess, 0, 10)
	if err != nil || len(rows) != 1 || !rows[0].Pseudonymized {
		t.Fatalf("ReadAfter = %+v, %v", rows, err)
	}
	if rows[0].IP != "203.0.113.0" {
		t.Fatalf("l'IP lisible n'est pas la tronquée : %q", rows[0].IP)
	}
	ip, err := s.RevealIP(KindAccess, rows[0].ID)
	if err != nil || ip != "203.0.113.77" {
		t.Fatalf("RevealIP = %q, %v", ip, err)
	}
}

// Un store ouvert en lecture seule ne reçoit rien.
func TestShippedRefusesAReadOnlyStore(t *testing.T) {
	dir := t.TempDir()
	openDir(t, dir) // crée le dossier
	ro := openDir(t, dir, func(o *Options) { o.ReadOnly = true })
	if _, err := ro.AddShipped(KindAccess, []ShippedRow{shipped(1, at("2026-10-21T10:00:00Z"), "203.0.113.1")}, 1); err == nil {
		t.Fatal("un store en lecture seule a reçu des lignes")
	}
}

func countGroup(t *testing.T, s *Store, q Query) int {
	t.Helper()
	q.Limit = 100
	page, err := s.Search(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Rows)
}

// Un fichier de période écrit avant la réception des lignes d'une passerelle n'a pas les colonnes origin : il est complété
// à l'ouverture, ses lignes restent lisibles, et il reçoit des lignes d'une passerelle.
func TestOpenCompletesAPeriodFileWrittenBeforeShippedRows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "203.0.113.1"))
	s.Flush()
	_ = s.Close()

	path := filepath.Join(dir, KindAccess.fileName(KindAccess.periodStart(at("2026-10-21T10:00:00Z"))))
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP INDEX idx_entries_shipped`, `ALTER TABLE entries DROP COLUMN origin`, `ALTER TABLE entries DROP COLUMN origin_id`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	_ = db.Close()

	s, err = Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.ReadAfter(KindAccess, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("ReadAfter après complétion = %d lignes, %v", len(rows), err)
	}
	if n, err := s.AddShipped(KindAccess, []ShippedRow{shipped(1, at("2026-10-21T10:00:05Z"), "203.0.113.2")}, 1); err != nil || n != 1 {
		t.Fatalf("AddShipped sur l'ancien fichier = %d, %v", n, err)
	}
}

// Les lignes qu'une ancienne version a répliquées d'un pair (origin non vide) ne se lisent plus : elles restent dans leur
// fichier jusqu'à sa suppression, sans compter pour la passerelle.
func TestRowsReplicatedByAnOlderVersionAreIgnored(t *testing.T) {
	s := openTest(t)
	s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "203.0.113.1"))
	s.Flush()
	path := filepath.Join(s.opts.Dir, KindAccess.fileName(KindAccess.periodStart(at("2026-10-21T10:00:00Z"))))
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO entries (ts, level, origin, origin_id) VALUES ('2026-10-21T10:00:01.000000Z', 'info', 'backup', 7)`); err != nil {
		t.Fatal(err)
	}
	if got := countGroup(t, s, Query{Kinds: []Kind{KindAccess}}); got != 1 {
		t.Fatalf("%d lignes lues, attendu 1 (la copie d'un pair est ignorée)", got)
	}
	if rows, err := s.ReadAfter(KindAccess, 0, 10); err != nil || len(rows) != 1 {
		t.Fatalf("ReadAfter = %d lignes, %v", len(rows), err)
	}
}
