// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"testing"
	"time"
)

const day = 24 * time.Hour

var monday = at("2026-10-05T00:00:00Z") // un lundi : début d'une période d'accès

func bufferStore(t *testing.T, dir string) *Store {
	t.Helper()
	s := openDir(t, dir)
	s.SetBuffer(Buffer{Acked: 7 * day, Max: 30 * day})
	return s
}

func addAt(t *testing.T, s *Store, ts ...time.Time) {
	t.Helper()
	for _, x := range ts {
		s.Add(KindAccess, access(x, "203.0.113.1"))
	}
	s.Flush()
}

// ackAll acquitte tout ce que contient la base, cumuls et compteurs compris.
func ackAll(s *Store) {
	s.SetAck("access", s.LastID(KindAccess))
	s.SetAck("system", s.LastID(KindSystem))
	s.SetAck("minute", 1<<62)
	s.SetAck("iperr", 1<<62)
}

func countAll(t *testing.T, s *Store) int {
	t.Helper()
	return countGroup(t, s, Query{Kinds: []Kind{KindAccess}})
}

// Sans acquittement de l'Admin, la rétention ordinaire reste la règle : rien n'est supprimé plus tôt que d'habitude.
func TestBufferIsInactiveUntilTheAdminAcknowledges(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	addAt(t, s, monday.Add(day))
	if s.BufferActive() {
		t.Fatal("le tampon est actif sans acquittement")
	}
	s.Purge(monday.Add(60 * day))
	if n := countAll(t, s); n != 1 {
		t.Fatalf("%d lignes, attendu 1 : la rétention ordinaire (365 jours) s'applique", n)
	}
}

func TestBufferDropsAnAcknowledgedPeriodAfterTheShortDelay(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	addAt(t, s, monday.Add(day), monday.Add(2*day))
	ackAll(s)
	if !s.BufferActive() {
		t.Fatal("le tampon n'est pas actif après un acquittement")
	}
	// Période finie depuis moins de 7 jours : gardée.
	s.Purge(monday.Add(7*day + 6*day))
	if n := countAll(t, s); n != 2 {
		t.Fatalf("%d lignes, attendu 2 : la période est finie depuis moins de 7 jours", n)
	}
	// Finie depuis plus de 7 jours : supprimée.
	s.Purge(monday.Add(7*day + 8*day))
	if n := countAll(t, s); n != 0 {
		t.Fatalf("%d lignes, attendu 0 : la période est acquittée et finie depuis plus de 7 jours", n)
	}
}

// Une ligne que l'Admin n'a pas acquittée n'est pas supprimée avec sa période : elle attend la borne.
func TestBufferKeepsUnacknowledgedLinesUntilTheHardLimit(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	addAt(t, s, monday.Add(day), monday.Add(2*day))
	s.SetAck("system", 1) // le tampon est actif, mais rien d'acquitté pour les accès
	s.Purge(monday.Add(7*day + 20*day))
	if n := countAll(t, s); n != 2 {
		t.Fatalf("%d lignes, attendu 2 : non acquittées, avant la borne de 30 jours", n)
	}
	s.Purge(monday.Add(7*day + 31*day))
	if n := countAll(t, s); n != 0 {
		t.Fatalf("%d lignes, attendu 0 : la borne de 30 jours est passée", n)
	}
}

// Acquitter les lignes ne suffit pas : les cumuls par minute que l'Admin n'a pas reçus retiennent le fichier.
func TestBufferWaitsForTheMinuteTotalsToo(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	addAt(t, s, monday.Add(day))
	s.SetAck("access", s.LastID(KindAccess))
	s.SetAck("system", s.LastID(KindSystem))
	s.SetAck("minute", 0)
	s.SetAck("iperr", 1<<62)
	s.Purge(monday.Add(7*day + 10*day))
	if n := countAll(t, s); n != 1 {
		t.Fatalf("%d lignes, attendu 1 : les cumuls ne sont pas acquittés", n)
	}
	s.SetAck("minute", 1<<62)
	s.Purge(monday.Add(7*day + 10*day))
	if n := countAll(t, s); n != 0 {
		t.Fatalf("%d lignes, attendu 0 : tout est acquitté", n)
	}
}

// Dans la période à cheval sur la borne, les lignes plus vieilles sont supprimées une à une.
func TestBufferTrimsThePeriodStraddlingTheHardLimit(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	addAt(t, s, monday.Add(day), monday.Add(6*day))
	s.SetAck("system", 1)
	s.Purge(monday.Add(33 * day)) // borne = monday + 3 jours
	if n := countAll(t, s); n != 1 {
		t.Fatalf("%d lignes, attendu 1 (celle d'après la borne)", n)
	}
}

// Les positions acquittées survivent à un redémarrage ; une position peut reculer quand l'Admin le dit, jamais sur un
// simple acquittement.
func TestBufferAcksSurviveReopenAndOnlyAnExactSetCanLowerThem(t *testing.T) {
	dir := t.TempDir()
	s := bufferStore(t, dir)
	s.SetAck("access", 100)
	s.AdvanceAck("access", 50)
	if got := s.Acked("access"); got != 100 {
		t.Fatalf("un acquittement a reculé la position : %d", got)
	}
	s.AdvanceAck("access", 150)
	if got := s.Acked("access"); got != 150 {
		t.Fatalf("position = %d, attendu 150", got)
	}
	s.SetAck("access", 10) // volume de logs de l'Admin remplacé
	if got := s.Acked("access"); got != 10 {
		t.Fatalf("la remise de l'Admin n'a pas été suivie : %d", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = bufferStore(t, dir)
	if !s.BufferActive() || s.Acked("access") != 10 {
		t.Fatalf("après réouverture : actif=%v position=%d, attendu actif et 10", s.BufferActive(), s.Acked("access"))
	}
}

func TestOldestUnackedIsTheFirstLineAfterTheAck(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	first, second := monday.Add(day), monday.Add(9*day) // deux périodes
	addAt(t, s, first)
	s.SetAck("access", s.LastID(KindAccess)) // la première est acquittée
	addAt(t, s, second)
	if got := s.OldestUnacked(); !got.Equal(second) {
		t.Fatalf("plus ancienne ligne non acquittée = %v, attendu %v", got, second)
	}
	s.SetAck("access", s.LastID(KindAccess))
	s.SetAck("system", s.LastID(KindSystem))
	if got := s.OldestUnacked(); !got.IsZero() {
		t.Fatalf("tout est acquitté, reçu %v", got)
	}
}

// Le SIEM (ou tout consommateur en retard) prend pour repère la durée du tampon dès que l'Admin acquitte.
func TestEffectiveRetentionFollowsTheBuffer(t *testing.T) {
	s := bufferStore(t, t.TempDir())
	if got := s.EffectiveRetention(KindAccess); got != DefaultAccessRetention {
		t.Fatalf("sans acquittement : %v, attendu la rétention ordinaire", got)
	}
	s.SetAck("access", 1)
	if got := s.EffectiveRetention(KindAccess); got != 7*day {
		t.Fatalf("avec acquittement : %v, attendu 7 jours", got)
	}
}
