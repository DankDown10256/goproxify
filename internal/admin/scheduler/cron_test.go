// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"testing"
	"time"
)

func TestParseExprInvalid(t *testing.T) {
	cases := []string{"", "* * *", "60 * * * *", "* 24 * * *", "* * 32 * *", "* * * 13 *", "* * * * 7", "a * * * *"}
	for _, c := range cases {
		if _, err := ParseExpr(c); err == nil {
			t.Errorf("ParseExpr(%q) : erreur attendue, aucune reçue", c)
		}
	}
}

func TestMatchesEveryDay(t *testing.T) {
	e, err := ParseExpr("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	yes := time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC)
	no := time.Date(2026, 1, 15, 3, 1, 0, 0, time.UTC)
	if !e.Matches(yes) {
		t.Errorf("attendu match pour %v", yes)
	}
	if e.Matches(no) {
		t.Errorf("match inattendu pour %v", no)
	}
}

func TestMatchesStep(t *testing.T) {
	e, err := ParseExpr("*/15 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []int{0, 15, 30, 45} {
		ts := time.Date(2026, 1, 1, 10, m, 0, 0, time.UTC)
		if !e.Matches(ts) {
			t.Errorf("attendu match à la minute %d", m)
		}
	}
	if e.Matches(time.Date(2026, 1, 1, 10, 20, 0, 0, time.UTC)) {
		t.Error("match inattendu à la minute 20")
	}
}

func TestMatchesWeekday(t *testing.T) {
	e, err := ParseExpr("0 8 * * 1") // lundi 08:00
	if err != nil {
		t.Fatal(err)
	}
	monday := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC) // un lundi
	if !e.Matches(monday) {
		t.Errorf("attendu match un lundi : %v (%v)", monday, monday.Weekday())
	}
	tuesday := monday.AddDate(0, 0, 1)
	if e.Matches(tuesday) {
		t.Errorf("match inattendu un mardi : %v", tuesday)
	}
}

// Quand jour-du-mois et jour-de-semaine sont tous deux restreints, cron les
// combine en OR, pas en AND.
func TestMatchesDomDowOR(t *testing.T) {
	e, err := ParseExpr("0 0 1 * 1") // le 1er du mois OU chaque lundi
	if err != nil {
		t.Fatal(err)
	}
	firstOfMonthNotMonday := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if firstOfMonthNotMonday.Weekday() == time.Monday {
		t.Fatal("cas de test invalide : ajuster la date")
	}
	if !e.Matches(firstOfMonthNotMonday) {
		t.Errorf("attendu match (jour du mois) pour %v", firstOfMonthNotMonday)
	}
}

func TestMatchesRangeAndList(t *testing.T) {
	e, err := ParseExpr("0 9-17 * * 1,3,5")
	if err != nil {
		t.Fatal(err)
	}
	monday9 := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)
	if !e.Matches(monday9) {
		t.Error("attendu match lundi 09:00")
	}
	if e.Matches(monday9.Add(30 * time.Minute)) {
		t.Error("match inattendu à 09:30 (minute non listée)")
	}
	tuesday9 := monday9.AddDate(0, 0, 1)
	if e.Matches(tuesday9) {
		t.Error("match inattendu un mardi (hors liste 1,3,5)")
	}
}
