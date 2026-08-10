// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"testing"
	"time"
)

func TestCronExprFrequencies(t *testing.T) {
	cases := []struct {
		name string
		sch  Schedule
		want string
	}{
		{"daily", Schedule{Frequency: FreqDaily, Hour: 3, Minute: 0}, "0 3 * * *"},
		{"weekly sunday", Schedule{Frequency: FreqWeekly, Hour: 2, Minute: 0, Weekday: 0}, "0 2 * * 0"},
		{"monthly", Schedule{Frequency: FreqMonthly, Hour: 4, Minute: 15, MonthDay: 1}, "15 4 1 * *"},
		{"yearly", Schedule{Frequency: FreqYearly, Hour: 5, Minute: 0, MonthDay: 1, Month: 1}, "0 5 1 1 *"},
		{"custom", Schedule{Frequency: FreqCustom, Cron: "30 */6 * * *"}, "30 */6 * * *"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.sch.CronExpr()
			if err != nil {
				t.Fatalf("CronExpr: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestCronExprRejectsInvalidMonthDay(t *testing.T) {
	sch := Schedule{Frequency: FreqMonthly, Hour: 3, Minute: 0, MonthDay: 31}
	if _, err := sch.CronExpr(); err == nil {
		t.Fatal("expected error for day 31")
	}
}

func TestNextCronDow7IsSunday(t *testing.T) {
	// Dimanche 2026-08-09 01:00 — prochaine "0 2 * * 7" = dimanche 2h
	from := time.Date(2026, 8, 9, 1, 0, 0, 0, time.Local)
	next, err := nextCron("0 2 * * 7", from)
	if err != nil {
		t.Fatal(err)
	}
	if next.Weekday() != time.Sunday || next.Hour() != 2 || next.Minute() != 0 {
		t.Fatalf("unexpected next=%v weekday=%v", next, next.Weekday())
	}
}

func TestParseCronToReadable(t *testing.T) {
	h, m, freq, wd, dom, mon := parseCronToReadable("0 3 * * *")
	if h != 3 || m != 0 || freq != FreqDaily {
		t.Fatalf("daily: h=%d m=%d freq=%s", h, m, freq)
	}
	h, m, freq, wd, dom, mon = parseCronToReadable("0 2 * * 0")
	if freq != FreqWeekly || wd != 0 || h != 2 {
		t.Fatalf("weekly: freq=%s wd=%d h=%d", freq, wd, h)
	}
	h, m, freq, wd, dom, mon = parseCronToReadable("0 4 1 * *")
	if freq != FreqMonthly || dom != 1 {
		t.Fatalf("monthly: freq=%s dom=%d", freq, dom)
	}
	h, m, freq, wd, dom, mon = parseCronToReadable("0 5 1 1 *")
	if freq != FreqYearly || dom != 1 || mon != 1 {
		t.Fatalf("yearly: freq=%s dom=%d mon=%d", freq, dom, mon)
	}
}

func TestNormalizeSchedulesCapsAtMax(t *testing.T) {
	in := make([]Schedule, MaxSchedules+3)
	for i := range in {
		in[i] = Schedule{Name: "x", Frequency: FreqDaily}
	}
	out := normalizeSchedules(in)
	if len(out) != MaxSchedules {
		t.Fatalf("got %d want %d", len(out), MaxSchedules)
	}
	for _, sch := range out {
		if sch.ID == "" {
			t.Fatal("expected id assigned")
		}
	}
}

func TestSlugify(t *testing.T) {
	if got := slugify("Quotidienne"); got != "quotidienne" {
		t.Fatalf("got %q", got)
	}
	if got := slugify("  Mensuelle ! "); got != "mensuelle" {
		t.Fatalf("got %q", got)
	}
}
