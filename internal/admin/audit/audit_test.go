package audit

import "testing"

func TestParseTimestamp(t *testing.T) {
	for _, in := range []string{
		"2026-09-24 09:21:21",
		"2026-09-24T09:21:21Z",
		"2026-09-24T09:21:21.123456Z",
		"2026-09-24 09:21:21+00:00",
		"2026-09-24 09:21:21 +0000 UTC",
	} {
		got := parseTimestamp(in)
		if got.IsZero() || got.Year() != 2026 || got.Hour() != 9 {
			t.Errorf("%q -> %v", in, got)
		}
	}
	if !parseTimestamp("n/a").IsZero() {
		t.Error("format invalide doit donner le zéro")
	}
}
