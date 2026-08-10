// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import "testing"

func TestStatusRange(t *testing.T) {
	cases := []struct {
		in      string
		lo, hi  int
		wantOK  bool
	}{
		{"5xx", 500, 600, true},
		{"2xx", 200, 300, true},
		{"5", 500, 600, true},
		{"502", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		lo, hi, ok := statusRange(c.in)
		if ok != c.wantOK || lo != c.lo || hi != c.hi {
			t.Fatalf("statusRange(%q) = %d,%d,%v ; want %d,%d,%v", c.in, lo, hi, ok, c.lo, c.hi, c.wantOK)
		}
	}
}

func TestStatusMatches(t *testing.T) {
	if !statusMatches(502, "5xx") {
		t.Fatal("502 should match 5xx")
	}
	if !statusMatches(502, "502") {
		t.Fatal("502 should match 502")
	}
	if statusMatches(404, "5xx") {
		t.Fatal("404 should not match 5xx")
	}
}
