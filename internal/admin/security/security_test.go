// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestSLAConfigDaysFor(t *testing.T) {
	cfg := DefaultSLAConfig()
	if cfg != (SLAConfig{CriticalDays: 7, HighDays: 14, MediumDays: 30, LowDays: 90}) {
		t.Fatalf("DefaultSLAConfig() = %+v, attendu 7/14/30/90", cfg)
	}
	cases := []struct {
		cvss float64
		want int
	}{
		{10.0, 7}, {9.0, 7},
		{8.9, 14}, {7.0, 14},
		{6.9, 30}, {4.0, 30},
		{3.9, 90}, {0, 90},
	}
	for _, c := range cases {
		if got := cfg.DaysFor(c.cvss); got != c.want {
			t.Errorf("DaysFor(%v) = %d, attendu %d", c.cvss, got, c.want)
		}
	}
}
