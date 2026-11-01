// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"testing"

	"github.com/vincamok/goproxify/internal/edge/threat"
)

func TestAddSeasonalMergesRoutesAcrossGateways(t *testing.T) {
	dst := emptyReport()
	a := threat.SimSeasonal{Mode: "block", Routes: []threat.SimSeasonalRoute{{Route: "app", Warm: true, Warnings: 1, Probables: 1, AlertSeconds: 60, HardenedRequests: 10, HardenedServed: 4}}}
	b := threat.SimSeasonal{Mode: "block", Routes: []threat.SimSeasonalRoute{
		{Route: "app", Warm: false, Warnings: 2, AlertSeconds: 30, HardenedRequests: 5, HardenedServed: 1},
		{Route: "api", Warm: true},
	}}
	addReport(&dst, threat.SimReport{Seasonal: &a, ByReason: map[string]int{}})
	addReport(&dst, threat.SimReport{Seasonal: &b, ByReason: map[string]int{}})
	if dst.Seasonal == nil || len(dst.Seasonal.Routes) != 2 {
		t.Fatalf("deux routes attendues : %+v", dst.Seasonal)
	}
	app := dst.Seasonal.Routes[0]
	if app.Route != "app" || app.Warm || app.Warnings != 3 || app.Probables != 1 || app.AlertSeconds != 90 || app.HardenedRequests != 15 || app.HardenedServed != 5 {
		t.Fatalf("les compteurs s'additionnent, la route n'est jugeable que si chaque passerelle l'a jugée : %+v", app)
	}
}
