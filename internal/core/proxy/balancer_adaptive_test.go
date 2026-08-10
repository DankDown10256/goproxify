// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
	corews "github.com/vincamok/goproxify/internal/core/ws"
)

type fakeScorer map[string]float64

func (f fakeScorer) Score(ip string) float64 {
	v, ok := f[ip]
	if !ok {
		return -1
	}
	return v
}

func TestAdaptivePicksLowestScore(t *testing.T) {
	route := &router.Route{
		LB: router.LBAdaptive,
		Backends: []router.Backend{
			{URL: "http://10.0.0.1:80"},
			{URL: "http://10.0.0.2:80"},
		},
	}
	b := NewBalancer(route, fakeScorer{"10.0.0.1": 80, "10.0.0.2": 20})
	got := b.Next(nil)
	if got == nil || got.URL != "http://10.0.0.2:80" {
		t.Fatalf("got %#v, want 10.0.0.2", got)
	}
}

func TestAdaptivePartialScoresIgnoresUnknown(t *testing.T) {
	route := &router.Route{
		LB: router.LBAdaptive,
		Backends: []router.Backend{
			{URL: "http://10.0.0.1:80"},
			{URL: "http://10.0.0.2:80"},
		},
	}
	b := NewBalancer(route, fakeScorer{"10.0.0.2": 10})
	// 10.0.0.1 unknown — must still pick scored backend, not fall back to RR blindly
	counts := map[string]int{}
	for i := 0; i < 20; i++ {
		got := b.Next(&http.Request{})
		if got == nil {
			t.Fatal("nil backend")
		}
		counts[got.URL]++
	}
	if counts["http://10.0.0.2:80"] != 20 {
		t.Fatalf("counts = %v, want only 10.0.0.2", counts)
	}
}

func TestAgentMetricsStoreUpdateFromMetrics(t *testing.T) {
	s := NewAgentMetricsStore()
	s.UpdateFromMetrics(corews.AgentMetricsPayload{
		Containers: []corews.ContainerMetric{
			{IP: "10.1.0.5", CPUPct: 100, MemPct: 0, DiskIOPCT: 0}, // score 50
			{IP: "10.1.0.6", CPUPct: 0, MemPct: 0, DiskIOPCT: 0},   // score 0
		},
	})
	if s.Score("10.1.0.5") != 50 {
		t.Fatalf("score high = %v, want 50", s.Score("10.1.0.5"))
	}
	if s.Score("10.1.0.6") != 0 {
		t.Fatalf("score low = %v, want 0", s.Score("10.1.0.6"))
	}
	if s.Score("9.9.9.9") != -1 {
		t.Fatalf("unknown = %v, want -1", s.Score("9.9.9.9"))
	}
}

func TestCompositeScoreWeights(t *testing.T) {
	// 50*0.5 + 100*0.3 + 0*0.2 = 25+30 = 55
	got := compositeScore(50, 100, 0)
	if got != 55 {
		t.Fatalf("composite = %v, want 55", got)
	}
}
