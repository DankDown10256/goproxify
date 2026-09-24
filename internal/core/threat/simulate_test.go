// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestSimulate_CustomPathBlocksAndBans(t *testing.T) {
	cfg := Config{CustomLists: CustomListsConfig{Paths: []string{"/wp-admin"}}, BanDuration: Duration{time.Hour}}
	events := []SimEvent{
		{Time: t0, IP: "1.1.1.1", Path: "/wp-admin/x", Status: 404},
		{Time: t0.Add(time.Second), IP: "1.1.1.1", Path: "/home", Status: 200},
		{Time: t0.Add(2 * time.Second), IP: "2.2.2.2", Path: "/home", Status: 200},
	}
	r := Simulate(cfg, events)
	if r.Blocked != 2 || r.BlockedByBan != 1 || r.BlockedIPs != 1 {
		t.Fatalf("blocked=%d byBan=%d ips=%d", r.Blocked, r.BlockedByBan, r.BlockedIPs)
	}
	if r.LegitBlocked != 1 || len(r.Bans) != 1 {
		t.Fatalf("legit=%d bans=%d", r.LegitBlocked, len(r.Bans))
	}
}

func TestSimulate_BanExpires(t *testing.T) {
	cfg := Config{CustomLists: CustomListsConfig{Paths: []string{"/bad"}}, BanDuration: Duration{time.Minute}}
	events := []SimEvent{
		{Time: t0, IP: "1.1.1.1", Path: "/bad", Status: 404},
		{Time: t0.Add(2 * time.Minute), IP: "1.1.1.1", Path: "/ok", Status: 200},
	}
	if r := Simulate(cfg, events); r.Blocked != 1 {
		t.Fatalf("ban should have expired, blocked=%d", r.Blocked)
	}
}

func TestSimulate_RateUsesEventClock(t *testing.T) {
	cfg := Config{RateLimit: 5}
	var fast, slow []SimEvent
	for i := 0; i < 50; i++ {
		fast = append(fast, SimEvent{Time: t0.Add(time.Duration(i) * time.Millisecond), IP: "3.3.3.3", Path: "/", Status: 200})
		slow = append(slow, SimEvent{Time: t0.Add(time.Duration(i) * time.Second), IP: "3.3.3.3", Path: "/", Status: 200})
	}
	if r := Simulate(cfg, fast); r.Blocked == 0 || r.ByReason["threat: rate"] == 0 {
		t.Fatalf("burst should trigger rate: %+v", r)
	}
	if r := Simulate(cfg, slow); r.Blocked != 0 {
		t.Fatalf("1 req/s under limit 5 must pass, blocked=%d", r.Blocked)
	}
}

func TestSimulate_ErrorThresholdBans(t *testing.T) {
	cfg := Config{ErrorThreshold: 3, ErrorWindow: Duration{time.Minute}}
	var events []SimEvent
	for i := 0; i < 5; i++ {
		events = append(events, SimEvent{Time: t0.Add(time.Duration(i) * time.Second), IP: "4.4.4.4", Path: "/x", Status: 404})
	}
	r := Simulate(cfg, events)
	if len(r.Bans) != 1 || r.BlockedByBan != 2 {
		t.Fatalf("bans=%d byBan=%d", len(r.Bans), r.BlockedByBan)
	}
}

func TestSimulate_WhitelistExempts(t *testing.T) {
	cfg := Config{
		CustomLists: CustomListsConfig{Paths: []string{"/admin"}},
		Whitelist:   Whitelist{IPs: []string{"10.0.0.0/8"}},
	}
	r := Simulate(cfg, []SimEvent{{Time: t0, IP: "10.1.2.3", Path: "/admin", Status: 200}})
	if r.Blocked != 0 {
		t.Fatalf("whitelisted IP blocked")
	}
}

func TestSimulate_UnsortedInputAndNoProdMetrics(t *testing.T) {
	cfg := Config{RateLimit: 5}
	events := []SimEvent{
		{Time: t0.Add(2 * time.Second), IP: "5.5.5.5", Path: "/", Status: 200},
		{Time: t0, IP: "5.5.5.5", Path: "/", Status: 200},
	}
	if r := Simulate(cfg, events); r.Events != 2 || r.Blocked != 0 {
		t.Fatalf("%+v", r)
	}
}
