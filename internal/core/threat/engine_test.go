// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestEngine() *Engine {
	e := New(slog.Default(), nil)
	return e
}

func TestCheckDisabled(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{Enabled: false})
	r := httptest.NewRequest("GET", "/", nil)
	blocked, reason := e.Check(r, "1.2.3.4")
	if blocked || reason != "" {
		t.Fatal("disabled engine should not block")
	}
}

func TestCheckWhitelistedIP(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		CustomLists: CustomListsConfig{
			IPs: []string{"10.0.0.1"},
		},
		Whitelist: Whitelist{IPs: []string{"10.0.0.1"}},
	})
	r := httptest.NewRequest("GET", "/", nil)
	blocked, _ := e.Check(r, "10.0.0.1")
	if blocked {
		t.Fatal("whitelisted IP should not be blocked")
	}
}

func TestCheckCustomIP(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "block",
		CustomLists: CustomListsConfig{
			IPs: []string{"192.168.1.100"},
		},
	})
	r := httptest.NewRequest("GET", "/", nil)
	blocked, reason := e.Check(r, "192.168.1.100")
	if !blocked {
		t.Fatal("custom IP should be blocked")
	}
	if reason == "" {
		t.Fatal("reason should not be empty")
	}
}

func TestCheckCustomUA(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "block",
		CustomLists: CustomListsConfig{
			UAs: []string{"evilbot"},
		},
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 EvilBot/2.0")
	blocked, _ := e.Check(r, "1.2.3.4")
	if !blocked {
		t.Fatal("custom UA should be blocked")
	}
}

func TestCheckCustomPath(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "block",
		CustomLists: CustomListsConfig{
			Paths: []string{"/admin/secret"},
		},
	})
	r := httptest.NewRequest("GET", "/admin/secret/config", nil)
	blocked, _ := e.Check(r, "1.2.3.4")
	if !blocked {
		t.Fatal("custom path prefix should be blocked")
	}
}

func TestDetectMode(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "detect",
		CustomLists: CustomListsConfig{
			IPs: []string{"5.5.5.5"},
		},
	})
	r := httptest.NewRequest("GET", "/", nil)
	blocked, reason := e.Check(r, "5.5.5.5")
	if blocked {
		t.Fatal("detect mode should not block")
	}
	if reason == "" {
		t.Fatal("detect mode should still return a reason")
	}
}

func TestScoreThreshold(t *testing.T) {
	e := newTestEngine()
	// UA score=3, path score=2, total=5. Threshold=6 → should NOT block.
	e.UpdateConfig(Config{
		Enabled:        true,
		Mode:           "block",
		ScoreThreshold: 6,
		CustomLists: CustomListsConfig{
			UAs:   []string{"badbot"},
			Paths: []string{"/suspicious"},
		},
	})
	r := httptest.NewRequest("GET", "/suspicious/path", nil)
	r.Header.Set("User-Agent", "badbot/1.0")
	blocked, reason := e.Check(r, "1.2.3.4")
	if blocked {
		t.Fatalf("score 5 < threshold 6 should not block, reason=%s", reason)
	}

	// Now lower threshold to 5 → should block.
	e.UpdateConfig(Config{
		Enabled:        true,
		Mode:           "block",
		ScoreThreshold: 5,
		CustomLists: CustomListsConfig{
			UAs:   []string{"badbot"},
			Paths: []string{"/suspicious"},
		},
	})
	r2 := httptest.NewRequest("GET", "/suspicious/path", nil)
	r2.Header.Set("User-Agent", "badbot/1.0")
	blocked2, _ := e.Check(r2, "1.2.3.4")
	if !blocked2 {
		t.Fatal("score 5 >= threshold 5 should block")
	}
}

func TestRecordStatusDetectMode(t *testing.T) {
	var banned bool
	e := New(slog.Default(), func(ip, reason string, expires time.Time) {
		banned = true
	})
	e.UpdateConfig(Config{
		Enabled:        true,
		Mode:           "detect",
		ErrorThreshold: 2,
		ErrorWindow:    Duration{10 * time.Second},
		BanDuration:    Duration{time.Minute},
	})
	e.RecordStatus("1.2.3.4", 404)
	e.RecordStatus("1.2.3.4", 404)
	if banned {
		t.Fatal("detect mode: banFn should not be called")
	}
}

func TestWithSignal(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r = WithSignal(r, "threat: custom_ip")
	if got := SignalFromContext(r.Context()); got != "threat: custom_ip" {
		t.Fatalf("expected signal in context, got %q", got)
	}
}

func TestMergeRouteWhitelists(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "block",
		Lists:   ListsConfig{IPEnabled: true},
	})
	// Sans whitelist : une IP custom blacklistée est bloquée.
	// On simule juste que MergeRouteWhitelists ajoute l'IP à la whitelist.
	e.MergeRouteWhitelists([]string{"10.0.0.1"})

	r := httptest.NewRequest("GET", "/", nil)
	blocked, _ := e.Check(r, "10.0.0.1")
	if blocked {
		t.Fatal("IP ajoutée via MergeRouteWhitelists ne doit pas être bloquée")
	}

	// Appel multiple : pas de déduplons la config manuelle.
	e.UpdateConfig(Config{
		Enabled:   true,
		Mode:      "block",
		Whitelist: Whitelist{IPs: []string{"172.16.0.1"}},
	})
	e.MergeRouteWhitelists([]string{"10.0.0.2", "172.16.0.1"})
	if len(e.cfg.Whitelist.IPs) != 2 {
		t.Fatalf("dédup attendu: got %v", e.cfg.Whitelist.IPs)
	}
}

func TestCustomCIDR(t *testing.T) {
	e := newTestEngine()
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "block",
		CustomLists: CustomListsConfig{
			IPs: []string{"192.168.0.0/24"},
		},
	})
	r := httptest.NewRequest("GET", "/", nil)
	blocked, _ := e.Check(r, "192.168.0.55")
	if !blocked {
		t.Fatal("IP within custom CIDR should be blocked")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	blocked2, _ := e.Check(r2, "192.168.1.55")
	if blocked2 {
		t.Fatal("IP outside custom CIDR should not be blocked")
	}
}
