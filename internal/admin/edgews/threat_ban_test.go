// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestHandleThreatBanKeepsTheBanSource(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager("", db, slog.Default())
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	for _, p := range []edgeWS.ThreatBanPayload{
		{IP: "203.0.113.1", Reason: "threat: rate", ExpiresAt: exp, NodeName: "paris"},
		{IP: "203.0.113.2", Reason: "coraza: trop de refus", ExpiresAt: exp, NodeName: "paris", Source: "plugin:coraza"},
		{IP: "203.0.113.3", Reason: "forgé", ExpiresAt: exp, NodeName: "paris", Source: "fail2ban"},
		{IP: "203.0.113.4", Reason: "vide", ExpiresAt: exp, NodeName: "paris", Source: "plugin:"},
	} {
		raw, _ := json.Marshal(p)
		m.handleThreatBan(raw)
	}

	want := map[string]string{
		"203.0.113.1": "threat",
		"203.0.113.2": "plugin:coraza",
		"203.0.113.3": "threat", // seule une source de plugin est reprise du message
		"203.0.113.4": "threat",
	}
	for ip, src := range want {
		var id, bansSrc, histSrc string
		if err := db.QueryRow(`SELECT id, source FROM security_bans WHERE ip = ?`, ip).Scan(&id, &bansSrc); err != nil {
			t.Fatalf("%s : %v", ip, err)
		}
		if err := db.QueryRow(`SELECT source FROM security_ban_history WHERE ip = ? AND action = 'banned'`, ip).Scan(&histSrc); err != nil {
			t.Fatalf("%s historique : %v", ip, err)
		}
		if bansSrc != src || histSrc != src || id != src+"-"+ip {
			t.Errorf("%s : id=%q source=%q historique=%q, attendu source %q", ip, id, bansSrc, histSrc, src)
		}
	}
}

func TestHandleThreatBanStoresAndRelaysTheSignals(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager("", db, slog.Default())
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	signals := []router.BanSignal{
		{Name: "custom_path", Points: 6, Value: "/wp-login.php"},
		{Name: "error4xx", Points: 2.5, Value: "404 /x"},
		{Name: "", Points: 3},                            // sans nom : écarté
		{Name: "rate", Points: -4, Value: "\xff\xfe-ko"}, // négatif ramené à 0, UTF-8 invalide nettoyé
	}
	raw, _ := json.Marshal(edgeWS.ThreatBanPayload{IP: "203.0.113.1", Reason: "threat: score cumulé", ExpiresAt: exp, NodeName: "paris", Signals: signals})
	m.handleThreatBan(raw)

	list, err := m.loadActiveBans(context.Background(), nil)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %+v", err, list)
	}
	got := list[0].Signals
	if len(got) != 3 || got[0] != signals[0] || got[1] != signals[1] || got[2].Name != "rate" || got[2].Points != 0 {
		t.Fatalf("signaux relayés aux passerelles : %+v", got)
	}
	var hist string
	if err := db.QueryRow(`SELECT signals FROM security_ban_history WHERE ip = ?`, "203.0.113.1").Scan(&hist); err != nil || hist == "" {
		t.Fatalf("historique sans signaux : %q %v", hist, err)
	}

	// Un nouveau ban de la même IP remplace l'explication.
	raw, _ = json.Marshal(edgeWS.ThreatBanPayload{IP: "203.0.113.1", Reason: "threat: rate excessif", ExpiresAt: exp, NodeName: "paris",
		Signals: []router.BanSignal{{Name: "rate", Points: 4}}})
	m.handleThreatBan(raw)
	list, _ = m.loadActiveBans(context.Background(), nil)
	if len(list) != 1 || len(list[0].Signals) != 1 || list[0].Signals[0].Name != "rate" {
		t.Fatalf("explication non remplacée : %+v", list)
	}
}

func TestHandleBansStoreTheUserAgentThatCausedThem(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager("", db, slog.Default())
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	raw, _ := json.Marshal(edgeWS.ThreatBanPayload{IP: "203.0.113.1", Reason: "threat: ua", ExpiresAt: exp, NodeName: "paris",
		UserAgent: "sqlmap/1.7\r\n" + strings.Repeat("x", 500)})
	m.handleThreatBan(raw)
	raw, _ = json.Marshal(edgeWS.ThreatBanPayload{IP: "203.0.113.2", Reason: "threat: seuil auth-fail", ExpiresAt: exp, NodeName: "paris", UserAgent: "curl/8.0"})
	m.handleThreatBan(raw)

	for ip, want := range map[string]string{"203.0.113.1": "sqlmap/1.7??" + strings.Repeat("x", 300-len("sqlmap/1.7??")), "203.0.113.2": "curl/8.0"} {
		var inBans, inHistory string
		db.QueryRow(`SELECT user_agent FROM security_bans WHERE ip = ?`, ip).Scan(&inBans)
		db.QueryRow(`SELECT user_agent FROM security_ban_history WHERE ip = ?`, ip).Scan(&inHistory)
		if inBans != want || inHistory != want {
			t.Errorf("%s : bans=%q historique=%q, attendu %q", ip, inBans, inHistory, want)
		}
	}

	list, err := m.loadActiveBans(context.Background(), nil)
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %+v", err, list)
	}
	for _, b := range list {
		if b.IP == "203.0.113.2" && b.UserAgent != "curl/8.0" {
			t.Errorf("le ban renvoyé à la passerelle perd son User-Agent : %+v", b)
		}
	}
}
