// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func newTestEngine(t *testing.T) (*Engine, *sql.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e := New(d, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e.SaveConfig(Config{Enabled: true, WindowSec: 300, MaxErrors: 5}); err != nil {
		t.Fatal(err)
	}
	return e, d
}

// insertForbidden ajoute n erreurs client de l'IP à la minute de at, comme le compteur d'une passerelle.
func insertForbidden(t *testing.T, d *sql.DB, ip string, at time.Time, n int) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO edge_ip_errors (node_id, minute, ip, errors) VALUES ('edge-a', ?, ?, ?)
		ON CONFLICT (node_id, minute, ip) DO UPDATE SET errors = errors + excluded.errors`,
		at.UTC().Format("2006-01-02T15:04"), ip, n); err != nil {
		t.Fatal(err)
	}
}

func activeBans(t *testing.T, d *sql.DB, ip string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE ip=?`, ip).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScanOnlyCountsErrorsInsideTheWindow(t *testing.T) {
	e, d := newTestEngine(t)
	const ip = "203.0.113.60"
	insertForbidden(t, d, ip, time.Now().Add(-20*time.Minute), 10)
	e.scan()
	if activeBans(t, d, ip) != 0 {
		t.Fatal("des erreurs vieilles de 20 min ne comptent pas dans une fenêtre de 5 min")
	}
	insertForbidden(t, d, ip, time.Now().Add(-time.Minute), 5)
	e.scan()
	if activeBans(t, d, ip) != 1 {
		t.Fatal("5 erreurs dans la fenêtre doivent bannir")
	}
}

func TestScanDoesNotRebanRightAfterAnUnban(t *testing.T) {
	e, d := newTestEngine(t)
	const ip = "203.0.113.61"
	// 403 servis par le ban avant son déban. Les compteurs sont à la minute : le déban se place deux minutes plus tôt
	// que les nouvelles erreurs, la minute du déban elle-même n'étant jamais comptée.
	insertForbidden(t, d, ip, time.Now().Add(-3*time.Minute), 20)
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, action, source, created_at) VALUES (?, 'unbanned', 'fleet', ?)`, ip,
		time.Now().Add(-2*time.Minute).UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	e.scan()
	if activeBans(t, d, ip) != 0 {
		t.Fatal("les erreurs antérieures au déban ne doivent pas rebannir")
	}
	insertForbidden(t, d, ip, time.Now(), 5)
	e.scan()
	if activeBans(t, d, ip) != 1 {
		t.Fatal("de nouvelles erreurs après le déban doivent rebannir")
	}
}

func TestLastBanEndIsTheLatestUnbanOrExpiry(t *testing.T) {
	e, d := newTestEngine(t)
	const ip = "203.0.113.62"
	if !e.lastBanEnd(ip).IsZero() {
		t.Fatal("jamais banni : pas de fin de ban")
	}
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, action, created_at) VALUES (?, 'unbanned', datetime('now','-10 minutes'))`, ip); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-30 * time.Second).UTC().Truncate(time.Second)
	future := time.Now().Add(time.Hour).UTC()
	for id, exp := range map[string]time.Time{"expire": expired, "actif": future} {
		if _, err := d.Exec(`INSERT INTO security_bans (id, ip, reason, source, expires_at) VALUES (?, ?, '', 'threat', ?)`,
			id, ip, exp.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.lastBanEnd(ip); !got.Equal(expired) {
		t.Fatalf("fin du dernier ban : %v, attendu l'expiration %v (un ban encore actif n'est pas une fin)", got, expired)
	}
}

func allBans(t *testing.T, d *sql.DB) []string {
	t.Helper()
	rows, err := d.Query(`SELECT ip FROM security_bans ORDER BY ip`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			t.Fatal(err)
		}
		out = append(out, ip)
	}
	return out
}

func TestScanBanTarget(t *testing.T) {
	for _, tc := range []struct{ logged, want string }{
		{"203.0.113.70", "203.0.113.70"},
		{"203.0.113.71:51234", "203.0.113.71"},
		{"2a01:e0a:1:2::5", "2a01:e0a:1:2::/64"},
		{"[2a01:e0a:1:3::5]:443", "2a01:e0a:1:3::/64"},
	} {
		e, d := newTestEngine(t)
		insertForbidden(t, d, tc.logged, time.Now().Add(-time.Minute), 5)
		e.scan()
		if got := allBans(t, d); len(got) != 1 || got[0] != tc.want {
			t.Errorf("logs.ip=%q : bans %v, attendu [%s]", tc.logged, got, tc.want)
		}
	}
}

func TestScanIgnoresPseudonymizedIPs(t *testing.T) {
	e, d := newTestEngine(t)
	insertForbidden(t, d, "[pseudonymisé]", time.Now().Add(-time.Minute), 10)
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("une IP pseudonymisée ne peut pas être bannie : %v", got)
	}
}

func TestScanIgnoresTruncatedIPs(t *testing.T) {
	e, d := newTestEngine(t)
	// Une passerelle ne compte pas les IP qu'elle tronque ; x.x.x.0 d'un compteur est une adresse comme une autre
	// (ex. dans un /23).
	insertForbidden(t, d, "198.51.100.0", time.Now().Add(-time.Minute), 5)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "198.51.100.0" {
		t.Fatalf("IP réelle en .0 : bans %v, attendu [198.51.100.0]", got)
	}
}

func TestScanSkippedWhileAdminPushesIPProtection(t *testing.T) {
	for _, key := range []string{"logs.ip_anonymize", "logs.ip_pseudonymize"} {
		e, d := newTestEngine(t)
		if err := db.SetSetting(d, key, "true"); err != nil {
			t.Fatal(err)
		}
		// Passerelle antérieure au marqueur ip_truncated : IP tronquées non signalées.
		insertForbidden(t, d, "203.0.113.0", time.Now().Add(-time.Minute), 50)
		insertForbidden(t, d, "2a01:e0a:1::", time.Now().Add(-time.Minute), 50)
		e.scan()
		if got := allBans(t, d); len(got) != 0 {
			t.Errorf("%s : les IP reçues sont tronquées, aucun ban attendu : %v", key, got)
		}
		if e.LastActivity().IsZero() {
			t.Errorf("%s : le scan doit compter comme actif (pas d'alerte engine_silent)", key)
		}
	}
}

func TestScanAggregatesIPv6By64(t *testing.T) {
	e, d := newTestEngine(t)
	at := time.Now().Add(-time.Minute)
	for _, ip := range []string{"2a01:e0a:1:2::1", "2a01:e0a:1:2::2", "2a01:e0a:1:2::3", "2a01:e0a:1:2:abcd::4"} {
		insertForbidden(t, d, ip, at, 1)
	}
	insertForbidden(t, d, "2a01:e0a:1:3::1", at, 1)
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("4 erreurs dans le /64 sous un seuil de 5 : bans %v", got)
	}
	insertForbidden(t, d, "2a01:e0a:1:2::5", at, 1)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "2a01:e0a:1:2::/64" {
		t.Fatalf("5 erreurs réparties sur le /64 : bans %v, attendu [2a01:e0a:1:2::/64]", got)
	}
}

func TestScanIPv6Whitelist(t *testing.T) {
	e, d := newTestEngine(t)
	if err := e.SaveConfig(Config{Enabled: true, WindowSec: 300, MaxErrors: 5, Whitelist: []string{"2a01:e0a:1:4::5"}}); err != nil {
		t.Fatal(err)
	}
	insertForbidden(t, d, "2a01:e0a:1:4::5", time.Now().Add(-time.Minute), 10)
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("une IPv6 en liste blanche ne doit pas être bannie : %v", got)
	}
	insertForbidden(t, d, "2a01:e0a:1:4::6", time.Now().Add(-time.Minute), 5)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "2a01:e0a:1:4::6" {
		t.Fatalf("voisine d'une IP exemptée : bans %v, attendu l'adresse seule, pas le /64", got)
	}
}

func TestScanDoesNotRebanIPv6PrefixRightAfterAnUnban(t *testing.T) {
	e, d := newTestEngine(t)
	insertForbidden(t, d, "2a01:e0a:1:2::5", time.Now().Add(-3*time.Minute), 20)
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, action, source, created_at) VALUES ('2a01:e0a:1:2::/64', 'unbanned', 'fleet', ?)`,
		time.Now().Add(-2*time.Minute).UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("les erreurs antérieures au déban du /64 ne doivent pas rebannir : %v", got)
	}
	insertForbidden(t, d, "2a01:e0a:1:2::9", time.Now(), 5)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "2a01:e0a:1:2::/64" {
		t.Fatalf("de nouvelles erreurs après le déban doivent rebannir le /64 : %v", got)
	}
}

func TestScanRebansOnceThePreviousBanHasExpired(t *testing.T) {
	e, d := newTestEngine(t)
	expired := time.Now().Add(-time.Minute)
	for ip, exp := range map[string]string{
		"203.0.113.63": expired.UTC().Format(time.RFC3339),
		"203.0.113.64": expired.In(time.FixedZone("", 2*3600)).Format(time.RFC3339),
	} {
		if _, err := d.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES (?, ?, 'fleet', ?)`,
			"ancien-"+ip, ip, exp); err != nil {
			t.Fatal(err)
		}
		insertForbidden(t, d, ip, time.Now(), 5)
	}
	e.scan()
	for _, ip := range []string{"203.0.113.63", "203.0.113.64"} {
		if activeBans(t, d, ip) != 2 {
			t.Errorf("%s : un ban expiré depuis 1 min ne compte plus comme « déjà banni », et les erreurs qui suivent son expiration comptent", ip)
		}
	}
}
