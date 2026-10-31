// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package bansdb

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestUnbanOnlyLiftsBansPostedBeforeIt(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const ip = "203.0.113.5"
	old := time.Now().Add(-2 * time.Hour).UTC().Format(sqlTime)
	for _, src := range []string{"fail2ban", "threat", "admin"} {
		if _, err := d.db.Exec(`INSERT INTO bans (id, ip, source, created_at) VALUES (?, ?, ?, ?)`, src+"-old", ip, src, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.UpsertBan("fail2ban-new", ip, "", "", "fail2ban", nil); err != nil {
		t.Fatal(err)
	}

	at := time.Now().Add(-time.Hour)
	if err := d.Unban(ip, at); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "fail2ban-new" {
		t.Fatalf("seul le ban posé après le déban doit rester, toutes sources confondues : %+v", rows)
	}
	if rows[0].CreatedAt.IsZero() {
		t.Fatal("created_at doit être relu (filtre des bans de pairs)")
	}

	// Un déban plus ancien ne recule pas la date retenue.
	if err := d.Unban(ip, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	unbans, err := d.Unbans()
	if err != nil {
		t.Fatal(err)
	}
	if got := unbans[ip]; !got.Equal(at.UTC().Truncate(time.Second)) {
		t.Fatalf("date de déban retenue : %v, attendu %v", got, at.UTC().Truncate(time.Second))
	}
}

func TestExpiredBanIsNeitherActiveNorKept(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	for id, exp := range map[string]*time.Time{"expire": &past, "actif": &future, "permanent": nil} {
		if err := d.UpsertBan(id, "203.0.113.7", "", "", "fail2ban", exp); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := d.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == "expire" {
			t.Fatal("un ban expiré depuis 1 min n'est plus actif (et non jusqu'à minuit UTC)")
		}
	}
	if len(rows) != 2 {
		t.Fatalf("2 bans actifs attendus : %+v", rows)
	}
	if err := d.PurgeExpiredBans(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM bans`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("la purge supprime le ban expiré et lui seul : %d bans restants", n)
	}
}

func TestHistoryWindowsSeeTodaysEvents(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const ip = "203.0.113.8"
	if _, err := d.db.Exec(`INSERT INTO ban_history (ip, source, created_at) VALUES (?, 'threat', ?)`,
		ip, time.Now().Add(-time.Hour).UTC().Format(sqlTime)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := d.RecordBanEvent(ip, "threat"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		if err := d.RecordProxyEvent("a.example", i < 5); err != nil {
			t.Fatal(err)
		}
	}

	since := time.Now().Add(-5 * time.Minute)
	check := func(step string) {
		t.Helper()
		if n, err := d.RecentBanCount(since, "threat"); err != nil || n != 3 {
			t.Fatalf("%s : %d bans dans les 5 dernières minutes, attendu 3 (err %v)", step, n, err)
		}
		if got, n, err := d.RepeatBanIP(since, 3); err != nil || got != ip || n != 3 {
			t.Fatalf("%s : IP récidiviste %q (%d), attendu %s (3)", step, got, n, ip)
		}
		if rows, err := d.BanHistorySince(since); err != nil || len(rows) != 3 {
			t.Fatalf("%s : %d entrées d'historique, attendu 3 (err %v)", step, len(rows), err)
		}
		if rate, host, err := d.ProxyErrorRate(since, 10); err != nil || host != "a.example" || rate != 50 {
			t.Fatalf("%s : taux d'erreurs %v sur %q, attendu 50 sur a.example (err %v)", step, rate, host, err)
		}
	}
	check("avant purge")
	if err := d.PurgeBanHistory(since); err != nil {
		t.Fatal(err)
	}
	if err := d.PurgeProxyErrors(since); err != nil {
		t.Fatal(err)
	}
	check("après purge des entrées antérieures à la fenêtre")
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM ban_history`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("seule l'entrée vieille d'1 h doit être purgée : %d restantes", n)
	}
}

func TestBanCountForIP(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const ip = "203.0.113.7"
	at := func(ago time.Duration) string { return time.Now().Add(-ago).UTC().Format(sqlTime) }
	add := func(ip, src string, ago time.Duration) {
		t.Helper()
		if _, err := d.db.Exec(`INSERT INTO ban_history (ip, source, created_at) VALUES (?, ?, ?)`, ip, src, at(ago)); err != nil {
			t.Fatal(err)
		}
	}
	add(ip, "threat", 3*24*time.Hour)
	add(ip, "threat", 2*time.Hour)
	add(ip, "fail2ban", time.Hour)          // autre source : ignorée
	add("203.0.113.8", "threat", time.Hour) // autre IP : ignorée
	add(ip, "threat", 20*24*time.Hour)      // hors fenêtre

	since := time.Now().Add(-7 * 24 * time.Hour)
	n, err := d.BanCountForIP(ip, "threat", since)
	if err != nil || n != 2 {
		t.Fatalf("bans Ephor de l'IP dans la fenêtre : %d %v, attendu 2", n, err)
	}

	// Un déban manuel remet la récidive à zéro : seuls les bans postérieurs comptent.
	if err := d.Unban(ip, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.BanCountForIP(ip, "threat", since); n != 0 {
		t.Fatalf("après déban : %d, attendu 0", n)
	}
	add(ip, "threat", time.Minute)
	if n, _ := d.BanCountForIP(ip, "threat", since); n != 1 {
		t.Fatalf("ban postérieur au déban : %d, attendu 1", n)
	}
}

func TestEraseIPRemovesBansAndHistoryButKeepsTheUnban(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, ip := range []string{"203.0.113.42", "198.51.100.9"} {
		if err := d.UpsertBan("b-"+ip, ip, "", "test", "native", nil); err != nil {
			t.Fatal(err)
		}
		if err := d.RecordBanEvent(ip, "native"); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Unban("203.0.113.42", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertBan("again", "203.0.113.42", "", "test", "native", nil); err != nil {
		t.Fatal(err)
	}
	n, err := d.EraseIP("203.0.113.42", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("%d lignes supprimées, attendu au moins 2 (ban + historique)", n)
	}
	var left int
	d.db.QueryRow(`SELECT (SELECT COUNT(*) FROM bans WHERE ip='203.0.113.42') + (SELECT COUNT(*) FROM ban_history WHERE ip='203.0.113.42')`).Scan(&left) //nolint:errcheck
	if left != 0 {
		t.Fatalf("%d lignes de l'IP effacée subsistent", left)
	}
	var other int
	d.db.QueryRow(`SELECT (SELECT COUNT(*) FROM bans) + (SELECT COUNT(*) FROM ban_history)`).Scan(&other) //nolint:errcheck
	if other != 2 {
		t.Fatalf("les données d'une autre IP ont été touchées : %d lignes, attendu 2", other)
	}
	if un, _ := d.Unbans(); len(un) != 1 {
		t.Fatalf("le déban doit rester : %v", un)
	}
}

func TestBanSignalsRoundTrip(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	signals := []router.BanSignal{{Name: "path", Points: 6, Value: "/wp-login.php"}, {Name: "error4xx", Points: 2.5}}
	if err := d.UpsertRuntimeBan(&router.RuntimeBan{ID: "threat-1", IP: "203.0.113.5", Source: "threat", Signals: signals, UserAgent: "sqlmap/1.7"}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertBan("native-1", "203.0.113.6", "", "", "native", nil); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ActiveBans()
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %+v", err, rows)
	}
	for _, r := range rows {
		switch r.ID {
		case "threat-1":
			if r.UserAgent != "sqlmap/1.7" {
				t.Fatalf("User-Agent relu : %q", r.UserAgent)
			}
			if len(r.Signals) != 2 || r.Signals[0] != signals[0] || r.Signals[1] != signals[1] {
				t.Fatalf("signaux relus : %+v", r.Signals)
			}
		case "native-1":
			if len(r.Signals) != 0 || r.UserAgent != "" {
				t.Fatalf("un ban manuel n'a ni signaux ni User-Agent : %+v", r)
			}
		}
	}
}
