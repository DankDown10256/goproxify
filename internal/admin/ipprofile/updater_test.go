// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipprofile

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestNormalizeCIDRs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		drop bool
		want []string
	}{
		{"doublons et IP nue", []string{"1.2.3.4", "1.2.3.4/32", "1.2.3.4"}, false, []string{"1.2.3.4/32"}},
		{"contenu dans un autre", []string{"10.1.2.0/24", "10.1.0.0/16", "10.1.2.3"}, false, []string{"10.1.0.0/16"}},
		{"voisins fusionnés", []string{"1.0.0.0/24", "1.0.1.0/24"}, false, []string{"1.0.0.0/23"}},
		{"fusion en cascade", []string{"1.0.0.0/24", "1.0.1.0/24", "1.0.2.0/24", "1.0.3.0/24"}, false, []string{"1.0.0.0/22"}},
		{"non voisins", []string{"1.0.1.0/24", "1.0.2.0/24"}, false, []string{"1.0.1.0/24", "1.0.2.0/24"}},
		{"bits hôte masqués", []string{"1.2.3.4/24"}, false, []string{"1.2.3.0/24"}},
		{"ipv6", []string{"2a00::/33", "2a00:0:8000::/33", "2a00::1"}, false, []string{"2a00::/32"}},
		{"ipv4 mappée en v6", []string{"::ffff:1.2.3.4"}, false, []string{"1.2.3.4/32"}},
		{"invalides ignorées", []string{"n'importe quoi", "", "1.2.3.4/99"}, false, []string{}},
		{"privées conservées si allow", []string{"10.0.0.0/8"}, false, []string{"10.0.0.0/8"}},
		{
			"privées retirées si deny",
			[]string{"10.1.0.0/16", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.0/10", "fd00::/8", "fe80::1", "::1", "8.8.8.0/24", "2001:4860::/32", "240.0.0.0/4"},
			true,
			[]string{"8.8.8.0/24", "2001:4860::/32"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeCIDRs(c.in, c.drop)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func testUpdater(db *sql.DB) *Updater {
	return New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func insertProfile(t *testing.T, db *sql.DB, id, mode, url string) {
	t.Helper()
	urls, _ := json.Marshal([]string{url})
	if _, err := db.Exec(`INSERT INTO ip_profiles (id, name, profile_type, mode, feed_urls, feed_format, refresh_interval_h, cidrs, enabled)
		VALUES (?, ?, 'custom', ?, ?, 'plain', 1, '[]', 1)`, id, id, mode, string(urls)); err != nil {
		t.Fatal(err)
	}
}

func storedCIDRs(t *testing.T, db *sql.DB, id string) []string {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT cidrs FROM ip_profiles WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var out []string
	json.Unmarshal([]byte(raw), &out) //nolint:errcheck
	return out
}

func TestRefreshConditionalRequests(t *testing.T) {
	var hits, notModified int
	body := "# feed\n1.0.0.0/24\n1.0.1.0/24\n10.0.0.0/8\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, body) //nolint:errcheck
	}))
	defer srv.Close()

	db := openTestDB(t)
	insertProfile(t, db, "p", "deny", srv.URL)
	u := testUpdater(db)
	ctx := context.Background()

	if err := u.refresh(ctx, "p", false); err != nil {
		t.Fatal(err)
	}
	if got := storedCIDRs(t, db, "p"); !reflect.DeepEqual(got, []string{"1.0.0.0/23"}) {
		t.Fatalf("après 1er fetch: %v", got)
	}

	if _, err := db.Exec(`UPDATE ip_profiles SET cidrs='["sentinelle"]' WHERE id='p'`); err != nil {
		t.Fatal(err)
	}
	if err := u.refresh(ctx, "p", false); err != nil {
		t.Fatal(err)
	}
	if notModified != 1 {
		t.Fatalf("304 attendu, notModified=%d hits=%d", notModified, hits)
	}
	if got := storedCIDRs(t, db, "p"); !reflect.DeepEqual(got, []string{"sentinelle"}) {
		t.Fatalf("un 304 ne doit pas toucher les CIDRs, got %v", got)
	}

	if err := u.RefreshProfile(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if notModified != 1 {
		t.Fatalf("le refresh forcé ne doit pas être conditionnel")
	}
	if got := storedCIDRs(t, db, "p"); !reflect.DeepEqual(got, []string{"1.0.0.0/23"}) {
		t.Fatalf("après refresh forcé: %v", got)
	}

	// Changer le mode invalide les validateurs : la liste est retraitée (privées gardées en allow).
	if _, err := db.Exec(`UPDATE ip_profiles SET mode='allow' WHERE id='p'`); err != nil {
		t.Fatal(err)
	}
	if err := u.refresh(ctx, "p", false); err != nil {
		t.Fatal(err)
	}
	if got := storedCIDRs(t, db, "p"); !reflect.DeepEqual(got, []string{"1.0.0.0/23", "10.0.0.0/8"}) {
		t.Fatalf("après changement de mode: %v", got)
	}
}

func TestRefreshProfileWithoutFeedKeepsManualCIDRs(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`INSERT INTO ip_profiles (id, name, mode, cidrs) VALUES ('m', 'm', 'deny', '["9.9.9.0/24"]')`); err != nil {
		t.Fatal(err)
	}
	u := testUpdater(db)
	u.refreshDue(context.Background())
	if err := u.RefreshProfile(context.Background(), "m"); err == nil {
		t.Fatal("erreur attendue pour un profil sans feed")
	}
	if got := storedCIDRs(t, db, "m"); !reflect.DeepEqual(got, []string{"9.9.9.0/24"}) {
		t.Fatalf("CIDRs manuels écrasés: %v", got)
	}
}

func enabledOf(t *testing.T, db *sql.DB, ptype string) int {
	t.Helper()
	var e int
	if err := db.QueryRow(`SELECT enabled FROM ip_profiles WHERE profile_type=?`, ptype).Scan(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSeedDisablesProfilesCoveredByL1(t *testing.T) {
	db := openTestDB(t)
	u := testUpdater(db)
	u.seed(context.Background())
	for ptype, want := range map[string]int{
		"firehol-l1": 1, "tor": 1, "et-compromised": 1,
		"spamhaus-drop": 0, "dshield": 0, "feodo": 0,
	} {
		if got := enabledOf(t, db, ptype); got != want {
			t.Errorf("%s: enabled=%d, want %d", ptype, got, want)
		}
	}
}

func TestDisableCoveredByL1MigratesOnce(t *testing.T) {
	db := openTestDB(t)
	u := testUpdater(db)
	ctx := context.Background()
	u.seed(ctx)
	// Simule une base antérieure : tout activé, marqueur absent.
	db.Exec(`UPDATE ip_profiles SET enabled=1`)                                            //nolint:errcheck
	db.Exec(`DELETE FROM settings WHERE key=?`, coveredByL1Setting)                        //nolint:errcheck
	db.Exec(`UPDATE ip_profiles SET feed_urls='["https://x"]' WHERE profile_type='feodo'`) //nolint:errcheck

	u.disableCoveredByL1(ctx)
	if enabledOf(t, db, "spamhaus-drop") != 0 || enabledOf(t, db, "dshield") != 0 {
		t.Fatal("spamhaus-drop et dshield auraient dû être désactivés")
	}
	if enabledOf(t, db, "feodo") != 1 {
		t.Fatal("un profil dont le feed a été personnalisé doit rester actif")
	}

	db.Exec(`UPDATE ip_profiles SET enabled=1 WHERE profile_type='dshield'`) //nolint:errcheck
	u.disableCoveredByL1(ctx)
	if enabledOf(t, db, "dshield") != 1 {
		t.Fatal("la migration ne doit s'appliquer qu'une fois")
	}
}
