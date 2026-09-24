// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipprofile

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestRetryDelay(t *testing.T) {
	cases := []struct {
		failures, intervalH int
		want                time.Duration
	}{
		{1, 24, 15 * time.Minute},
		{2, 24, 30 * time.Minute},
		{3, 24, time.Hour},
		{5, 24, 4 * time.Hour},
		{6, 24, 6 * time.Hour},
		{40, 24, 6 * time.Hour},
		{6, 1, time.Hour},
		{1, 1, 15 * time.Minute},
		{3, 0, time.Hour},
	}
	for _, c := range cases {
		if got := retryDelay(c.failures, c.intervalH); got != c.want {
			t.Errorf("retryDelay(%d, %d) = %v, want %v", c.failures, c.intervalH, got, c.want)
		}
	}
}

func profileState(t *testing.T, db *sql.DB, id string) (failures int, lastErr, next string) {
	t.Helper()
	if err := db.QueryRow(`SELECT consecutive_failures, last_error, COALESCE(next_attempt_at,'') FROM ip_profiles WHERE id=?`, id).
		Scan(&failures, &lastErr, &next); err != nil {
		t.Fatal(err)
	}
	return
}

func TestFailureBackoffAndRecovery(t *testing.T) {
	status := http.StatusServiceUnavailable
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		io.WriteString(w, "1.0.0.0/24\n") //nolint:errcheck
	}))
	defer srv.Close()

	db := openTestDB(t)
	insertProfile(t, db, "p", "deny", srv.URL)
	if _, err := db.Exec(`UPDATE ip_profiles SET cidrs='["9.9.9.0/24"]' WHERE id='p'`); err != nil {
		t.Fatal(err)
	}
	u := testUpdater(db)
	ctx := context.Background()

	u.refreshDue(ctx)
	f, msg, next := profileState(t, db, "p")
	if f != 1 || msg == "" || next == "" {
		t.Fatalf("échec non enregistré: failures=%d err=%q next=%q", f, msg, next)
	}
	if got := storedCIDRs(t, db, "p"); !reflect.DeepEqual(got, []string{"9.9.9.0/24"}) {
		t.Fatalf("la dernière liste valide doit rester appliquée: %v", got)
	}
	var lastUpdated sql.NullString
	db.QueryRow(`SELECT last_updated_at FROM ip_profiles WHERE id='p'`).Scan(&lastUpdated) //nolint:errcheck
	if lastUpdated.Valid {
		t.Fatal("last_updated_at ne doit pas bouger sur un échec")
	}

	hits = 0
	u.refreshDue(ctx)
	if hits != 0 {
		t.Fatalf("pas de nouvelle tentative avant next_attempt_at (hits=%d)", hits)
	}

	db.Exec(`UPDATE ip_profiles SET next_attempt_at=datetime('now','-1 minute')`) //nolint:errcheck
	u.refreshDue(ctx)
	if f, _, _ = profileState(t, db, "p"); f != 2 || hits != 1 {
		t.Fatalf("2e échec attendu: failures=%d hits=%d", f, hits)
	}

	status = http.StatusOK
	db.Exec(`UPDATE ip_profiles SET next_attempt_at=datetime('now','-1 minute')`) //nolint:errcheck
	u.refreshDue(ctx)
	f, msg, next = profileState(t, db, "p")
	if f != 0 || msg != "" || next != "" {
		t.Fatalf("le succès doit réinitialiser l'état: failures=%d err=%q next=%q", f, msg, next)
	}
	if got := storedCIDRs(t, db, "p"); !reflect.DeepEqual(got, []string{"1.0.0.0/24"}) {
		t.Fatalf("après reprise: %v", got)
	}
}

func TestShrinkGuard(t *testing.T) {
	var feed string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, feed) //nolint:errcheck
	}))
	defer srv.Close()

	db := openTestDB(t)
	insertProfile(t, db, "p", "deny", srv.URL)
	u := testUpdater(db)
	ctx := context.Background()

	var full strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&full, "8.%d.0.0/16\n", i*2) // non adjacents : pas de fusion
	}
	feed = full.String()
	if err := u.refresh(ctx, "p", false); err != nil {
		t.Fatal(err)
	}
	if n := len(storedCIDRs(t, db, "p")); n != 40 {
		t.Fatalf("40 entrées attendues, got %d", n)
	}

	feed = "8.0.0.0/16\n"
	if err := u.refresh(ctx, "p", false); err == nil {
		t.Fatal("une liste réduite à 1 entrée sur 40 doit être rejetée")
	}
	if n := len(storedCIDRs(t, db, "p")); n != 40 {
		t.Fatalf("la liste valide doit être conservée, got %d", n)
	}
	if f, msg, _ := profileState(t, db, "p"); f != 1 || !strings.Contains(msg, "rejetée") {
		t.Fatalf("rejet non enregistré: failures=%d err=%q", f, msg)
	}

	feed = ""
	if err := u.refresh(ctx, "p", false); err == nil {
		t.Fatal("un feed vide doit être rejeté")
	}

	if err := u.RefreshProfile(ctx, "p"); err != nil {
		t.Fatalf("le refresh forcé accepte la réduction: %v", err)
	}
	if n := len(storedCIDRs(t, db, "p")); n != 0 {
		t.Fatalf("liste vide forcée attendue, got %d", n)
	}
	if f, _, _ := profileState(t, db, "p"); f != 0 {
		t.Fatalf("le forçage réussi doit réinitialiser les échecs, got %d", f)
	}
}

func TestShrinkGuardIgnoresLegacyRawLists(t *testing.T) {
	// Stockée avant l'agrégation : 32 /24 contigus (= un /19) ; la nouvelle liste agrégée n'a
	// qu'une entrée mais représente la même couverture.
	var raw []string
	for i := 0; i < 32; i++ {
		raw = append(raw, fmt.Sprintf("1.0.%d.0/24", i))
	}
	if err := checkShrink(raw, []string{"1.0.0.0/19"}, "deny"); err != nil {
		t.Fatalf("faux rejet d'une liste simplement agrégée: %v", err)
	}
}

func TestAlertAfterConsecutiveFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	db := openTestDB(t)
	insertProfile(t, db, "p", "deny", srv.URL)
	u := testUpdater(db)
	ctx := context.Background()
	var got []int
	var gotName string
	u.OnRefreshFail = func(id, name string, failures int, cause error, lastUpdatedAt string) {
		got = append(got, failures)
		gotName = name
	}

	fail := func() {
		db.Exec(`UPDATE ip_profiles SET next_attempt_at=NULL`) //nolint:errcheck
		u.refreshDue(ctx)
	}
	for i := 0; i < 5; i++ {
		fail()
	}
	if !reflect.DeepEqual(got, []int{3}) || gotName != "p" {
		t.Fatalf("alerte attendue une seule fois au 3e échec, got %v (%q)", got, gotName)
	}

	// Seuil réglable, et une reprise réarme l'alerte.
	got = nil
	db.Exec(`INSERT INTO settings (key, value) VALUES (?, '2')`, alertThresholdSetting) //nolint:errcheck
	db.Exec(`UPDATE ip_profiles SET consecutive_failures=0`)                            //nolint:errcheck
	for i := 0; i < 3; i++ {
		fail()
	}
	if !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("seuil 2: got %v", got)
	}

	// 0 = désactivé.
	got = nil
	db.Exec(`UPDATE settings SET value='0' WHERE key=?`, alertThresholdSetting) //nolint:errcheck
	db.Exec(`UPDATE ip_profiles SET consecutive_failures=0`)                    //nolint:errcheck
	for i := 0; i < 4; i++ {
		fail()
	}
	if len(got) != 0 {
		t.Fatalf("alerte désactivée: got %v", got)
	}
}
