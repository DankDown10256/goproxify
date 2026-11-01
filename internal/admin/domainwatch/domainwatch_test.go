// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package domainwatch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

type fakeCT struct {
	entries map[string][]CTEntry
	err     error
	calls   []string
}

func (f *fakeCT) Fetch(_ context.Context, endpoint, domain string) ([]CTEntry, error) {
	f.calls = append(f.calls, endpoint+"|"+domain)
	return f.entries[domain], f.err
}

type fakeDNS struct {
	caa      map[string][]CAARecord
	dangling map[string]string
	err      error
	queries  int
}

func (f *fakeDNS) CAA(_ context.Context, name string) ([]CAARecord, error) {
	f.queries++
	return f.caa[name], f.err
}

func (f *fakeDNS) Dangling(_ context.Context, name string) (string, error) {
	f.queries++
	return f.dangling[name], f.err
}

type rig struct {
	t      *testing.T
	db     *sql.DB
	w      *Watcher
	ct     *fakeCT
	dns    *fakeDNS
	alerts []alerting.Event
	sleeps []time.Duration
	now    time.Time
}

func newRig(t *testing.T, domains ...string) *rig {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	for i, d := range domains {
		if _, err := db.Exec(`INSERT INTO domains (id, domain) VALUES (?, ?)`, string(rune('a'+i)), d); err != nil {
			t.Fatal(err)
		}
	}
	r := &rig{t: t, db: db, ct: &fakeCT{entries: map[string][]CTEntry{}}, dns: &fakeDNS{caa: map[string][]CAARecord{}, dangling: map[string]string{}},
		now: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}
	r.w = &Watcher{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CT: r.ct,
		Alert: func(e alerting.Event) { r.alerts = append(r.alerts, e) },
		DNS:   func(string) (DNSClient, error) { return r.dns, nil },
		Now:   func() time.Time { return r.now },
		Sleep: func(d time.Duration) { r.sleeps = append(r.sleeps, d) }}
	return r
}

func (r *rig) config(c Config) {
	r.t.Helper()
	if err := r.w.SetConfig(c); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) run() {
	r.t.Helper()
	r.now = r.now.Add(time.Hour)
	if err := r.w.Run(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) findings(status string) []Finding {
	r.t.Helper()
	f, err := r.w.Findings(status)
	if err != nil {
		r.t.Fatal(err)
	}
	return f
}

func certPEM(t *testing.T, serial int64) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "app.example.fr"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestDisabledByDefaultAndNothingIsSent(t *testing.T) {
	r := newRig(t, "app.example.fr")
	if r.w.Config().Active() {
		t.Fatal("tout est désactivé par défaut")
	}
	r.run()
	if len(r.ct.calls) != 0 || r.dns.queries != 0 || len(r.alerts) != 0 {
		t.Fatal("rien ne doit sortir sans opt-in")
	}
	r.config(Config{Enabled: true}) // interrupteur général seul : aucune vérification choisie
	r.run()
	if len(r.ct.calls) != 0 || r.dns.queries != 0 {
		t.Fatal("chaque vérification s'active séparément")
	}
}

func TestOnlyTheChosenChecksSendNames(t *testing.T) {
	r := newRig(t, "app.example.fr")
	r.config(Config{Enabled: true, CAA: true})
	r.run()
	if len(r.ct.calls) != 0 {
		t.Fatal("le journal de transparence n'est pas consulté sans ct")
	}
	if r.dns.queries != 1 {
		t.Fatalf("seul CAA interroge le DNS : %d requêtes", r.dns.queries)
	}
}

func TestExistingCertificatesAreBaselinedThenANewForeignOneAlerts(t *testing.T) {
	r := newRig(t, "app.example.fr")
	r.config(Config{Enabled: true, CT: true, TrustedIssuers: []string{"Cloudflare"}})
	r.ct.entries["app.example.fr"] = []CTEntry{
		{Serial: "0A1B", Issuer: "C=US, O=Let's Encrypt, CN=R11", Names: []string{"app.example.fr"}},
		{Serial: "ff02", Issuer: "C=US, O=Cloudflare, Inc., CN=Cloudflare TLS", Names: []string{"app.example.fr"}},
	}
	r.run()
	if len(r.alerts) != 0 {
		t.Fatalf("la première analyse établit la référence sans alerter : %+v", r.alerts)
	}
	byKey := map[string]string{}
	for _, f := range r.findings("") {
		byKey[f.Key] = f.Status
	}
	if byKey["a1b"] != StatusBaseline || byKey["ff02"] != StatusTrusted {
		t.Fatalf("existant listé, émetteur toléré reconnu : %v", byKey)
	}

	r.ct.entries["app.example.fr"] = append(r.ct.entries["app.example.fr"], CTEntry{
		Serial: "00:C0:FF:EE", Issuer: "O=Some CA", Names: []string{"app.example.fr", "www.example.fr"}, NotBefore: r.now})
	r.run()
	if len(r.alerts) != 1 {
		t.Fatalf("un certificat inattendu apparu depuis doit alerter une fois : %+v", r.alerts)
	}
	a := r.alerts[0]
	if a.Trigger != alerting.TriggerDomainWatch || a.Severity != alerting.SevCritical || a.Domain != "app.example.fr" ||
		a.Detail["finding"] != "unexpected_certificate" || a.Detail["serial"] != "c0ffee" || a.Detail["issuer"] != "O=Some CA" {
		t.Fatalf("alerte : %+v", a)
	}
	r.run()
	if len(r.alerts) != 1 {
		t.Fatal("le même certificat ne ré-alerte pas")
	}

	if ok, err := r.w.Accept("app.example.fr", CheckCT, "c0ffee"); !ok || err != nil {
		t.Fatalf("accepter : %v %v", ok, err)
	}
	if open := r.findings(StatusOpen); len(open) != 0 {
		t.Fatalf("un certificat reconnu n'est plus à traiter : %+v", open)
	}
	if ok, _ := r.w.Accept("app.example.fr", CheckCT, "inconnu"); ok {
		t.Fatal("rien à accepter pour une clé inconnue")
	}
}

func TestCertificatesObtainedByGoProxifyAreOursEvenAfterRenewal(t *testing.T) {
	r := newRig(t, "app.example.fr")
	if _, err := r.db.Exec(`INSERT INTO certs (id, domain, issuer, expires_at, cert_pem) VALUES ('c1', 'app.example.fr', 'letsencrypt', ?, ?)`,
		r.now.Add(time.Hour), certPEM(t, 0x1234)); err != nil {
		t.Fatal(err)
	}
	r.config(Config{Enabled: true, CT: true})
	r.ct.entries["app.example.fr"] = []CTEntry{{Serial: "1234", Issuer: "Let's Encrypt"}}
	r.run() // baseline
	// Renouvellement : le certificat suivant remplace le premier dans la base ; l'ancien reste reconnu.
	if _, err := r.db.Exec(`UPDATE certs SET cert_pem=? WHERE id='c1'`, certPEM(t, 0x5678)); err != nil {
		t.Fatal(err)
	}
	r.ct.entries["app.example.fr"] = []CTEntry{{Serial: "1234", Issuer: "Let's Encrypt"}, {Serial: "5678", Issuer: "Let's Encrypt"}}
	r.run()
	if len(r.alerts) != 0 {
		t.Fatalf("les certificats de GoProxify, anciens et nouveaux, n'alertent jamais : %+v", r.alerts)
	}
	for _, f := range r.findings("") {
		if f.Check == CheckCT && f.Status != StatusOurs {
			t.Fatalf("tous reconnus comme les siens : %+v", f)
		}
	}
}

func TestCAAFindings(t *testing.T) {
	r := newRig(t, "app.example.fr", "ok.example.fr", "wide.example.fr", "excl.example.fr")
	r.config(Config{Enabled: true, CAA: true})
	r.dns.caa["ok.example.fr"] = []CAARecord{{Tag: "issue", Value: "letsencrypt.org"}}
	r.dns.caa["wide.example.fr"] = []CAARecord{{Tag: "issue", Value: "letsencrypt.org"}, {Tag: "issue", Value: "digicert.com"},
		{Tag: "issue", Value: "sectigo.com"}, {Tag: "issue", Value: "globalsign.com; account=1"}}
	r.dns.caa["excl.example.fr"] = []CAARecord{{Tag: "issue", Value: "digicert.com"}, {Tag: "iodef", Value: "mailto:s@example.fr"}}
	r.run()
	got := map[string]string{}
	for _, f := range r.findings(StatusOpen) {
		got[f.Domain] = f.Key + ":" + f.Severity
	}
	if got["app.example.fr"] != "caa_missing:info" || got["wide.example.fr"] != "caa_too_wide:info" || got["excl.example.fr"] != "caa_excludes_ca:warning" {
		t.Fatalf("constats CAA : %v", got)
	}
	if _, bad := got["ok.example.fr"]; bad {
		t.Fatal("un CAA qui autorise l'autorité de GoProxify ne donne rien")
	}
	if len(r.alerts) != 3 {
		t.Fatalf("une alerte par constat : %d", len(r.alerts))
	}
	r.run()
	if len(r.alerts) != 3 {
		t.Fatal("un constat qui dure n'alerte qu'une fois")
	}

	// Corrigé, puis de nouveau cassé : il alerte de nouveau.
	r.dns.caa["excl.example.fr"] = []CAARecord{{Tag: "issue", Value: "letsencrypt.org"}}
	r.run()
	for _, f := range r.findings(StatusResolved) {
		if f.Domain != "excl.example.fr" {
			continue
		}
		if f.Key != "caa_excludes_ca" {
			t.Fatalf("résolu : %+v", f)
		}
	}
	r.dns.caa["excl.example.fr"] = []CAARecord{{Tag: "issue", Value: "digicert.com"}}
	r.run()
	if len(r.alerts) != 4 {
		t.Fatalf("un constat qui revient ré-alerte : %d alertes", len(r.alerts))
	}
}

func TestDanglingCNAME(t *testing.T) {
	r := newRig(t, "old.example.fr", "live.example.fr")
	r.config(Config{Enabled: true, Dangling: true})
	r.dns.dangling["old.example.fr"] = "shop-1234.hosting.example"
	r.run()
	if len(r.alerts) != 1 || r.alerts[0].Detail["finding"] != "dangling_cname" || r.alerts[0].Detail["target"] != "shop-1234.hosting.example" || r.alerts[0].Severity != alerting.SevWarning {
		t.Fatalf("alerte : %+v", r.alerts)
	}
	r.dns.dangling["old.example.fr"] = ""
	r.run()
	if len(r.findings(StatusOpen)) != 0 || len(r.findings(StatusResolved)) != 1 {
		t.Fatalf("la cible rétablie résout le constat : %+v", r.findings(""))
	}
}

func TestRequestsAreSpacedAndDomainsAreBounded(t *testing.T) {
	var doms []string
	for i := 0; i < maxDomains+30; i++ {
		doms = append(doms, "h"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+".example.fr")
	}
	r := newRig(t, doms...)
	r.config(Config{Enabled: true, CT: true})
	r.run()
	if len(r.ct.calls) > maxDomains {
		t.Fatalf("au plus %d domaines par analyse : %d appels", maxDomains, len(r.ct.calls))
	}
	var spaced int
	for _, d := range r.sleeps {
		if d >= 3*time.Second {
			spaced++
		}
	}
	if spaced < len(r.ct.calls)-1 {
		t.Fatalf("les appels au journal sont espacés : %d pauses pour %d appels", spaced, len(r.ct.calls))
	}
}

func TestWildcardsAndDuplicatesCountOnce(t *testing.T) {
	r := newRig(t, "*.example.fr", "Example.FR.", "example.fr", "localhost")
	r.config(Config{Enabled: true, CAA: true})
	r.run()
	if r.dns.queries != 1 {
		t.Fatalf("un nom sans joker, sans doublon, avec un point : %d requêtes", r.dns.queries)
	}
}

func TestErrorsAreReportedWithoutStoppingTheRun(t *testing.T) {
	r := newRig(t, "a.example.fr", "b.example.fr")
	r.config(Config{Enabled: true, CT: true, CAA: true})
	r.ct.err = errors.New("HTTP 503")
	r.run()
	st := r.w.State()
	if !strings.Contains(st.LastError, "HTTP 503") || st.Domains != 2 || st.LastRun.IsZero() {
		t.Fatalf("l'état doit dire ce qui a échoué : %+v", st)
	}
	if r.dns.queries != 2 {
		t.Fatalf("les autres vérifications continuent : %d requêtes DNS", r.dns.queries)
	}
}

func TestManualRunCooldownAndOneRunAtATime(t *testing.T) {
	r := newRig(t, "app.example.fr")
	r.config(Config{Enabled: true, CAA: true})
	if err := r.w.RunNow(); err != nil {
		t.Fatal(err)
	}
	if err := r.w.RunNow(); !errors.Is(err, ErrBusy) {
		t.Fatalf("une analyse à la demande toutes les cinq minutes au plus : %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{Enabled: true, CT: true, CTEndpoint: "https://crt.sh", Resolver: "9.9.9.9:53", IntervalHours: 12, TrustedIssuers: []string{"Cloudflare"}, CAIssuer: "letsencrypt.org"}
	if err := ok.Validate(nil); err != nil {
		t.Fatalf("réglage valide refusé : %v", err)
	}
	bad := map[string]Config{
		"cadence trop courte": {IntervalHours: 1},
		"cadence trop longue": {IntervalHours: 1000},
		"journal en clair":    {CTEndpoint: "http://crt.sh"},
		"résolveur sans port": {Resolver: "9.9.9.9"},
		"émetteur vide":       {TrustedIssuers: []string{" "}},
		"autorité mal formée": {CAIssuer: "let's encrypt"},
		"trop d'émetteurs":    {TrustedIssuers: make([]string, maxTrustedIssuers+1)},
	}
	for name, c := range bad {
		if c.Validate(nil) == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
	if err := (Config{CTEndpoint: "https://10.0.0.5"}).Validate(func(string) error { return errors.New("adresse privée") }); err == nil {
		t.Fatal("le contrôle d'adresse du journal doit s'appliquer")
	}
}

func TestHTTPCTReadsACrtShStyleAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "app.example.fr" || r.URL.Query().Get("output") != "json" {
			http.Error(w, "mauvaise requête", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[{"id":1,"serial_number":"03AC","issuer_name":"C=US, O=Let's Encrypt, CN=R11","name_value":"app.example.fr\nwww.example.fr","not_before":"2026-10-01T00:00:00","not_after":"2027-01-01T00:00:00"}]`))
	}))
	defer srv.Close()
	got, err := HTTPCT{}.Fetch(context.Background(), srv.URL, "app.example.fr")
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	e := got[0]
	if e.Serial != "03AC" || len(e.Names) != 2 || e.NotAfter.Year() != 2027 || !strings.Contains(e.Issuer, "Let's Encrypt") {
		t.Fatalf("entrée : %+v", e)
	}
	for code, body := range map[int]string{http.StatusNotFound: "", http.StatusOK: ""} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code); _, _ = w.Write([]byte(body)) }))
		if got, err := (HTTPCT{}).Fetch(context.Background(), s.URL, "x.example.fr"); err != nil || len(got) != 0 {
			t.Errorf("HTTP %d sans contenu : aucune entrée, pas d'erreur (%v %v)", code, got, err)
		}
		s.Close()
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer bad.Close()
	if _, err := (HTTPCT{}).Fetch(context.Background(), bad.URL, "x.example.fr"); err == nil {
		t.Fatal("une erreur du journal doit remonter")
	}
}
