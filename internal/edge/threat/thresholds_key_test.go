// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

const stuffing = "stuffing"

func stuffingConfig(mode string) ThresholdsConfig {
	return ThresholdsConfig{
		Logins: []LoginRoute{{Path: "/login", Field: "email"}},
		Rules: []ThresholdRule{{
			Name: stuffing, Mode: mode, By: ThresholdByAccount, Status: []string{"401"}, Paths: []string{"/login"},
			Count: 5, Window: Duration{10 * time.Minute},
		}},
	}
}

// loginReq : une connexion JSON portant une observation, comme celle que le dispatch fabrique.
func loginReq(account string) *http.Request {
	r := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"`+account+`","password":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	ctx, _ := behavior.WithObservation(context.Background())
	return r.WithContext(ctx)
}

// attempt joue ce que fait la passerelle : lecture avant la route, réponse, puis observation. Rend la protection rencontrée.
func attempt(e *Engine, ip, account string, status int) *KeyGuard {
	r := loginReq(account)
	g := e.KeyProtection(r, "app.test", ip)
	e.Observe(r, ip, "app.test", status)
	return g
}

func ipN(i int) string { return "198.51.100." + string(rune('1'+i)) }

func TestDistributedStuffingProtectsTheAccountNotTheIPs(t *testing.T) {
	e, _, bans := thresholdEngine(t, stuffingConfig(ThresholdBlock))
	for i := 0; i < 5; i++ {
		if g := attempt(e, ipN(i), "victime@example.fr", 401); g != nil {
			t.Fatalf("tentative %d : rien à protéger encore", i)
		}
	}
	if len(*bans) != 0 {
		t.Fatalf("un Seuil à clé ne bannit jamais : %+v", *bans)
	}
	if e.ProtectedKeys() != 1 {
		t.Fatalf("le compte visé doit être sous protection : %d clés", e.ProtectedKeys())
	}

	g := attempt(e, "203.0.113.50", "victime@example.fr", 401)
	if g == nil || g.Rule != stuffing || g.By != ThresholdByAccount {
		t.Fatalf("une IP inconnue qui vise le compte protégé doit être soumise à la protection : %+v", g)
	}
	now := e.counters.now()
	allowed := 0
	for i := 0; i < 10; i++ {
		if g.Allow(now) {
			allowed++
		}
	}
	if allowed != defaultProtectRate {
		t.Fatalf("trois tentatives par minute pour l'ensemble des IP sans historique : %d admises", allowed)
	}

	if g := attempt(e, "203.0.113.50", "autre@example.fr", 401); g != nil {
		t.Fatalf("un autre compte n'est pas protégé : %+v", g)
	}
}

func TestAccountsAreNormalizedAndNeverStoredInClear(t *testing.T) {
	e, _, _ := thresholdEngine(t, stuffingConfig(ThresholdBlock))
	variants := []string{"Victime@Example.fr", " victime@example.fr", "VICTIME@EXAMPLE.FR", "victime@example.fr", "victime@example.fr"}
	for i, v := range variants {
		attempt(e, ipN(i), v, 401)
	}
	if e.ProtectedKeys() != 1 {
		t.Fatalf("la casse et les espaces de bord ne changent pas le compte : %d clés", e.ProtectedKeys())
	}
	for i := range e.keyCounters.shards {
		for k := range e.keyCounters.shards[i].m {
			if strings.Contains(k, "victime") {
				t.Fatalf("l'identifiant ne doit jamais figurer dans une clé : %q", k)
			}
		}
	}
	e.protected.mu.Lock()
	defer e.protected.mu.Unlock()
	for k := range e.protected.m {
		if strings.Contains(k, "victime") {
			t.Fatalf("l'identifiant ne doit jamais figurer dans une protection : %q", k)
		}
	}
}

func TestProtectionEndsAfterProtectFor(t *testing.T) {
	e, now, _ := thresholdEngine(t, stuffingConfig(ThresholdBlock))
	for i := 0; i < 5; i++ {
		attempt(e, ipN(i), "victime@example.fr", 401)
	}
	if attempt(e, "203.0.113.50", "victime@example.fr", 200) == nil {
		t.Fatal("prérequis : protégé")
	}
	*now = now.Add(defaultProtectFor + time.Second)
	if g := attempt(e, "203.0.113.50", "victime@example.fr", 200); g != nil {
		t.Fatalf("la protection tombe d'elle-même : %+v", g)
	}
}

func TestDetectModeCountsButNeverProtects(t *testing.T) {
	e, _, _ := thresholdEngine(t, stuffingConfig(ThresholdDetect))
	before := thresholdCount("key_shadow")
	for i := 0; i < 5; i++ {
		attempt(e, ipN(i), "victime@example.fr", 401)
	}
	if thresholdCount("key_shadow") != before+1 || e.ProtectedKeys() != 0 {
		t.Fatalf("detect : le dépassement est compté, rien n'est protégé (%d clés)", e.ProtectedKeys())
	}
	if g := attempt(e, "203.0.113.50", "victime@example.fr", 401); g != nil {
		t.Fatalf("detect ne limite rien : %+v", g)
	}
}

func TestWhitelistedIPsAreNeverGuarded(t *testing.T) {
	e, _, _ := thresholdEngine(t, stuffingConfig(ThresholdBlock), func(c *Config) {
		c.Whitelist = Whitelist{IPs: []string{"203.0.113.9/32"}}
	})
	for i := 0; i < 5; i++ {
		attempt(e, ipN(i), "victime@example.fr", 401)
	}
	if g := attempt(e, "203.0.113.9", "victime@example.fr", 200); g != nil {
		t.Fatalf("la liste blanche d'Ephor passe : %+v", g)
	}
	if g := attempt(e, "203.0.113.10", "victime@example.fr", 200); g == nil {
		t.Fatal("une autre IP reste soumise")
	}
}

func TestLoginBodyIsReadOnlyOnDeclaredRoutesAndGivenBackToTheBackend(t *testing.T) {
	e, _, _ := thresholdEngine(t, stuffingConfig(ThresholdBlock))

	r := loginReq("victime@example.fr")
	e.KeyProtection(r, "app.test", "198.51.100.1")
	rest, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(rest), `"password":"x"`) || !strings.Contains(string(rest), "victime@example.fr") {
		t.Fatalf("le backend doit recevoir le corps entier : %q", rest)
	}

	other := httptest.NewRequest("POST", "/contact", strings.NewReader(`{"email":"a@b.fr"}`))
	other.Header.Set("Content-Type", "application/json")
	other = other.WithContext(r.Context())
	e.KeyProtection(other, "app.test", "198.51.100.1")
	if left, _ := io.ReadAll(other.Body); string(left) != `{"email":"a@b.fr"}` {
		t.Fatalf("hors des routes de connexion le corps n'est pas touché : %q", left)
	}

	get := httptest.NewRequest("GET", "/login?email=a@b.fr", nil)
	if g := e.KeyProtection(get, "app.test", "198.51.100.1"); g != nil {
		t.Fatal("un GET ne vise aucun compte")
	}
}

func TestLoginBodyFormatsAndLimits(t *testing.T) {
	e, _, _ := thresholdEngine(t, stuffingConfig(ThresholdBlock))
	acct := func(r *http.Request) string {
		ctx, obs := behavior.WithObservation(context.Background())
		r = r.WithContext(ctx)
		e.KeyProtection(r, "app.test", "198.51.100.1")
		return obs.Account()
	}
	form := httptest.NewRequest("POST", "/login", strings.NewReader("email=Alice%40example.fr&password=x"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	js := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"alice@example.fr"}`))
	js.Header.Set("Content-Type", "application/json; charset=utf-8")
	a, b := acct(form), acct(js)
	if a == "" || a != b {
		t.Fatalf("un formulaire et un JSON désignent le même compte : %q %q", a, b)
	}

	num := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":12345}`))
	num.Header.Set("Content-Type", "application/json")
	if acct(num) == "" {
		t.Fatal("un identifiant numérique est un identifiant")
	}

	for name, body := range map[string]string{
		"champ absent":     `{"user":"alice"}`,
		"JSON invalide":    `{"email":`,
		"identifiant long": `{"email":"` + strings.Repeat("a", accountMaxLen+1) + `"}`,
	} {
		r := httptest.NewRequest("POST", "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if got := acct(r); got != "" {
			t.Errorf("%s : aucun compte attendu, reçu %q", name, got)
		}
	}

	big := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"alice@example.fr","pad":"`+strings.Repeat("x", 3*loginBodyMax)+`"}`))
	big.Header.Set("Content-Type", "application/json")
	ctx, _ := behavior.WithObservation(context.Background())
	big = big.WithContext(ctx)
	e.KeyProtection(big, "app.test", "198.51.100.1")
	all, _ := io.ReadAll(big.Body)
	if len(all) < 3*loginBodyMax {
		t.Fatalf("un gros corps doit rester entier pour le backend : %d octets", len(all))
	}
}

func TestJA4KeyNeverTargetsAKnownBrowser(t *testing.T) {
	cfg := ThresholdsConfig{Rules: []ThresholdRule{{
		Name: "ja4-fail", Mode: ThresholdBlock, By: ThresholdByJA4, Status: []string{"401"}, Count: 3, Window: Duration{10 * time.Minute},
	}}}
	e, _, _ := thresholdEngine(t, cfg)
	e.SetBehaviorStore(behavior.NewReplayStore(0))
	fail := func(ja4, ip string) *KeyGuard {
		r := httptest.NewRequest("POST", "/x", nil)
		ctx, _ := behavior.WithObservation(tlsfp.WithContext(context.Background(), &tlsfp.Fingerprint{JA4: ja4}))
		r = r.WithContext(ctx)
		g := e.KeyProtection(r, "app.test", ip)
		e.Observe(r, ip, "app.test", 401)
		return g
	}
	const chrome, tool = "t13d1516h2_8daaf6152771_02713d6af862", "t13d1010h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	for i := 0; i < 6; i++ {
		fail(chrome, ipN(i))
	}
	if e.ProtectedKeys() != 0 {
		t.Fatal("la pile d'un navigateur connu est partagée par des millions de visiteurs : jamais une clé")
	}
	for i := 0; i < 3; i++ {
		fail(tool, ipN(i))
	}
	if g := fail(tool, "203.0.113.77"); g == nil || g.By != ThresholdByJA4 {
		t.Fatalf("une pile d'outil inconnue qui échoue depuis plusieurs IP est protégée : %+v", g)
	}
}

func TestASNKeyUsesTheGatewayDatabase(t *testing.T) {
	cfg := ThresholdsConfig{Rules: []ThresholdRule{{
		Name: "asn-fail", Mode: ThresholdBlock, By: ThresholdByASN, Status: []string{"401"}, Count: 3, Window: Duration{10 * time.Minute},
	}}}
	e, _, _ := thresholdEngine(t, cfg)
	st := behavior.NewReplayStore(0)
	st.SetASNLookup(func(ip string) uint32 {
		if strings.HasPrefix(ip, "198.51.100.") {
			return 64500
		}
		return 0
	})
	e.SetBehaviorStore(st)
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/x", nil)
		ctx, _ := behavior.WithObservation(context.Background())
		e.Observe(r.WithContext(ctx), ipN(i), "app.test", 401)
	}
	r := httptest.NewRequest("GET", "/", nil)
	ctx, _ := behavior.WithObservation(context.Background())
	if g := e.KeyProtection(r.WithContext(ctx), "app.test", "198.51.100.200"); g == nil || g.By != ThresholdByASN {
		t.Fatalf("une autre IP du même opérateur est soumise à la protection : %+v", g)
	}
	if g := e.KeyProtection(r.WithContext(ctx), "app.test", "203.0.113.5"); g != nil {
		t.Fatalf("un autre opérateur n'est pas touché : %+v", g)
	}
}

func TestKeyedThresholdValidation(t *testing.T) {
	logins := []LoginRoute{{Path: "/login", Field: "email"}}
	base := ThresholdRule{Name: "k", By: ThresholdByAccount, Count: 5, Window: Duration{time.Minute}}
	mk := func(r ThresholdRule, l []LoginRoute) Config {
		return Config{Thresholds: ThresholdsConfig{Rules: []ThresholdRule{r}, Logins: l}}
	}
	with := func(f func(*ThresholdRule)) ThresholdRule {
		r := base
		f(&r)
		return r
	}
	if err := mk(base, logins).ValidateThresholds(); err != nil {
		t.Fatalf("un Seuil by account avec une route de connexion est valide : %v", err)
	}
	protect := with(func(r *ThresholdRule) { r.Action, r.ProtectFor, r.Limit = "protect", Duration{time.Hour}, 10 })
	if err := mk(protect, logins).ValidateThresholds(); err != nil {
		t.Fatalf("action protect explicite : %v", err)
	}
	cases := map[string]Config{
		"by account sans route de connexion": mk(base, nil),
		"clé inconnue":                       mk(ThresholdRule{Name: "k", By: "pays", Count: 5, Window: Duration{time.Minute}}, logins),
		"ban sur une clé":                    mk(with(func(r *ThresholdRule) { r.Action = "ban" }), logins),
		"score sur une clé":                  mk(with(func(r *ThresholdRule) { r.Action = "score" }), logins),
		"protect par IP":                     mk(ThresholdRule{Name: "k", Action: "protect", Count: 5, Window: Duration{time.Minute}}, logins),
		"protect_for par IP":                 mk(ThresholdRule{Name: "k", ProtectFor: Duration{time.Hour}, Count: 5, Window: Duration{time.Minute}}, logins),
		"protect_for trop court":             mk(with(func(r *ThresholdRule) { r.ProtectFor = Duration{time.Second} }), logins),
		"limit trop grand":                   mk(with(func(r *ThresholdRule) { r.Limit = 100000 }), logins),
		"méthodes sans POST":                 mk(with(func(r *ThresholdRule) { r.Methods = []string{"GET"} }), logins),
		"route sans champ":                   mk(base, []LoginRoute{{Path: "/login"}}),
		"route sans barre":                   mk(base, []LoginRoute{{Path: "login", Field: "email"}}),
	}
	for name, c := range cases {
		if err := c.ValidateThresholds(); err == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
}
