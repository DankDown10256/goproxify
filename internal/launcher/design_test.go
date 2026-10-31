// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAccessCode = "ABCD-EFGH"

// syncWriter reçoit la sortie du launcher, écrite par ses goroutines, et la relit sans course.
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func designStartListen(t *testing.T, mutate func(*ListenOptions)) *listenFixture {
	t.Helper()
	return startListen(t, func(o *ListenOptions) {
		o.AccessCode = testAccessCode
		if mutate != nil {
			mutate(o)
		}
	})
}

// login ouvre une session avec le code et rend son cookie.
func (f *listenFixture) login(code string) (*http.Response, *http.Cookie) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.base+"/design/login", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == designCookie {
			return resp, c
		}
	}
	return resp, nil
}

func (f *listenFixture) session() *http.Cookie {
	f.t.Helper()
	resp, c := f.login(testAccessCode)
	if resp.StatusCode != http.StatusSeeOther || c == nil {
		f.t.Fatalf("connexion refusée : %d", resp.StatusCode)
	}
	return c
}

func (f *listenFixture) call(method, path string, c *http.Cookie, body any, hdr map[string]string) (int, map[string]any) {
	f.t.Helper()
	var rd bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&rd).Encode(body)
	}
	req, _ := http.NewRequest(method, f.base+path, &rd)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	if c != nil {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func soloRequest() DesignRequest {
	return DesignRequest{
		Hosts: []DesignHost{{Addr: "192.168.1.10", Roles: []string{"admin", "edge", "agent"}, Local: true}},
		Email: "me@lan.fr",
	}
}

func TestDesignRequestTopology(t *testing.T) {
	t.Run("nom déduit de l'adresse, hôte unique local d'office", func(t *testing.T) {
		r := DesignRequest{Hosts: []DesignHost{{Addr: "192.168.1.10", Roles: []string{"admin", "edge"}}}}
		topo, err := r.Topology()
		if err != nil {
			t.Fatal(err)
		}
		if topo.Local != "host-192-168-1-10" || topo.Hosts[0].Name != topo.Local {
			t.Errorf("topologie = %+v", topo)
		}
	})
	t.Run("plusieurs hôtes", func(t *testing.T) {
		r := DesignRequest{Hosts: []DesignHost{
			{Name: "main", Addr: "192.168.1.10", Roles: []string{"admin", "edge", "agent"}, Local: true},
			{Addr: "192.168.1.50", Roles: []string{"agent"}},
		}}
		topo, err := r.Topology()
		if err != nil || topo.Local != "main" || len(topo.Hosts) != 2 {
			t.Fatalf("topo = %+v, err = %v", topo, err)
		}
	})
	for name, r := range map[string]DesignRequest{
		"aucun hôte local désigné": {Hosts: []DesignHost{
			{Addr: "10.0.0.1", Roles: []string{"admin", "edge"}}, {Addr: "10.0.0.2", Roles: []string{"agent"}}}},
		"deux hôtes locaux": {Hosts: []DesignHost{
			{Addr: "10.0.0.1", Roles: []string{"admin", "edge"}, Local: true}, {Addr: "10.0.0.2", Roles: []string{"agent"}, Local: true}}},
		"adresse invalide":                    {Hosts: []DesignHost{{Addr: "10.0.0.1; rm -rf /", Roles: []string{"admin", "edge"}, Local: true}}},
		"adresse vide":                        {Hosts: []DesignHost{{Addr: "", Roles: []string{"admin", "edge"}, Local: true}}},
		"deux Admin":                          {Hosts: []DesignHost{{Addr: "10.0.0.1", Roles: []string{"admin", "edge"}, Local: true}, {Addr: "10.0.0.2", Roles: []string{"admin", "agent"}}}},
		"Admin ailleurs que sur l'hôte local": {Hosts: []DesignHost{{Addr: "10.0.0.1", Roles: []string{"edge"}, Local: true}, {Addr: "10.0.0.2", Roles: []string{"admin"}}}},
		"pas d'Admin":                         {Hosts: []DesignHost{{Addr: "10.0.0.1", Roles: []string{"edge"}, Local: true}}},
		"rôle inconnu":                        {Hosts: []DesignHost{{Addr: "10.0.0.1", Roles: []string{"admin", "edge", "root"}, Local: true}}},
		"aucun hôte":                          {},
		"groupe sans edge":                    {Hosts: []DesignHost{{Addr: "10.0.0.1", Roles: []string{"admin", "edge"}, Local: true}, {Addr: "10.0.0.2", Roles: []string{"agent"}, Group: "g"}}},
	} {
		if _, err := r.Topology(); err == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
}

func TestAccessCode(t *testing.T) {
	re := regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := NewAccessCode()
		if err != nil || !re.MatchString(c) {
			t.Fatalf("code = %q, err = %v", c, err)
		}
		seen[c] = true
	}
	if len(seen) < 49 {
		t.Error("les codes doivent être aléatoires")
	}
	if normalizeCode(" abcd-efgh ") != "ABCDEFGH" {
		t.Error("le code se saisit sans tiret ni casse")
	}
}

func TestDesignNeedsTheAccessCode(t *testing.T) {
	f := designStartListen(t, nil)

	code, hdr, body := f.get(f.base + "/design")
	if code != http.StatusOK || !strings.Contains(body, `name="code"`) || strings.Contains(body, "<script") {
		t.Fatalf("sans session, la page demande le code : %d %s", code, body)
	}
	if strings.Contains(hdr.Get("Content-Security-Policy"), "script-src") {
		t.Error("la page de connexion n'exécute aucun script")
	}
	for _, p := range []string{"/design/api/state", "/design/api/status"} {
		if st, _ := f.call(http.MethodGet, p, nil, nil, nil); st != http.StatusUnauthorized {
			t.Errorf("GET %s sans session = %d", p, st)
		}
	}
	for _, p := range []string{"/design/api/plan", "/design/api/deploy", "/design/api/finish"} {
		if st, _ := f.call(http.MethodPost, p, nil, soloRequest(), nil); st != http.StatusUnauthorized {
			t.Errorf("POST %s sans session = %d", p, st)
		}
	}
	if len(f.api.created) != 0 {
		t.Error("rien ne doit être créé sans le code")
	}

	if resp, c := f.login("ZZZZ-ZZZZ"); resp.StatusCode != http.StatusForbidden || c != nil {
		t.Errorf("mauvais code = %d, cookie %v", resp.StatusCode, c)
	}
	resp, c := f.login(" abcd efgh ")
	if resp.StatusCode != http.StatusSeeOther || c == nil {
		t.Fatalf("bon code (saisie libre) = %d", resp.StatusCode)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/design" {
		t.Errorf("cookie de session = %+v", c)
	}
}

func TestDesignPageCarriesANonceAndNoLooseScript(t *testing.T) {
	f := designStartListen(t, nil)
	c := f.session()
	req, _ := http.NewRequest(http.MethodGet, f.base+"/design", nil)
	req.AddCookie(c)
	resp, err := f.cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	csp := resp.Header.Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'nonce-([0-9a-f]+)'`).FindStringSubmatch(csp)
	if m == nil || strings.Contains(csp, "script-src 'unsafe-inline'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("CSP = %s", csp)
	}
	if !strings.Contains(buf.String(), `<script nonce="`+m[1]+`">`) {
		t.Error("le script de la page porte le nonce de la réponse")
	}
	if strings.Count(buf.String(), "<script") != 1 || strings.Contains(buf.String(), " onclick=") {
		t.Error("un seul script, sans gestionnaire en ligne")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("la page ne se met pas en cache")
	}
}

func TestDesignLocksAfterTooManyWrongCodes(t *testing.T) {
	f := designStartListen(t, nil)
	for i := 0; i < maxCodeFailures; i++ {
		f.login("AAAA-AAAA")
	}
	resp, c := f.login(testAccessCode)
	if resp.StatusCode != http.StatusTooManyRequests || c != nil {
		t.Fatalf("même le bon code est refusé pendant le verrouillage : %d", resp.StatusCode)
	}
}

func TestDesignLockoutExpires(t *testing.T) {
	d := &designState{code: testAccessCode}
	now := time.Now()
	for i := 0; i < maxCodeFailures; i++ {
		d.check("nope", now)
	}
	if ok, locked := d.check(testAccessCode, now.Add(time.Second)); ok || locked <= 0 {
		t.Error("verrouillé")
	}
	if ok, _ := d.check(testAccessCode, now.Add(codeLockout+time.Second)); !ok {
		t.Error("le verrouillage est levé après la minute")
	}
}

func TestDesignWritesComeFromThePage(t *testing.T) {
	f := designStartListen(t, nil)
	c := f.session()
	if st, _ := f.call(http.MethodPost, "/design/api/deploy", c, soloRequest(), map[string]string{"Origin": "http://evil.example"}); st != http.StatusForbidden {
		t.Errorf("origine étrangère = %d", st)
	}
	if st, _ := f.call(http.MethodPost, "/design/api/deploy", c, soloRequest(), map[string]string{"Sec-Fetch-Site": "cross-site"}); st != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site cross-site = %d", st)
	}
	if st, _ := f.call(http.MethodPost, "/design/api/deploy", c, soloRequest(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); st != http.StatusForbidden {
		t.Errorf("type non JSON (formulaire d'une autre page) = %d", st)
	}
	if len(f.api.created) != 0 {
		t.Error("rien ne doit être créé")
	}
}

func TestDesignStatePrefillsFromTheCommandLine(t *testing.T) {
	topo := &Topology{Local: "main", Hosts: []Host{
		{Name: "main", Addr: "192.168.1.10", Roles: []string{"edge", "agent"}},
		{Name: "nas", Addr: "192.168.1.60", Roles: []string{"agent"}},
	}}
	f := designStartListen(t, func(o *ListenOptions) {
		o.Initial, o.InitialEmail, o.InitialNote = topo, "me@lan.fr", "Topologie à compléter : il faut exactement un Admin"
	})
	st, got := f.call(http.MethodGet, "/design/api/state", f.session(), nil, nil)
	if st != http.StatusOK || got["message"] == "" {
		t.Fatalf("état = %d %v", st, got)
	}
	req := got["request"].(map[string]any)
	hosts := req["hosts"].([]any)
	if req["email"] != "me@lan.fr" || len(hosts) != 2 || hosts[0].(map[string]any)["local"] != true {
		t.Errorf("préremplissage = %v", req)
	}
}

func TestDesignPlanCreatesNothing(t *testing.T) {
	f := designStartListen(t, nil)
	c := f.session()
	st, got := f.call(http.MethodPost, "/design/api/plan", c, soloRequest(), nil)
	if st != http.StatusOK || got["admin_url"] != "https://192.168.1.10:9443" || len(got["pull"].([]any)) != 3 {
		t.Fatalf("plan = %d %v", st, got)
	}
	for _, k := range []string{"pull", "networks", "volumes", "pending"} {
		if _, ok := got[k].([]any); !ok {
			t.Errorf("%s doit être une liste (la page lit .length), reçu %#v", k, got[k])
		}
	}
	if len(f.api.created) != 0 || len(f.api.pulled) != 0 {
		t.Errorf("la simulation n'écrit rien : %v %v", f.api.created, f.api.pulled)
	}
	bad := soloRequest()
	bad.Hosts[0].Roles = []string{"agent"}
	if st, got := f.call(http.MethodPost, "/design/api/plan", c, bad, nil); st != http.StatusBadRequest || got["error"] == nil {
		t.Errorf("topologie incohérente = %d %v", st, got)
	}
}

// waitDesign attend la fin (ou l'échec) de l'installation lancée par l'interface.
func (f *listenFixture) waitDesign(c *http.Cookie) map[string]any {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, s := f.call(http.MethodGet, "/design/api/status", c, nil, nil)
		if s["done"] == true || (s["error"] != nil && s["error"] != "") {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatal("installation non terminée")
	return nil
}

func TestDesignInstallsThenFinishes(t *testing.T) {
	out := &syncWriter{}
	f := designStartListen(t, func(o *ListenOptions) { o.Out = out; o.Linger = time.Hour })
	c := f.session()

	two := DesignRequest{Email: "me@lan.fr", Hosts: []DesignHost{
		{Name: "main", Addr: "192.168.1.10", Roles: []string{"admin", "edge", "agent"}, Local: true},
		{Name: "nas", Addr: "192.168.1.60", Roles: []string{"agent"}},
	}}
	if st, got := f.call(http.MethodPost, "/design/api/deploy", c, two, nil); st != http.StatusAccepted {
		t.Fatalf("deploy = %d %v", st, got)
	}
	s := f.waitDesign(c)
	if s["done"] != true || s["error"] != "" {
		t.Fatalf("statut = %v", s)
	}
	rep := s["report"].(map[string]any)
	if rep["admin_url"] != "https://192.168.1.10:9443" || rep["email"] != "me@lan.fr" || len(rep["password"].(string)) < 16 ||
		len(rep["fingerprint"].(string)) != 64 || len(rep["pending"].([]any)) != 1 {
		t.Errorf("rapport = %v", rep)
	}
	if _, ok := rep["containers"].([]any); !ok {
		t.Errorf("containers doit être une liste : %#v", rep["containers"])
	}
	if len(s["steps"].([]any)) == 0 {
		t.Error("l'avancement est exposé")
	}
	f.api.mu.Lock()
	created := strings.Join(f.api.created, ",")
	f.api.mu.Unlock()
	if created != "goproxify-admin,goproxify-edge,goproxify-agent" {
		t.Errorf("créés = %s", created)
	}
	if !strings.Contains(out.String(), rep["password"].(string)) {
		t.Error("le mot de passe est aussi écrit dans la sortie du conteneur, une seule fois")
	}
	if key, _ := rep["backup_key"].(string); len(key) != 64 {
		t.Errorf("le rapport donne la clé de sauvegarde : %v", rep["backup_key"])
	}

	// Une seule installation par launcher.
	if st, _ := f.call(http.MethodPost, "/design/api/deploy", c, two, nil); st != http.StatusConflict {
		t.Errorf("deuxième installation = %d", st)
	}
	if code, _, _ := f.get(f.joinURL(nil)); code != http.StatusSeeOther {
		t.Errorf("un lien de QR code n'installe plus rien après une installation : %d", code)
	}

	// « Terminer » fait sortir le launcher sans attendre la fin du délai de lecture.
	if st, _ := f.call(http.MethodPost, "/design/api/finish", c, struct{}{}, nil); st != http.StatusOK {
		t.Fatalf("finish = %d", st)
	}
	f.wait(nil)
}

func TestDesignFinishNeedsAFinishedInstall(t *testing.T) {
	f := designStartListen(t, nil)
	c := f.session()
	if st, _ := f.call(http.MethodPost, "/design/api/finish", c, struct{}{}, nil); st != http.StatusConflict {
		t.Errorf("finish sans installation = %d", st)
	}
	if _, s := f.call(http.MethodGet, "/design/api/status", c, nil, nil); s["started"] != false {
		t.Errorf("statut initial = %v", s)
	} else if _, ok := s["steps"].([]any); !ok {
		t.Errorf("steps doit être une liste (la page lit .forEach), reçu %#v", s["steps"])
	}
}

// failingStart fait échouer le premier démarrage de conteneur, comme un démon qui refuse.
type failingStart struct {
	*fakeAPI
	failed atomic.Bool
}

func (f *failingStart) Post(ctx context.Context, path string, body any, out any) error {
	if strings.HasSuffix(strings.SplitN(path, "?", 2)[0], "/start") && f.failed.CompareAndSwap(false, true) {
		return context.DeadlineExceeded
	}
	return f.fakeAPI.Post(ctx, path, body, out)
}

func TestDesignFailedInstallCanBeRetried(t *testing.T) {
	api := &failingStart{fakeAPI: newFakeAPI()}
	f := designStartListen(t, func(o *ListenOptions) { o.API = api; o.Linger = time.Hour })
	c := f.session()

	if st, _ := f.call(http.MethodPost, "/design/api/deploy", c, soloRequest(), nil); st != http.StatusAccepted {
		t.Fatalf("deploy = %d", st)
	}
	s := f.waitDesign(c)
	if s["done"] == true || s["error"] == "" {
		t.Fatalf("l'échec est signalé : %v", s)
	}
	// L'utilisateur corrige et recommence depuis la même page.
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, _ := f.call(http.MethodPost, "/design/api/deploy", c, soloRequest(), nil)
		if st == http.StatusAccepted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relance refusée : %d", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s := f.waitDesign(c); s["done"] != true {
		t.Fatalf("la relance aboutit : %v", s)
	}
}

func TestDesignActivityExtendsTheWindow(t *testing.T) {
	f := designStartListen(t, func(o *ListenOptions) { o.Window = 400 * time.Millisecond })
	c := f.session()
	// Une personne est en train de concevoir : 1,2 s d'activité sur une fenêtre de 0,4 s.
	for i := 0; i < 12; i++ {
		select {
		case err := <-f.done:
			t.Fatalf("le launcher a quitté malgré l'activité : %v", err)
		default:
		}
		if st, _ := f.call(http.MethodGet, "/design/api/state", c, nil, nil); st != http.StatusOK {
			t.Fatalf("état = %d", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Puis plus rien : la fenêtre se referme.
	f.wait(ErrWindowElapsed)
}

func TestDesignWindowStillElapsesWithoutActivity(t *testing.T) {
	f := designStartListen(t, func(o *ListenOptions) { o.Window = 200 * time.Millisecond })
	f.wait(ErrWindowElapsed)
}

func TestWaitingPageLinksToTheDesigner(t *testing.T) {
	f := designStartListen(t, nil)
	_, _, body := f.get(f.base + "/")
	if !strings.Contains(body, `href="/design"`) {
		t.Error("la page d'attente propose l'interface de conception")
	}
	if strings.Contains(body, testAccessCode) {
		t.Error("le code d'accès n'est jamais servi")
	}
}

func TestListenPrintsTheAccessCodeInItsOutput(t *testing.T) {
	out := &syncWriter{}
	_ = designStartListen(t, func(o *ListenOptions) { o.Out = out })
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(out.String(), testAccessCode) {
		if time.Now().After(deadline) {
			t.Fatalf("le code doit apparaître dans la sortie : %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestListenGeneratesAnAccessCodeByDefault(t *testing.T) {
	out := &syncWriter{}
	_ = startListen(t, func(o *ListenOptions) { o.Out = out })
	deadline := time.Now().Add(2 * time.Second)
	re := regexp.MustCompile(`Code d'accès : ([A-Z2-9]{4}-[A-Z2-9]{4})`)
	for re.FindStringSubmatch(out.String()) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("pas de code dans la sortie : %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// upload envoie le fichier d'une sauvegarde à la page, comme son script : corps brut, clé en en-tête.
func (f *listenFixture) upload(c *http.Cookie, data []byte, key, contentType string) (int, map[string]any) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.base+"/design/api/restore", bytes.NewReader(data))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Backup-Key", key)
	if c != nil {
		req.AddCookie(c)
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestDesignRebuildsAnAdminFromABackup(t *testing.T) {
	data, cert := makeBackup(t, true)
	out := &syncWriter{}
	f := designStartListen(t, func(o *ListenOptions) { o.Out = out; o.Linger = time.Hour })
	c := f.session()

	if _, st := f.call(http.MethodGet, "/design/api/state", c, nil, nil); st["restore_email"] != RestoreAdminEmail {
		t.Errorf("la page connaît le compte temporaire : %v", st)
	}
	st, info := f.upload(c, data, restoreKey, "application/octet-stream")
	if st != http.StatusOK || info["has_cert"] != true || info["fingerprint"] != cert.Fingerprint {
		t.Fatalf("lecture de la sauvegarde = %d %v", st, info)
	}
	hosts, _ := info["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("les hôtes de la sauvegarde sont rendus pour choisir cette machine : %v", info["hosts"])
	}

	req := DesignRequest{Restore: &DesignRestore{Local: "main"}}
	if st, plan := f.call(http.MethodPost, "/design/api/plan", c, req, nil); st != http.StatusOK {
		t.Fatalf("la simulation doit passer : %d %v", st, plan)
	}
	f.api.mu.Lock()
	nothing := len(f.api.created)
	f.api.mu.Unlock()
	if nothing != 0 {
		t.Fatal("la simulation ne crée rien")
	}
	if st, got := f.call(http.MethodPost, "/design/api/deploy", c, req, nil); st != http.StatusAccepted {
		t.Fatalf("deploy = %d %v", st, got)
	}
	s := f.waitDesign(c)
	if s["done"] != true || s["error"] != "" {
		t.Fatalf("statut = %v", s)
	}
	rep := s["report"].(map[string]any)
	if rep["restored"] != true || rep["kept_certificate"] != true || rep["fingerprint"] != cert.Fingerprint || rep["email"] != RestoreAdminEmail {
		t.Errorf("rapport = %v", rep)
	}
	f.api.mu.Lock()
	defer f.api.mu.Unlock()
	env := envOf(t, f.api.bodies["goproxify-admin"])
	if env["GPX_PAIRING_SECRET"] != restoreRoot || env["GPX_BACKUP_KEY"] != restoreKey {
		t.Errorf("l'Admin reprend le secret racine et la clé de la sauvegarde : %v", env)
	}
	if f.api.files["/etc/goproxify/state/architecture.json"] != restoreArchitecture {
		t.Error("architecture.json est déposé tel que sauvegardé")
	}
	if got := envOf(t, f.api.bodies["goproxify-edge"])["GPX_EDGE_CHANNEL_KEY"]; got == "" {
		t.Error("la passerelle reçoit sa clé de canal")
	}
}

func TestDesignRestoreIsGuarded(t *testing.T) {
	data, _ := makeBackup(t, true)
	f := designStartListen(t, nil)

	if st, _ := f.upload(nil, data, restoreKey, "application/octet-stream"); st != http.StatusUnauthorized {
		t.Errorf("sans session : %d", st)
	}
	c := f.session()
	if st, _ := f.upload(c, data, restoreKey, "application/json"); st != http.StatusForbidden {
		t.Errorf("le fichier se envoie en octet-stream, comme la page : %d", st)
	}
	if st, out := f.upload(c, data, "une-autre-cle", "application/octet-stream"); st != http.StatusUnprocessableEntity || !strings.Contains(out["error"].(string), "secrets") {
		t.Errorf("mauvaise clé : %d %v", st, out)
	}
	if st, out := f.upload(c, []byte("pas une sauvegarde"), restoreKey, "application/octet-stream"); st != http.StatusUnprocessableEntity {
		t.Errorf("fichier illisible : %d %v", st, out)
	}

	req := DesignRequest{Restore: &DesignRestore{Local: "main"}}
	if st, out := f.call(http.MethodPost, "/design/api/deploy", c, req, nil); st != http.StatusBadRequest || !strings.Contains(out["error"].(string), "aucune sauvegarde") {
		t.Errorf("reconstruire sans avoir lu de sauvegarde : %d %v", st, out)
	}

	// Une sauvegarde lue puis abandonnée ne reste pas utilisable.
	if st, _ := f.upload(c, data, restoreKey, "application/octet-stream"); st != http.StatusOK {
		t.Fatal("lecture")
	}
	if st, _ := f.call(http.MethodPost, "/design/api/restore/clear", c, struct{}{}, nil); st != http.StatusOK {
		t.Fatal("abandon")
	}
	if st, _ := f.call(http.MethodPost, "/design/api/deploy", c, req, nil); st != http.StatusBadRequest {
		t.Errorf("après l'abandon, plus de reconstruction : %d", st)
	}

	// Il faut dire laquelle des machines de la sauvegarde est celle-ci.
	if st, _ := f.upload(c, data, restoreKey, "application/octet-stream"); st != http.StatusOK {
		t.Fatal("lecture")
	}
	if st, out := f.call(http.MethodPost, "/design/api/plan", c, DesignRequest{Restore: &DesignRestore{Local: "inconnue"}}, nil); st != http.StatusBadRequest {
		t.Errorf("hôte inconnu : %d %v", st, out)
	}
}

func TestDesignDiagramFollowsTheDraftWithoutRequiringItToBeValid(t *testing.T) {
	f := designStartListen(t, nil)
	if st, _ := f.call(http.MethodPost, "/design/api/diagram", nil, DesignRequest{}, nil); st != http.StatusUnauthorized {
		t.Errorf("sans session : %d", st)
	}
	c := f.session()

	// Une saisie à moitié faite : pas d'adresse, pas de nom, un rôle inconnu.
	draft := DesignRequest{Hosts: []DesignHost{
		{Roles: []string{"admin", "edge", "bogus"}, Local: true},
		{Addr: "192.168.1.60", Roles: []string{"agent"}},
	}}
	st, out := f.call(http.MethodPost, "/design/api/diagram", c, draft, nil)
	if st != http.StatusOK {
		t.Fatalf("un brouillon se dessine : %d %v", st, out)
	}
	mm, _ := out["mermaid"].(string)
	svg, _ := out["svg"].(string)
	if !strings.HasPrefix(mm, "flowchart LR") || !strings.Contains(mm, "hôte 1") || !strings.Contains(mm, "host-192-168-1-60") {
		t.Errorf("mermaid = %s", mm)
	}
	if !strings.HasPrefix(svg, "<svg") || strings.Contains(svg, "bogus") {
		t.Errorf("svg = %.120s", svg)
	}

	// Sans hôte : un schéma Mermaid vide et pas de dessin, la page affiche son invite.
	if st, out := f.call(http.MethodPost, "/design/api/diagram", c, DesignRequest{}, nil); st != http.StatusOK || out["svg"] != "" {
		t.Errorf("sans hôte : %d %v", st, out)
	}
	if st, _ := f.call(http.MethodPost, "/design/api/diagram", c, DesignRequest{}, map[string]string{"Content-Type": "text/plain"}); st != http.StatusForbidden {
		t.Errorf("une écriture doit venir de la page : %d", st)
	}
}

func TestDesignDiagramOfABackupFollowsItsTopology(t *testing.T) {
	data, _ := makeBackup(t, true)
	f := designStartListen(t, nil)
	c := f.session()

	req := DesignRequest{Restore: &DesignRestore{Local: "main"}}
	if st, out := f.call(http.MethodPost, "/design/api/diagram", c, req, nil); st != http.StatusBadRequest {
		t.Errorf("avant d'avoir lu la sauvegarde : %d %v", st, out)
	}
	if st, _ := f.upload(c, data, restoreKey, "application/octet-stream"); st != http.StatusOK {
		t.Fatal("lecture")
	}
	st, out := f.call(http.MethodPost, "/design/api/diagram", c, req, nil)
	if st != http.StatusOK {
		t.Fatalf("diagramme de la sauvegarde : %d %v", st, out)
	}
	mm := out["mermaid"].(string)
	for _, want := range []string{"main · 10.0.0.1 (cette machine)", "nas · 10.0.0.2", "h0_admin", "h0_edge", "h1_agent -->|routes|"} {
		if !strings.Contains(mm, want) {
			t.Errorf("le schéma doit montrer %q :\n%s", want, mm)
		}
	}
	moved := DesignRequest{Restore: &DesignRestore{Local: "main", Addr: "192.168.1.99"}}
	if _, out := f.call(http.MethodPost, "/design/api/diagram", c, moved, nil); !strings.Contains(out["mermaid"].(string), "main · 192.168.1.99") {
		t.Error("l'adresse changée de cette machine se voit dans le schéma")
	}
	if st, _ := f.call(http.MethodPost, "/design/api/diagram", c, DesignRequest{Restore: &DesignRestore{Local: "inconnue"}}, nil); st != http.StatusBadRequest {
		t.Errorf("hôte inconnu : %d", st)
	}
}

func TestDesignPageOffersTheDiagramAndKeepsItsCSPClean(t *testing.T) {
	f := designStartListen(t, nil)
	c := f.session()
	req, _ := http.NewRequest(http.MethodGet, f.base+"/design", nil)
	req.AddCookie(c)
	resp, err := f.cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	page := buf.String()
	for _, want := range []string{`id="dg-view"`, `id="mm-src"`, `id="mm-copy"`, `id="src-restore"`, "prefers-color-scheme", "--accent"} {
		if !strings.Contains(page, want) {
			t.Errorf("la page doit contenir %q", want)
		}
	}
	if strings.Contains(page, "http://") && strings.Contains(page, "src=\"http") || strings.Contains(page, "cdn.") || strings.Contains(page, "<link ") {
		t.Error("aucune ressource externe : la page est servie hors ligne")
	}
	if strings.Contains(resp.Header.Get("Content-Security-Policy"), "img-src") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("la CSP reste fermée : %s", resp.Header.Get("Content-Security-Policy"))
	}
}
