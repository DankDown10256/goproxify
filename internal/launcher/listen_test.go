// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

type listenFixture struct {
	t     *testing.T
	admin *fakeAdmin
	api   *fakeAPI
	base  string // http://127.0.0.1:port du launcher
	done  chan error
	cl    *http.Client
}

// startListen lance le mode attente sur un port libre, face à un faux Admin.
func startListen(t *testing.T, mutate func(*ListenOptions)) *listenFixture {
	t.Helper()
	return startListenWithAdmin(t, newFakeAdmin(t), mutate)
}

func startListenWithAdmin(t *testing.T, admin *fakeAdmin, mutate func(*ListenOptions)) *listenFixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &listenFixture{t: t, admin: admin, api: newFakeAPI(), done: make(chan error, 1), base: "http://" + ln.Addr().String(),
		cl: &http.Client{Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	opt := ListenOptions{Listener: ln, Window: 10 * time.Second, Linger: 400 * time.Millisecond, API: f.api}
	if mutate != nil {
		mutate(&opt)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { f.done <- Listen(ctx, opt) }()
	return f
}

func (f *listenFixture) joinURL(extra url.Values) string {
	q := url.Values{"admin": {f.admin.srv.URL}, "token": {testJoinToken}, "fp": {f.admin.fp}}
	for k, v := range extra {
		q[k] = v
	}
	return f.base + "/join?" + q.Encode()
}

func (f *listenFixture) get(u string) (int, http.Header, string) {
	f.t.Helper()
	resp, err := f.cl.Get(u)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func (f *listenFixture) post(form url.Values, origin string) (int, http.Header, string) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.base+"/join", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

var nonceRe = regexp.MustCompile(`name="nonce" value="([0-9a-f]+)"`)

func (f *listenFixture) nonce(page string) string {
	m := nonceRe.FindStringSubmatch(page)
	if m == nil {
		f.t.Fatalf("pas de nonce dans la page : %s", page)
	}
	return m[1]
}

func (f *listenFixture) wait(want error) {
	f.t.Helper()
	select {
	case err := <-f.done:
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			f.t.Fatalf("Listen = %v, attendu %v", err, want)
		}
	case <-time.After(10 * time.Second):
		f.t.Fatal("Listen ne s'est pas terminé")
	}
}

func TestListenConfirmThenInstall(t *testing.T) {
	f := startListen(t, nil)

	code, hdr, page := f.get(f.joinURL(url.Values{"host": {"nas"}, "roles": {"agent"}}))
	if code != http.StatusOK {
		t.Fatalf("GET /join : %d", code)
	}
	for _, want := range []string{f.admin.srv.URL, strings.ToUpper(f.admin.fp[:2] + ":" + f.admin.fp[2:4]), "nas", "Installer"} {
		if !strings.Contains(page, want) {
			t.Errorf("la page de confirmation doit montrer %q", want)
		}
	}
	if strings.Contains(page, testJoinToken) {
		t.Error("le jeton ne doit pas être répété dans la page")
	}
	if strings.Contains(page, "<script") {
		t.Error("sans épinglage, pas de validation automatique")
	}
	if hdr.Get("Cache-Control") != "no-store" || hdr.Get("Referrer-Policy") != "same-origin" ||
		!strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("en-têtes de sécurité = %v", hdr)
	}

	// Un GET n'a aucun effet.
	if len(f.api.created) != 0 || f.admin.requests.Load() != 0 {
		t.Fatalf("GET /join ne doit rien déclencher : créés %v, requêtes à l'Admin %d", f.api.created, f.admin.requests.Load())
	}

	code, hdr, _ = f.post(url.Values{"nonce": {f.nonce(page)}}, f.base)
	if code != http.StatusSeeOther || hdr.Get("Location") != "/status" {
		t.Fatalf("POST /join : %d %v", code, hdr)
	}

	var status string
	for i := 0; i < 50; i++ {
		_, _, status = f.get(f.base + "/status")
		if strings.Contains(status, "Terminé") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(status, "Terminé") || !strings.Contains(status, "goproxify-agent") {
		t.Fatalf("page d'état = %s", status)
	}
	if !strings.Contains(status, `href="`+f.admin.srv.URL+`"`) || !strings.Contains(status, `content="5;url=`+f.admin.srv.URL+`"`) {
		t.Errorf("la page de fin doit renvoyer vers l'Admin : %s", status)
	}
	f.wait(nil)
	if len(f.api.created) != 1 || len(f.api.started) != 1 {
		t.Errorf("créés %v, démarrés %v", f.api.created, f.api.started)
	}
}

func TestListenPostNeedsTheNonceOfTheConfirmationPage(t *testing.T) {
	f := startListen(t, nil)
	_, _, page := f.get(f.joinURL(nil))
	nonce := f.nonce(page)

	if code, _, _ := f.post(url.Values{}, f.base); code != http.StatusForbidden {
		t.Errorf("POST sans nonce : %d", code)
	}
	if code, _, _ := f.post(url.Values{"nonce": {"inconnu"}}, f.base); code != http.StatusForbidden {
		t.Errorf("POST avec un nonce inconnu : %d", code)
	}
	if code, _, _ := f.post(url.Values{"nonce": {nonce}}, "http://page-pirate.example"); code != http.StatusForbidden {
		t.Errorf("POST d'une autre origine : %d", code)
	}
	if len(f.api.created) != 0 || f.admin.requests.Load() != 0 {
		t.Fatal("aucun de ces POST ne doit déclencher quoi que ce soit")
	}

	// Le nonce n'a pas été brûlé par les refus d'origine : le vrai POST passe, une seule fois.
	if code, _, _ := f.post(url.Values{"nonce": {nonce}}, f.base); code != http.StatusSeeOther {
		t.Fatalf("POST légitime : %d", code)
	}
	if code, _, _ := f.post(url.Values{"nonce": {nonce}}, f.base); code == http.StatusSeeOther {
		t.Error("un nonce ne sert qu'une fois")
	}
	f.wait(nil)
}

func TestListenOnlyOneInstallation(t *testing.T) {
	f := startListen(t, nil)
	_, _, p1 := f.get(f.joinURL(nil))
	_, _, p2 := f.get(f.joinURL(nil))
	n1, n2 := f.nonce(p1), f.nonce(p2)

	if code, _, _ := f.post(url.Values{"nonce": {n1}}, f.base); code != http.StatusSeeOther {
		t.Fatalf("premier POST : %d", code)
	}
	if code, _, _ := f.post(url.Values{"nonce": {n2}}, f.base); code != http.StatusConflict {
		t.Errorf("un seul déclenchement valide, second POST : %d", code)
	}
	f.wait(nil)
	if len(f.api.created) != 1 {
		t.Errorf("une seule installation, créés %v", f.api.created)
	}
}

func TestListenRefusesInvalidLinks(t *testing.T) {
	f := startListen(t, nil)
	for name, extra := range map[string]url.Values{
		"Admin en http":       {"admin": {"http://192.168.1.10:9443"}},
		"Admin avec chemin":   {"admin": {f.admin.srv.URL + "/x"}},
		"Admin avec identité": {"admin": {"https://u:p@192.168.1.10:9443"}},
		"jeton trop court":    {"token": {"abc"}},
		"jeton à caractères":  {"token": {"../../etc/passwd/aaaaaaaa"}},
		"empreinte invalide":  {"fp": {"nimporte"}},
	} {
		if code, _, _ := f.get(f.joinURL(extra)); code != http.StatusBadRequest {
			t.Errorf("%s : %d, attendu 400", name, code)
		}
	}
	if code, _, _ := f.get(f.base + "/join"); code != http.StatusBadRequest {
		t.Errorf("lien vide : %d", code)
	}
}

func TestListenEscapesWhatTheLinkAnnounces(t *testing.T) {
	f := startListen(t, nil)
	_, _, page := f.get(f.joinURL(url.Values{"host": {`<script>alert(1)</script>`}, "roles": {`"><img src=x>`}}))
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x>") {
		t.Errorf("le texte annoncé par le lien doit être échappé : %s", page)
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("le texte annoncé doit rester lisible, échappé")
	}
}

func TestListenPinnedAdmin(t *testing.T) {
	// Épinglage complet : le lien conforme se valide seul (par un POST de la page), tout autre est refusé.
	admin := newFakeAdmin(t)
	pinned := startListenWithAdmin(t, admin, func(o *ListenOptions) {
		o.PinnedAdmin, o.PinnedFingerprint = admin.srv.URL, admin.fp
	})
	code, hdr, page := pinned.get(pinned.joinURL(nil))
	if code != http.StatusOK || !strings.Contains(page, "<script>") ||
		!strings.Contains(hdr.Get("Content-Security-Policy"), "script-src 'unsafe-inline'") {
		t.Errorf("Admin épinglé conforme : %d, la page doit se valider seule (%q)", code, hdr.Get("Content-Security-Policy"))
	}
	if len(pinned.api.created) != 0 {
		t.Error("même épinglé, le GET n'installe rien : seul le POST de la page le fait")
	}
	if code, _, _ := pinned.get(pinned.joinURL(url.Values{"admin": {"https://192.168.1.99:9443"}})); code != http.StatusForbidden {
		t.Errorf("autre Admin : %d", code)
	}
	if code, _, _ := pinned.get(pinned.joinURL(url.Values{"fp": {strings.Repeat("00", 32)}})); code != http.StatusForbidden {
		t.Errorf("autre empreinte : %d", code)
	}
}

func TestListenWindowElapses(t *testing.T) {
	f := startListen(t, func(o *ListenOptions) { o.Window = 150 * time.Millisecond })
	f.wait(ErrWindowElapsed)
	if len(f.api.created) != 0 {
		t.Error("rien ne doit être installé sans déclenchement")
	}
}

func TestListenFailedInstallIsReportedAndLeavesNothing(t *testing.T) {
	f := startListen(t, nil)
	f.admin.handler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "ticket inconnu ou expiré", http.StatusNotFound)
	}

	_, _, page := f.get(f.joinURL(nil))
	if code, _, _ := f.post(url.Values{"nonce": {f.nonce(page)}}, f.base); code != http.StatusSeeOther {
		t.Fatalf("POST : %d", code)
	}
	var status string
	for i := 0; i < 50; i++ {
		_, _, status = f.get(f.base + "/status")
		if strings.Contains(status, "Échec") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(status, "Échec") || !strings.Contains(status, "expiré") {
		t.Fatalf("la page d'état doit dire pourquoi : %s", status)
	}
	if strings.Contains(status, "http-equiv=\"refresh\"") {
		t.Error("une fois fini, la page cesse de se rafraîchir")
	}
	err := func() error {
		select {
		case e := <-f.done:
			return e
		case <-time.After(10 * time.Second):
			return errors.New("timeout")
		}
	}()
	if err == nil || !strings.Contains(err.Error(), "expiré") {
		t.Errorf("Listen doit rendre l'erreur de l'installation : %v", err)
	}
	if len(f.api.created) != 0 {
		t.Errorf("rien ne doit rester : %v", f.api.created)
	}
}

func TestListenWaitingPageAndUnknownRoutes(t *testing.T) {
	f := startListen(t, nil)
	if code, _, page := f.get(f.base + "/"); code != http.StatusOK || !strings.Contains(page, "attend un lien") {
		t.Errorf("page d'attente : %d", code)
	}
	if code, _, _ := f.get(f.base + "/autre"); code != http.StatusNotFound {
		t.Errorf("route inconnue : %d", code)
	}
	if code, _, page := f.get(f.base + "/status"); code != http.StatusOK || !strings.Contains(page, "Aucune installation") {
		t.Errorf("état avant déclenchement : %d", code)
	}
}

func TestListenStopsOnContextCancel(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Listen(ctx, ListenOptions{Listener: ln, API: newFakeAPI()}) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Listen = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Listen doit s'arrêter avec son contexte")
	}
}

func TestListenValidatesPins(t *testing.T) {
	for name, opt := range map[string]ListenOptions{
		"Admin en http":      {PinnedAdmin: "http://x:9443", API: newFakeAPI()},
		"empreinte invalide": {PinnedFingerprint: "zz", API: newFakeAPI()},
		"sans API":           {},
	} {
		if err := Listen(context.Background(), opt); err == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
}
