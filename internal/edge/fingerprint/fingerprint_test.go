// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

var route = &router.Route{ID: "p1", Host: "blog.test"}

func resp(status int, ctype, body string, kv ...string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", ctype)
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: &http.Request{Method: http.MethodGet}}
}

func clock(s *Store, t *time.Time) { s.now = func() time.Time { return *t } }

func products(s *Store) map[string]string {
	out := map[string]string{}
	for _, o := range s.Entries("p1") {
		out[o.Backend+"|"+o.Product] = o.Version
	}
	return out
}

func TestHeadersAreReadBeforeAnythingHidesThem(t *testing.T) {
	s := NewStore()
	s.ObserveResponse(route, "http://10.0.0.1:80", resp(404, "text/plain", "", "Server", "nginx/1.25.3", "X-Powered-By", "PHP/8.2.12"))
	got := products(s)
	if got["http://10.0.0.1:80|nginx"] != "1.25.3" || got["http://10.0.0.1:80|php"] != "8.2.12" {
		t.Fatalf("%v", got)
	}
}

func TestANewerVersionReplacesTheOlderOneOfTheSameBackend(t *testing.T) {
	s := NewStore()
	now := time.Now()
	clock(s, &now)
	s.ObserveResponse(route, "http://b1", resp(200, "text/plain", "", "Server", "nginx/1.24.0"))
	s.ObserveResponse(route, "http://b2", resp(200, "text/plain", "", "Server", "nginx/1.20.0"))
	now = now.Add(2 * time.Minute)
	s.ObserveResponse(route, "http://b1", resp(200, "text/plain", "", "Server", "nginx/1.25.3"))
	got := products(s)
	if got["http://b1|nginx"] != "1.25.3" || got["http://b2|nginx"] != "1.20.0" || len(got) != 2 {
		t.Fatalf("une mise à jour remplace l'ancienne version de CE backend seulement : %v", got)
	}
}

func TestSameHeadersAreNotParsedAgainWithinAMinute(t *testing.T) {
	s := NewStore()
	now := time.Now()
	clock(s, &now)
	r := func() *http.Response { return resp(200, "text/plain", "", "Server", "nginx/1.25.3") }
	s.ObserveResponse(route, "http://b", r())
	first := s.Entries("p1")[0].Last
	now = now.Add(10 * time.Second)
	s.ObserveResponse(route, "http://b", r())
	if !s.Entries("p1")[0].Last.Equal(first) {
		t.Error("une réponse identique, revue 10 s plus tard, ne coûte rien")
	}
	now = now.Add(2 * time.Minute)
	s.ObserveResponse(route, "http://b", r())
	if !s.Entries("p1")[0].Last.After(first) {
		t.Error("la date de dernière observation se rafraîchit")
	}
}

const wpPage = `<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hello</body></html>`

func TestGeneratorIsReadFromTheHTMLWithoutChangingWhatTheClientGets(t *testing.T) {
	s := NewStore()
	r := resp(200, "text/html; charset=UTF-8", wpPage)
	s.ObserveResponse(route, "http://b", r)
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(body) != wpPage {
		t.Fatalf("le client reçoit la page intacte : %q", body)
	}
	if products(s)["http://b|wordpress"] != "6.4.2" {
		t.Fatalf("%v", products(s))
	}
}

func TestGzipPagesAreReadToo(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(wpPage))
	zw.Close()
	s := NewStore()
	r := resp(200, "text/html", buf.String(), "Content-Encoding", "gzip")
	s.ObserveResponse(route, "http://b", r)
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !bytes.Equal(got, buf.Bytes()) {
		t.Fatal("le client reçoit les octets gzip tels quels")
	}
	if products(s)["http://b|wordpress"] != "6.4.2" {
		t.Fatalf("%v", products(s))
	}
}

func TestPagesAreSampledNotReadForEveryRequest(t *testing.T) {
	s := NewStore()
	now := time.Now()
	clock(s, &now)
	r1 := resp(200, "text/html", "<html></html>")
	s.ObserveResponse(route, "http://b", r1)
	if _, ok := r1.Body.(*sniffBody); !ok {
		t.Fatal("la première page est lue")
	}
	r2 := resp(200, "text/html", "<html></html>")
	s.ObserveResponse(route, "http://b", r2)
	if _, ok := r2.Body.(*sniffBody); ok {
		t.Error("pas deux fois en dix minutes")
	}
	now = now.Add(11 * time.Minute)
	r3 := resp(200, "text/html", "<html></html>")
	s.ObserveResponse(route, "http://b", r3)
	if _, ok := r3.Body.(*sniffBody); !ok {
		t.Error("à nouveau après le délai")
	}
}

func TestOnlyCompleteHTMLPagesAreRead(t *testing.T) {
	s := NewStore()
	for name, r := range map[string]*http.Response{
		"json":    resp(200, "application/json", `{}`),
		"404":     resp(404, "text/html", wpPage),
		"partiel": resp(206, "text/html", wpPage),
		"brotli":  resp(200, "text/html", wpPage, "Content-Encoding", "br"),
	} {
		s.ObserveResponse(route, "http://b-"+name, r)
		if _, ok := r.Body.(*sniffBody); ok {
			t.Errorf("%s : ne doit pas être lu", name)
		}
	}
	head := resp(200, "text/html", "")
	head.Request.Method = http.MethodHead
	s.ObserveResponse(route, "http://b-head", head)
	if _, ok := head.Body.(*sniffBody); ok {
		t.Error("HEAD : pas de corps à lire")
	}
}

func TestStateSurvivesRestartAndMergesWithPeersIdempotently(t *testing.T) {
	a := NewStore()
	a.ObserveResponse(route, "http://b", resp(200, "text/plain", "", "Server", "nginx/1.25.3"))
	snap := a.Snapshot()

	b := NewStore()
	b.Restore(snap)
	if products(b)["http://b|nginx"] != "1.25.3" {
		t.Fatalf("redémarrage : %v", products(b))
	}

	// Un pair a vu une version plus récente du même backend, plus un autre backend.
	later := time.Now().Add(time.Hour)
	peer := NewStore()
	peer.now = func() time.Time { return later }
	peer.ObserveResponse(route, "http://b", resp(200, "text/plain", "", "Server", "nginx/1.26.0"))
	peer.ObserveResponse(route, "http://c", resp(200, "text/plain", "", "Server", "Apache/2.4.58"))
	for i := 0; i < 2; i++ {
		b.ApplyPeer("peer", peer.Export())
	}
	got := products(b)
	if got["http://b|nginx"] != "1.26.0" || got["http://c|apache http server"] != "2.4.58" || len(got) != 2 {
		t.Fatalf("fusion : %v", got)
	}
	// L'ordre n'y change rien.
	c := NewStore()
	c.ApplyPeer("peer", peer.Export())
	c.ApplyPeer("a", snap)
	if !equal(products(c), products(b)) {
		t.Fatalf("fusion commutative : %v / %v", products(c), products(b))
	}
}

func equal(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestForgetDropsDeletedProxiesAndExpiredObservations(t *testing.T) {
	s := NewStore()
	now := time.Now()
	clock(s, &now)
	s.ObserveResponse(route, "http://b", resp(200, "text/plain", "", "Server", "nginx/1.25.3"))
	s.ObserveResponse(&router.Route{ID: "gone"}, "http://x", resp(200, "text/plain", "", "Server", "nginx/1.25.3"))
	s.Forget(func(id string) bool { return id != "gone" })
	if len(s.Entries("gone")) != 0 || len(s.Entries("p1")) != 1 {
		t.Fatal("un proxy supprimé n'a plus d'inventaire")
	}
	now = now.Add(TTL + time.Hour)
	if len(s.Entries("p1")) != 0 {
		t.Error("une observation non revue depuis 30 jours sort de l'inventaire")
	}
	s.Forget(func(string) bool { return true })
	if len(s.Snapshot().Routes) != 0 {
		t.Error("et de la copie locale")
	}
}

func TestPerRouteIsBounded(t *testing.T) {
	s := NewStore()
	for i := 0; i < 200; i++ {
		s.put("p1", Obs{Backend: "http://b" + strings.Repeat("x", i), Product: "nginx", Source: "headers", Last: time.Now()})
	}
	if n := len(s.Entries("p1")); n > maxPerRoute {
		t.Errorf("%d observations", n)
	}
}
