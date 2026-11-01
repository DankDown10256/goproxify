// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/tlsfp"
)

func TestRejectionLogStaysBounded(t *testing.T) {
	l := newRejectionLog(nil)
	for i := 0; i < 20000; i++ {
		l.Record(RejectUnknownSNI, fmt.Sprintf("198.51.%d.%d", i/256%256, i%256), fmt.Sprintf("nom-%d.scan.test", i), fmt.Sprintf("t13d%04d", i))
	}
	if len(l.names) > rejectNameCap || len(l.sources) > rejectSourceCap || len(l.ja4) > rejectJA4Cap {
		t.Fatalf("tables non bornées : %d noms, %d IP, %d empreintes", len(l.names), len(l.sources), len(l.ja4))
	}
	if got := l.reasons[RejectUnknownSNI]; got != 20000 {
		t.Fatalf("le total par raison reste exact : %d, attendu 20000", got)
	}
}

func TestRejectionLogKeepsTheFrequentOnesAndCountsDistinctSources(t *testing.T) {
	l := newRejectionLog(nil)
	for i := 0; i < 3000; i++ {
		l.Record(RejectUnknownSNI, fmt.Sprintf("203.0.113.%d", i%200), fmt.Sprintf("bruit-%d.test", i), "")
		if i%10 == 0 {
			l.Record(RejectUnknownSNI, fmt.Sprintf("192.0.2.%d", i/10%40), "oublie.example.fr", "t13d1516h2_aaaa_bbbb")
		}
	}
	snap := l.Snapshot()
	if len(snap.Names) == 0 || snap.Names[0].Name != "oublie.example.fr" || snap.Names[0].Count != 300 {
		t.Fatalf("le nom le plus demandé doit survivre à l'éviction et passer en tête : %+v", snap.Names[:1])
	}
	if snap.Names[0].Sources != 40 || snap.Names[0].SourcesCapped {
		t.Fatalf("40 IP distinctes attendues (sous le plafond de %d) : %+v", rejectIPsPerName, snap.Names[0])
	}
	if len(snap.JA4) != 1 || snap.JA4[0].JA4 != "t13d1516h2_aaaa_bbbb" {
		t.Fatalf("empreinte : %+v", snap.JA4)
	}
	if len(snap.Names) > rejectSnapshotN || len(snap.Sources) > rejectSnapshotN {
		t.Fatalf("l'instantané se limite aux %d premiers", rejectSnapshotN)
	}
}

func TestRejectionLogCapsDistinctSourcesPerName(t *testing.T) {
	l := newRejectionLog(nil)
	for i := 0; i < 500; i++ {
		l.Record(RejectUnknownSNI, fmt.Sprintf("10.9.%d.%d", i/200, i%200), "partout.test", "")
	}
	n := l.Snapshot().Names[0]
	if n.Sources != rejectIPsPerName || !n.SourcesCapped {
		t.Fatalf("au plafond, le nombre d'IP est marqué comme tronqué : %+v", n)
	}
}

func TestRejectionLogSanitisesWhatTheClientChose(t *testing.T) {
	l := newRejectionLog(nil)
	l.Record(RejectUnknownSNI, "203.0.113.5", "EVIL\r\nINJECT\x00"+strings.Repeat("a", 500)+".test", "")
	got := l.Snapshot().Names[0].Name
	if len(got) > rejectNameMaxLen || strings.ContainsAny(got, "\r\n\x00") || got != strings.ToLower(got) {
		t.Fatalf("nom non assaini : %q", got)
	}
	if !strings.HasPrefix(got, "evil??inject?") {
		t.Fatalf("les caractères de contrôle deviennent « ? » : %q", got)
	}
}

func TestRejectionLogForgetAndNil(t *testing.T) {
	l := newRejectionLog(nil)
	l.Record(RejectNoSNI, "203.0.113.5", "", "")
	l.Forget("203.0.113.5")
	if len(l.Snapshot().Sources) != 0 {
		t.Fatal("une IP effacée ne figure plus au classement")
	}
	var none *rejectionLog
	none.Record(RejectNoSNI, "203.0.113.5", "x", "")
	none.Forget("203.0.113.5")
	if snap := none.Snapshot(); snap.Reasons == nil || snap.Names == nil {
		t.Fatal("un journal absent rend un instantané vide mais sérialisable")
	}
}

// Un scan de milliers d'IP ne doit pas remplir les logs système : une ligne par raison et par fenêtre.
func TestRejectionLogWritesOneLinePerReasonAndWindow(t *testing.T) {
	var buf bytes.Buffer
	l := newRejectionLog(slog.New(slog.NewTextHandler(&buf, nil)))
	for i := 0; i < 500; i++ {
		l.Record(RejectUnknownSNI, fmt.Sprintf("198.51.100.%d", i%250), "scan.test", "t13d0000")
	}
	l.Record(RejectNoSNI, "198.51.100.1", "", "")
	if n := strings.Count(buf.String(), "entrée: connexion rejetée"); n != 2 {
		t.Fatalf("%d lignes, attendu une par raison (2)", n)
	}
	if !strings.Contains(buf.String(), "ja4=t13d0000") || !strings.Contains(buf.String(), "name=scan.test") {
		t.Fatalf("la ligne porte l'IP, l'empreinte et le nom : %s", buf.String())
	}
}

func rejected(reason string) float64 {
	return testutil.ToFloat64(metrics.TLS.Rejected.WithLabelValues(reason))
}

func TestHandshakeFailureReasons(t *testing.T) {
	l := &sniListener{hostLabel: func(sni string) string {
		if sni == "app.example.fr" {
			return "app.example.fr"
		}
		return otherHostLabel
	}}
	fp := &tlsfp.Fingerprint{JA4: "t13d"}
	for name, tc := range map[string]struct {
		sni  string
		fp   *tlsfp.Fingerprint
		want string
	}{
		"pas du TLS":           {"", nil, RejectNotTLS},
		"pas de nom":           {"", fp, RejectNoSNI},
		"adresse IPv4":         {"192.0.2.10", fp, RejectIPLiteral},
		"adresse IPv6":         {"2001:db8::1", fp, RejectIPLiteral},
		"nom sans certificat":  {"inconnu.example.fr", fp, RejectUnknownSNI},
		"nom connu interrompu": {"app.example.fr", fp, RejectHandshake},
	} {
		if got := l.handshakeFailure(tc.sni, tc.fp); got != tc.want {
			t.Errorf("%s : %q, attendu %q", name, got, tc.want)
		}
	}
}

// listenerWithLog : un listener dont toute poignée de main échoue (aucun certificat), branché sur un journal des rejets.
func listenerWithLog(t *testing.T) (*sniListener, *rejectionLog, string) {
	t.Helper()
	l, addr := newTestSNIListener(t)
	l.rejects = newRejectionLog(nil)
	l.tlsCfg = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("aucun certificat")
	}}
	l.hostLabel = func(string) string { return otherHostLabel }
	return l, l.rejects, addr
}

func TestSNIListenerClassifiesRejections(t *testing.T) {
	t.Run("nom sans certificat", func(t *testing.T) {
		l, rej, addr := listenerWithLog(t)
		before := rejected(RejectUnknownSNI)
		accepted := acceptAsync(l)
		c := tls.Client(dial(t, addr), &tls.Config{ServerName: "Scanner.Example.Test", InsecureSkipVerify: true})
		if err := c.Handshake(); err == nil {
			t.Fatal("la poignée de main devait échouer")
		}
		<-accepted
		waitCond(t, "rejet compté", func() bool { return rejected(RejectUnknownSNI) == before+1 })
		snap := rej.Snapshot()
		if len(snap.Names) != 1 || snap.Names[0].Name != "scanner.example.test" || len(snap.Sources) != 1 || snap.Sources[0].IP != "127.0.0.1" {
			t.Fatalf("le nom demandé (assaini) et l'IP doivent figurer au classement : %+v", snap)
		}
		if len(snap.JA4) != 1 {
			t.Fatalf("l'empreinte du client doit figurer au classement : %+v", snap.JA4)
		}
	})

	t.Run("accès par l'IP, sans nom", func(t *testing.T) {
		l, _, addr := listenerWithLog(t)
		before := rejected(RejectNoSNI)
		accepted := acceptAsync(l)
		c := tls.Client(dial(t, addr), &tls.Config{InsecureSkipVerify: true})
		if err := c.Handshake(); err == nil {
			t.Fatal("la poignée de main devait échouer")
		}
		<-accepted
		waitCond(t, "rejet compté", func() bool { return rejected(RejectNoSNI) == before+1 })
	})

	t.Run("pas du TLS", func(t *testing.T) {
		l, _, addr := listenerWithLog(t)
		before := rejected(RejectNotTLS)
		accepted := acceptAsync(l)
		c := dial(t, addr)
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) //nolint:errcheck
		<-accepted
		waitCond(t, "rejet compté", func() bool { return rejected(RejectNotTLS) == before+1 })
	})

	t.Run("connexion coupée avant le ClientHello", func(t *testing.T) {
		l, _, addr := listenerWithLog(t)
		before := rejected(RejectBadClientHello)
		acceptAsync(l)
		dial(t, addr).Close()
		waitCond(t, "rejet compté", func() bool { return rejected(RejectBadClientHello) == before+1 })
	})
}

func TestUnknownHostIsCountedAndRanked(t *testing.T) {
	s := whitelistServer(t, nil)
	s.threatEngine = nil
	s.rejects = newRejectionLog(nil)
	before := testutil.ToFloat64(unknownHostTotal)

	for _, host := range []string{"inconnu.test", "inconnu.test", "autre.test"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		req.RemoteAddr = "198.51.100.7:4000"
		s.dispatch(httptest.NewRecorder(), req)
	}
	if got := testutil.ToFloat64(unknownHostTotal); got != before+3 {
		t.Fatalf("compteur : %v, attendu %v", got, before+3)
	}
	snap := s.rejects.Snapshot()
	if snap.Reasons[RejectUnknownHost] != 3 || len(snap.Names) != 2 || snap.Names[0].Name != "inconnu.test" || snap.Names[0].Count != 2 {
		t.Fatalf("classement : %+v", snap)
	}
}

func TestRejectionsEndpoint(t *testing.T) {
	s := whitelistServer(t, nil)
	s.rejects = newRejectionLog(nil)
	s.rejects.Record(RejectNoSNI, "203.0.113.9", "", "t13d1516h2_x")

	rec := httptest.NewRecorder()
	s.handleRejections(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/rejections", nil))
	var snap RejectionSnapshot
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &snap) != nil {
		t.Fatalf("réponse illisible : %d %s", rec.Code, rec.Body.String())
	}
	if snap.Reasons[RejectNoSNI] != 1 || len(snap.Sources) != 1 || snap.Sources[0].IP != "203.0.113.9" || snap.Since == "" {
		t.Fatalf("instantané : %+v", snap)
	}
}
