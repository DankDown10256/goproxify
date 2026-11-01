// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func newTestSNIListener(t *testing.T) (*sniListener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &sniListener{
		inner:  ln,
		table:  &router.Table{},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		tlsCfg: &tls.Config{},
		fps:    &sync.Map{},
	}
	t.Cleanup(func() { l.Close() })
	return l, ln.Addr().String()
}

// startHello ouvre une connexion qui envoie un vrai ClientHello pour sni.
func startHello(t *testing.T, addr, sni string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake() //nolint:errcheck
	return c
}

type accepted struct {
	conn net.Conn
	err  error
}

func acceptAsync(l *sniListener) <-chan accepted {
	ch := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		ch <- accepted{c, err}
	}()
	return ch
}

func TestSNIListenerSilentConnectionDoesNotBlockOthers(t *testing.T) {
	l, addr := newTestSNIListener(t)

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	client := startHello(t, addr, "a.example.com")

	select {
	case got := <-acceptAsync(l):
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.conn.RemoteAddr().String() != client.LocalAddr().String() {
			t.Fatalf("connexion acceptée %s, attendu celle qui a envoyé son ClientHello (%s)", got.conn.RemoteAddr(), client.LocalAddr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("une connexion muette a bloqué l'acceptation des suivantes")
	}
}

func counterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	c.Write(&m) //nolint:errcheck
	return m.GetCounter().GetValue()
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func expectClosed(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within)) //nolint:errcheck
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("la connexion devait être fermée par la passerelle (lecture : %v)", err)
	}
}

func TestSNIListenerClosesSilentConnectionAfterTimeout(t *testing.T) {
	l, addr := newTestSNIListener(t)
	l.helloTimeout = 150 * time.Millisecond
	acceptAsync(l)
	before := counterValue(metrics.TLS.Rejected.WithLabelValues("timeout"))

	expectClosed(t, dial(t, addr), 2*time.Second)

	if got := counterValue(metrics.TLS.Rejected.WithLabelValues("timeout")); got != before+1 {
		t.Fatalf("rejets « timeout » : %v, attendu %v", got, before+1)
	}
}

func TestSNIListenerCapsPendingPerSource(t *testing.T) {
	l, addr := newTestSNIListener(t)
	l.maxPendingPerSource = 2
	l.helloTimeout = 5 * time.Second
	acceptAsync(l)
	before := counterValue(metrics.TLS.Rejected.WithLabelValues("too_many_pending"))

	held := []net.Conn{dial(t, addr), dial(t, addr)}
	expectClosed(t, dial(t, addr), 2*time.Second)

	for _, c := range held {
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
		if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
			t.Fatalf("une connexion sous le plafond a été fermée (lecture : %v)", err)
		}
	}
	if got := counterValue(metrics.TLS.Rejected.WithLabelValues("too_many_pending")); got != before+1 {
		t.Fatalf("rejets « too_many_pending » : %v, attendu %v", got, before+1)
	}
}

func TestSourceKeyGroupsIPv6By64(t *testing.T) {
	addr := func(s string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	if a, b := sourceKey(addr("[2a01:e0a:1:2::5]:1000")), sourceKey(addr("[2a01:e0a:1:2:abcd::7]:2000")); a != b {
		t.Fatalf("deux adresses d'un même /64 : %q et %q", a, b)
	}
	if a, b := sourceKey(addr("[2a01:e0a:1:2::5]:1000")), sourceKey(addr("[2a01:e0a:1:3::5]:1000")); a == b {
		t.Fatalf("deux /64 différents ne doivent pas se confondre : %q", a)
	}
	if got := sourceKey(addr("203.0.113.7:443")); got != "203.0.113.7" {
		t.Fatalf("IPv4 : %q", got)
	}
}

func testServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func activeHosts(t *testing.T) map[string]float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "gpx_tls_active_connections" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "host" {
					out[lp.GetValue()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	return out
}

func waitCond(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Avec un certificat wildcard, n'importe quel sous-domaine termine sa poignée de main : les connexions actives doivent
// rester comptées sous le nom du certificat, jamais sous le SNI choisi par le client.
func TestSNIListenerActiveConnsStayBounded(t *testing.T) {
	const label = "*.bounded.test"
	l, addr := newTestSNIListener(t)
	l.tlsCfg = &tls.Config{Certificates: []tls.Certificate{testServerCert(t)}}
	l.hostLabel = func(sni string) string {
		if strings.HasSuffix(sni, ".bounded.test") {
			return label
		}
		return otherHostLabel
	}
	base := activeHosts(t)[label]

	const n = 20
	var server []net.Conn
	for i := 0; i < n; i++ {
		accepted := acceptAsync(l)
		client := tls.Client(dial(t, addr), &tls.Config{ServerName: fmt.Sprintf("x%d.bounded.test", i), InsecureSkipVerify: true})
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		got := <-accepted
		if got.err != nil {
			t.Fatal(got.err)
		}
		server = append(server, got.conn)
		want := base + float64(i+1)
		waitCond(t, "connexion comptée", func() bool { return activeHosts(t)[label] == want })
	}
	for host := range activeHosts(t) {
		if strings.HasPrefix(host, "x") && strings.HasSuffix(host, ".bounded.test") {
			t.Fatalf("série créée pour un SNI choisi par le client : %q", host)
		}
	}
	for _, c := range server {
		l.connClosed(c)
	}
	if got := activeHosts(t)[label]; got != base {
		t.Fatalf("connexions actives après fermeture : %v, attendu %v", got, base)
	}
}

// Une poignée de main qui échoue (nom sans certificat) n'a jamais été comptée : la fermer ne doit rien décompter, ni créer
// de série au nom que le scanner a demandé.
func TestSNIListenerFailedHandshakeLeavesNoSeries(t *testing.T) {
	l, addr := newTestSNIListener(t)
	l.tlsCfg = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("aucun certificat")
	}}
	l.hostLabel = func(sni string) string { return sni }

	accepted := acceptAsync(l)
	client := tls.Client(dial(t, addr), &tls.Config{ServerName: "scanner-xyz.failed.test", InsecureSkipVerify: true})
	if err := client.Handshake(); err == nil {
		t.Fatal("la poignée de main devait échouer")
	}
	got := <-accepted
	if got.err != nil {
		t.Fatal(got.err)
	}
	l.connClosed(got.conn)

	for host := range activeHosts(t) {
		if strings.Contains(host, "scanner-xyz") {
			t.Fatalf("série créée pour un nom sans certificat : %q", host)
		}
	}
}
