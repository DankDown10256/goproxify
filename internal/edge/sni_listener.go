// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	"github.com/vincamok/goproxify/internal/edge/tlsfp"
)

const (
	// clientHelloTimeout borne l'attente du ClientHello : les scanners qui ouvrent TCP sans rien envoyer.
	clientHelloTimeout = 3 * time.Second
	// maxPendingHellos et maxPendingPerSource bornent les ClientHello en cours de lecture, au total et par source.
	maxPendingHellos    = 2048
	maxPendingPerSource = 32

	otherHostLabel = "autre"
)

// sniListener lit le ClientHello de chaque connexion TCP pour y trouver le SNI, avant que la couche TLS ne démarre.
// La lecture se fait hors de la boucle d'acceptation : une connexion muette ne retarde pas les suivantes.
type sniListener struct {
	inner  net.Listener
	table  *router.Table
	log    *slog.Logger
	tlsCfg *tls.Config
	ech    *edgetls.ECHManager // clés ECH courantes ; la config TLS est choisie par connexion
	fps    *sync.Map           // *tls.Conn → *tlsfp.Fingerprint, vidé à la fermeture (connClosed)

	// hostLabel ramène un SNI au nom du certificat qui le sert, pour les métriques : une valeur choisie par le client ne
	// doit jamais devenir une étiquette. nil : tout porte l'étiquette otherHostLabel.
	hostLabel func(sni string) string

	// rejects retient ce que l'entrée refuse (raison, nom demandé, IP, empreinte) ; nil : seuls les compteurs sont tenus.
	rejects *rejectionLog

	// onUnknown reçoit les rejets qui disent « quelqu'un frappe un nom que cette passerelle ne sert pas » (pas de nom, adresse IP,
	// nom sans certificat, pas du TLS) : de quoi alimenter le signal « hôte inconnu » d'Ephor. nil : rien.
	onUnknown func(ip, name string)

	// Zéro : valeurs par défaut ci-dessus.
	helloTimeout        time.Duration
	maxPending          int
	maxPendingPerSource int

	startOnce sync.Once
	closeOnce sync.Once
	ready     chan helloResult
	done      chan struct{}

	mu       sync.Mutex
	pending  int
	bySource map[string]int

	tracks sync.Map // *tls.Conn → *tlsConnTrack
}

type helloResult struct {
	conn net.Conn
	err  error
}

// tlsConnTrack retient l'étiquette sous laquelle une connexion a été comptée active, pour la décompter sous la même.
type tlsConnTrack struct {
	mu     sync.Mutex
	label  string
	closed bool
}

func (l *sniListener) start() {
	l.ready = make(chan helloResult)
	l.done = make(chan struct{})
	l.bySource = map[string]int{}
	go l.loop()
}

func (l *sniListener) loop() {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			l.deliver(helloResult{err: err})
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-l.done:
				return
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		src := sourceKey(conn.RemoteAddr())
		if !l.admit(src) {
			l.reject(RejectTooManyPending, addrIP(conn.RemoteAddr()), "", "")
			conn.Close()
			continue
		}
		go l.hello(conn, src)
	}
}

func (l *sniListener) Accept() (net.Conn, error) {
	l.startOnce.Do(l.start)
	select {
	case r := <-l.ready:
		return r.conn, r.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *sniListener) Close() error {
	l.startOnce.Do(l.start)
	l.closeOnce.Do(func() { close(l.done) })
	return l.inner.Close()
}

func (l *sniListener) Addr() net.Addr { return l.inner.Addr() }

func (l *sniListener) deliver(r helloResult) {
	select {
	case l.ready <- r:
	case <-l.done:
		if r.conn != nil {
			r.conn.Close()
		}
	}
}

func (l *sniListener) admit(src string) bool {
	maxTotal, maxSource := l.maxPending, l.maxPendingPerSource
	if maxTotal <= 0 {
		maxTotal = maxPendingHellos
	}
	if maxSource <= 0 {
		maxSource = maxPendingPerSource
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending >= maxTotal || l.bySource[src] >= maxSource {
		return false
	}
	l.pending++
	l.bySource[src]++
	return true
}

func (l *sniListener) release(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending--
	if l.bySource[src] <= 1 {
		delete(l.bySource, src)
	} else {
		l.bySource[src]--
	}
}

// sourceKey regroupe une IPv6 par /64 (un abonné y change d'adresse à volonté), comme les compteurs d'Ephor.
func sourceKey(a net.Addr) string {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return a.String()
	}
	ip := ap.Addr().Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func (l *sniListener) hello(conn net.Conn, src string) {
	releaseSlot := sync.OnceFunc(func() { l.release(src) })
	defer releaseSlot()

	timeout := l.helloTimeout
	if timeout <= 0 {
		timeout = clientHelloTimeout
	}
	conn.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
	sni, fp, peeked, err := edgetls.PeekClientHello(conn)
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		reason := RejectBadClientHello
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			reason = RejectTimeout
		}
		l.reject(reason, addrIP(conn.RemoteAddr()), "", "")
		conn.Close()
		return
	}
	sni = strings.ToLower(strings.TrimSpace(sni))
	if route, ok := l.table.PassthroughRoute(sni); ok {
		releaseSlot()
		l.doPassthrough(peeked, route)
		return
	}
	// Retourner *tls.Conn directement : http.Server fait une type assertion sur
	// *tls.Conn pour router les connexions h2 via TLSNextProto. Un wrapper custom
	// ferait échouer cette assertion et forcerait toutes les connexions en HTTP/1.1,
	// provoquant ERR_HTTP2_PROTOCOL_ERROR quand le client a négocié h2 via ALPN.
	cfg := l.tlsCfg
	if c := l.ech.Config(); c != nil {
		cfg = c
	}
	tlsConn := tls.Server(peeked, cfg)
	if fp != nil && l.fps != nil {
		l.fps.Store(tlsConn, fp)
	}
	l.tracks.Store(tlsConn, &tlsConnTrack{})
	go l.measureHandshake(tlsConn, sni, addrIP(conn.RemoteAddr()), fp)
	l.deliver(helloResult{conn: tlsConn})
}

// reject compte un rejet à l'entrée, par raison (étiquette de métrique), et le garde dans le classement.
func (l *sniListener) reject(reason, ip, name, ja4 string) {
	metrics.TLS.Rejected.WithLabelValues(reason).Inc()
	l.rejects.Record(reason, ip, name, ja4)
	if l.onUnknown != nil {
		switch reason {
		case RejectNoSNI, RejectIPLiteral, RejectUnknownSNI, RejectNotTLS:
			l.onUnknown(ip, cleanName(name))
		}
	}
}

// handshakeFailure dit pourquoi une poignée de main a échoué, d'après ce que le ClientHello annonçait : pas du TLS, pas de nom
// (accès par l'IP), une adresse IP à la place d'un nom, un nom sans certificat, ou un nom connu dont la poignée de main a été
// interrompue ou refusée.
func (l *sniListener) handshakeFailure(sni string, fp *tlsfp.Fingerprint) string {
	switch {
	case fp == nil:
		return RejectNotTLS
	case sni == "":
		return RejectNoSNI
	}
	if _, err := netip.ParseAddr(sni); err == nil {
		return RejectIPLiteral
	}
	if l.hostLabel != nil && l.hostLabel(sni) == otherHostLabel {
		return RejectUnknownSNI
	}
	return RejectHandshake
}

// addrIP donne l'IP d'une adresse « ip:port », IPv4-mappée ramenée en IPv4 ; ce qu'on ne sait pas lire est rendu tel quel.
func addrIP(a net.Addr) string {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return a.String()
	}
	return ap.Addr().Unmap().String()
}

func (l *sniListener) label(sni string) string {
	if l.hostLabel == nil {
		return otherHostLabel
	}
	return l.hostLabel(sni)
}

// measureHandshake enregistre la durée du handshake TLS et compte la connexion active. Une poignée de main qui échoue
// (nom sans certificat, client qui part) n'est ni mesurée ni comptée : connClosed n'a alors rien à décompter.
// tls.Conn.Handshake() est idempotent : l'appel concurrent avec celui de http.Server est sans danger.
func (l *sniListener) measureHandshake(c *tls.Conn, sni, ip string, fp *tlsfp.Fingerprint) {
	start := time.Now()
	if err := c.Handshake(); err != nil {
		ja4 := ""
		if fp != nil {
			ja4 = fp.JA4
		}
		l.reject(l.handshakeFailure(sni, fp), ip, sni, ja4)
		return
	}
	label := l.label(sni)
	if v, ok := l.tracks.Load(c); ok {
		t := v.(*tlsConnTrack)
		t.mu.Lock()
		if !t.closed {
			t.label = label
			metrics.TLS.ActiveConns.WithLabelValues(label).Inc()
		}
		t.mu.Unlock()
	}
	metrics.TLS.HandshakeDuration.WithLabelValues(label).Observe(time.Since(start).Seconds())
}

// connClosed libère ce que la connexion retenait ; à appeler quand http.Server la ferme ou la détourne (ConnState).
func (l *sniListener) connClosed(conn net.Conn) {
	if l.fps != nil {
		l.fps.Delete(conn)
	}
	v, ok := l.tracks.LoadAndDelete(conn)
	if !ok {
		return
	}
	t := v.(*tlsConnTrack)
	t.mu.Lock()
	t.closed = true
	if t.label != "" {
		metrics.TLS.ActiveConns.WithLabelValues(t.label).Dec()
	}
	t.mu.Unlock()
}
