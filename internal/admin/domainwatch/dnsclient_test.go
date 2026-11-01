// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package domainwatch

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// serveDNS démarre un résolveur local qui répond avec handler.
func serveDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("pas de socket UDP local : %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go srv.ActivateAndServe() //nolint:errcheck
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestResolverClientWalksUpToTheCAAAndSpotsADanglingCNAME(t *testing.T) {
	addr := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeCAA && q.Name == "example.fr.":
			m.Answer = append(m.Answer, &dns.CAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Tag: "issue", Value: "letsencrypt.org"})
		case q.Qtype == dns.TypeCAA && q.Name == "broken.example.fr.":
			m.Rcode = dns.RcodeServerFailure
		case q.Qtype == dns.TypeA && q.Name == "old.example.fr.":
			m.Rcode = dns.RcodeNameError
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "gone.hosting.example."})
		case q.Qtype == dns.TypeA && q.Name == "absent.example.fr.":
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	c, err := NewDNS(addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	recs, err := c.CAA(ctx, "app.eu.example.fr")
	if err != nil || len(recs) != 1 || recs[0].Tag != "issue" || recs[0].Value != "letsencrypt.org" {
		t.Fatalf("le CAA d'un ancêtre s'applique (RFC 8659) : %+v %v", recs, err)
	}
	if recs, err := c.CAA(ctx, "other.test"); err != nil || len(recs) != 0 {
		t.Fatalf("aucun CAA nulle part : %+v %v", recs, err)
	}
	if _, err := c.CAA(ctx, "broken.example.fr"); err == nil {
		t.Fatal("une panne du résolveur est une erreur, pas une absence de CAA")
	}

	if target, err := c.Dangling(ctx, "old.example.fr"); err != nil || target != "gone.hosting.example" {
		t.Fatalf("CNAME vers une cible disparue : %q %v", target, err)
	}
	if target, _ := c.Dangling(ctx, "absent.example.fr"); target != "" {
		t.Fatalf("un nom absent sans CNAME n'est pas un nom pendant : %q", target)
	}
	if target, _ := c.Dangling(ctx, "live.example.fr"); target != "" {
		t.Fatalf("un nom qui résout n'est pas pendant : %q", target)
	}
}

func TestNewDNSNeedsAResolverWhenTheSystemHasNone(t *testing.T) {
	if _, err := NewDNS("9.9.9.9:53"); err != nil {
		t.Fatalf("un résolveur explicite suffit : %v", err)
	}
}
