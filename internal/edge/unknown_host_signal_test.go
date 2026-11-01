// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

func unknownHostGateway(t *testing.T, mode string) *Server {
	t.Helper()
	s := newEphorGateway(t, t.TempDir())
	s.rejects = newRejectionLog(nil)
	s.threatEngine.UpdateConfig(threat.Config{
		Enabled:     true,
		Mode:        "block",
		IPScore:     threat.IPScoreConfig{Enabled: true, BanThreshold: 3, HalfLife: threat.Duration{Duration: time.Hour}},
		UnknownHost: threat.UnknownHostConfig{Mode: mode, Points: 2},
	})
	return s
}

func unknownRequest(s *Server, ip, host string) int {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	s.dispatch(rec, req)
	return rec.Code
}

// Jamais de ban au premier accès : il faut plusieurs accès à des hôtes inconnus pour franchir le seuil de la note.
func TestUnknownHostAccessesAddUpToABanInTheDispatch(t *testing.T) {
	s := unknownHostGateway(t, threat.UnknownHostBlock)
	const ip = "203.0.113.90"
	// 2 points par accès, seuil de ban à 3 : le premier accès ne bannit jamais, le deuxième franchit le seuil.
	if code := unknownRequest(s, ip, "inconnu.test"); code != http.StatusNotFound {
		t.Fatalf("premier accès : %d, attendu 404", code)
	}
	if blocked, _ := s.banStore.CheckBlocked(ip); blocked {
		t.Fatal("jamais de ban au premier accès")
	}
	unknownRequest(s, ip, "inconnu.test")
	if blocked, _ := s.banStore.CheckBlocked(ip); !blocked {
		t.Fatal("le deuxième accès franchit le seuil de la note")
	}
	if code := unknownRequest(s, ip, "autre.test"); code != http.StatusForbidden {
		t.Fatalf("l'IP bannie est refusée : %d", code)
	}
}

func TestUnknownHostDetectDoesNotBanInTheDispatch(t *testing.T) {
	s := unknownHostGateway(t, threat.UnknownHostDetect)
	for i := 0; i < 10; i++ {
		unknownRequest(s, "203.0.113.91", "inconnu.test")
	}
	if blocked, _ := s.banStore.CheckBlocked("203.0.113.91"); blocked {
		t.Fatal("en detect, rien n'est versé à la note")
	}
}

func TestBanWhitelistedIPIsNeverNotedForUnknownHosts(t *testing.T) {
	s := unknownHostGateway(t, threat.UnknownHostBlock)
	s.profileStore.Replace([]*router.IPProfile{{ID: router.WhitelistProfileID, Mode: "allow", CIDRs: []string{"203.0.113.92"}}})
	for i := 0; i < 10; i++ {
		unknownRequest(s, "203.0.113.92", "inconnu.test")
	}
	if blocked, _ := s.banStore.CheckBlocked("203.0.113.92"); blocked {
		t.Fatal("une IP de la liste blanche des bans n'est ni évaluée ni comptée")
	}
}

// Les rejets TLS qui disent « un nom que cette passerelle ne sert pas » alimentent le signal ; les autres, non.
func TestTLSRejectionsFeedTheUnknownHostSignal(t *testing.T) {
	l, rej, addr := listenerWithLog(t)
	_ = rej
	var mu sync.Mutex
	got := map[string]string{}
	l.onUnknown = func(ip, name string) { mu.Lock(); got[ip+"|"+name] = name; mu.Unlock() }

	accepted := acceptAsync(l)
	c := tls.Client(dial(t, addr), &tls.Config{ServerName: "Scanner.Example.Test", InsecureSkipVerify: true})
	if err := c.Handshake(); err == nil {
		t.Fatal("la poignée de main devait échouer")
	}
	<-accepted
	waitCond(t, "signal reçu", func() bool { mu.Lock(); defer mu.Unlock(); return got["127.0.0.1|scanner.example.test"] != "" })

	// Une connexion coupée avant le ClientHello n'est pas une requête sur un hôte inconnu.
	acceptAsync(l)
	dial(t, addr).Close()
	waitCond(t, "rejet compté", func() bool { return rejected(RejectBadClientHello) > 0 })
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("seul le nom sans certificat alimente le signal : %v", got)
	}
}
