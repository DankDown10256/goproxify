package logger

import (
	"net/http/httptest"
	"testing"
)

func TestRealIPIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	SetTrustedProxies(nil)
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:4242"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("CF-Connecting-IP", "5.6.7.8")
	if got := RealIP(req); got != "203.0.113.10" {
		t.Fatalf("RealIP = %q, want peer", got)
	}
}

func TestRealIPTrustsPrivateAndConfiguredPeers(t *testing.T) {
	SetTrustedProxies([]string{"203.0.113.0/24"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	for _, peer := range []string{"10.1.2.3:80", "127.0.0.1:80", "203.0.113.9:80"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
		if got := RealIP(req); got != "1.2.3.4" {
			t.Fatalf("peer %s: RealIP = %q", peer, got)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.1:80"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := RealIP(req); got != "198.51.100.1" {
		t.Fatalf("untrusted peer: RealIP = %q", got)
	}
}

func TestRealIPXFFReadFromRight(t *testing.T) {
	SetTrustedProxies([]string{"203.0.113.0/24"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	cases := map[string]string{
		"6.6.6.6, 1.2.3.4":                        "1.2.3.4",
		"6.6.6.6, 1.2.3.4, 203.0.113.7, 10.0.0.2": "1.2.3.4",
		"10.0.0.9, 203.0.113.7":                   "10.0.0.9",
		"garbage, 1.2.3.4":                        "1.2.3.4",
	}
	for xff, want := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:80"
		req.Header.Set("X-Forwarded-For", xff)
		if got := RealIP(req); got != want {
			t.Errorf("XFF %q: RealIP = %q, want %q", xff, got, want)
		}
	}
}

func TestRealIPWildcardKeepsLegacy(t *testing.T) {
	SetTrustedProxies([]string{"*"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:4242"
	req.Header.Set("X-Real-IP", "9.9.9.9")
	if got := RealIP(req); got != "9.9.9.9" {
		t.Fatalf("RealIP = %q", got)
	}
}
