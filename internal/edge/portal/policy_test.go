// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPolicyValidate(t *testing.T) {
	ok := Policy{HoursEnabled: true, Days: []int{1, 2}, StartTime: "07:00", EndTime: "20:00", Timezone: "Europe/Paris", IPAllow: []string{"10.0.0.0/8", "1.2.3.4"}, IdleTimeoutMin: 15}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Policy{
		"sans jour":  {HoursEnabled: true, StartTime: "07:00", EndTime: "20:00"},
		"jour 9":     {HoursEnabled: true, Days: []int{9}, StartTime: "07:00", EndTime: "20:00"},
		"fin avant":  {HoursEnabled: true, Days: []int{1}, StartTime: "20:00", EndTime: "07:00"},
		"heure":      {HoursEnabled: true, Days: []int{1}, StartTime: "7h", EndTime: "20:00"},
		"fuseau":     {HoursEnabled: true, Days: []int{1}, StartTime: "07:00", EndTime: "20:00", Timezone: "Mars/Base"},
		"ip":         {IPAllow: []string{"pas-une-ip"}},
		"cidr":       {IPAllow: []string{"10.0.0.0/99"}},
		"inactivité": {IdleTimeoutMin: 5000},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: erreur attendue", name)
		}
	}
	if err := (Policy{}).Validate(); err != nil {
		t.Fatalf("politique vide valide: %v", err)
	}
}

func TestPolicyAllowsTime(t *testing.T) {
	p := Policy{HoursEnabled: true, Days: []int{1, 2, 3, 4, 5}, StartTime: "07:00", EndTime: "20:00", Timezone: "Europe/Paris"}
	paris, _ := time.LoadLocation("Europe/Paris")
	cases := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 9, 28, 9, 0, 0, 0, paris), true},     // lundi 09:00
		{time.Date(2026, 9, 28, 6, 59, 0, 0, paris), false},   // avant l'ouverture
		{time.Date(2026, 9, 28, 20, 0, 0, 0, paris), false},   // fin exclue
		{time.Date(2026, 9, 27, 12, 0, 0, 0, paris), false},   // dimanche
		{time.Date(2026, 9, 28, 6, 30, 0, 0, time.UTC), true}, // 08:30 à Paris (UTC+2)
	}
	for _, c := range cases {
		if got := p.AllowsTime(c.at); got != c.want {
			t.Errorf("%v: %v, attendu %v", c.at, got, c.want)
		}
	}
	if !(Policy{}).AllowsTime(time.Now()) {
		t.Fatal("sans restriction horaire, tout est permis")
	}
}

func TestPolicyAllowsIP(t *testing.T) {
	p := Policy{IPAllow: []string{"10.0.0.0/8", "203.0.113.7"}}
	for ip, want := range map[string]bool{"10.1.2.3": true, "203.0.113.7": true, "203.0.113.8": false, "192.168.1.1": false} {
		if got := p.AllowsIP(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
	if p.AllowsIP(nil) {
		t.Fatal("IP inconnue refusée quand une liste existe")
	}
	if !(Policy{}).AllowsIP(nil) {
		t.Fatal("sans liste, tout est permis")
	}
}

func TestClientIPTrustsProxyOnlyFromLoopback(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.4")
	if got := clientIP(r); !got.Equal(net.ParseIP("198.51.100.4")) {
		t.Fatalf("via proxy local: %v", got)
	}
	r.RemoteAddr = "198.51.100.9:5555"
	if got := clientIP(r); !got.Equal(net.ParseIP("198.51.100.9")) {
		t.Fatalf("pair distant: en-tête ignoré attendu, reçu %v", got)
	}
}
