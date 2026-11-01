// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func unknownCount(result string) float64 {
	return testutil.ToFloat64(threatUnknownHostTotal.WithLabelValues(result))
}

// unknownEngine : score cumulé (ban à 6), un point par accès à un hôte inconnu.
func unknownEngine(t *testing.T, mode string, extra ...func(*Config)) (*Engine, *time.Time, *[]explained) {
	t.Helper()
	cfg := Config{
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 6, HalfLife: Duration{time.Hour}},
		UnknownHost: UnknownHostConfig{Mode: mode},
	}
	for _, f := range extra {
		f(&cfg)
	}
	return explainEngine(t, cfg)
}

func TestUnknownHostNeverBansOnTheFirstAccess(t *testing.T) {
	e, _, bans := unknownEngine(t, UnknownHostBlock)
	for i := 0; i < 5; i++ {
		e.NoteUnknownHost("198.51.100.1", "inconnu.test")
	}
	if len(*bans) != 0 {
		t.Fatalf("5 points sous le seuil de 6 : %+v", *bans)
	}
	e.NoteUnknownHost("198.51.100.1", "inconnu.test")
	if len(*bans) != 1 || (*bans)[0].reason != "threat: score cumulé" {
		t.Fatalf("six accès franchissent le seuil : %+v", *bans)
	}
	if got := sumPoints((*bans)[0].signals); got != 6 || (*bans)[0].signals[0].Name != "unknown_host" || (*bans)[0].signals[0].Value != "inconnu.test" {
		t.Fatalf("le ban explique le signal avec ses points et le nom demandé : %+v", (*bans)[0].signals)
	}
}

func TestUnknownHostPointsAreConfigurable(t *testing.T) {
	e, _, bans := unknownEngine(t, UnknownHostBlock, func(c *Config) { c.UnknownHost.Points = 3 })
	e.NoteUnknownHost("198.51.100.1", "x.test")
	if len(*bans) != 0 {
		t.Fatal("3 points sous le seuil")
	}
	e.NoteUnknownHost("198.51.100.1", "x.test")
	if len(*bans) != 1 {
		t.Fatalf("2 × 3 points atteignent 6 : %+v", *bans)
	}
}

func TestUnknownHostDetectOnlyCounts(t *testing.T) {
	e, _, bans := unknownEngine(t, UnknownHostDetect)
	before := unknownCount("shadow")
	for i := 0; i < 20; i++ {
		e.NoteUnknownHost("198.51.100.1", "x.test")
	}
	if len(*bans) != 0 || unknownCount("shadow") != before+20 {
		t.Fatalf("en detect : compté, jamais versé : %+v", *bans)
	}
}

func TestUnknownHostOffAndWithoutScoreDoNothing(t *testing.T) {
	e, _, bans := unknownEngine(t, "")
	for i := 0; i < 20; i++ {
		e.NoteUnknownHost("198.51.100.1", "x.test")
	}
	if len(*bans) != 0 {
		t.Fatal("off par défaut")
	}
	e2, _, bans2 := unknownEngine(t, UnknownHostBlock, func(c *Config) { c.IPScore.Enabled = false })
	for i := 0; i < 20; i++ {
		e2.NoteUnknownHost("198.51.100.1", "x.test")
	}
	if len(*bans2) != 0 {
		t.Fatal("sans score cumulé, rien n'est versé : jamais de ban au premier accès")
	}
}

func TestUnknownHostExemptions(t *testing.T) {
	e, _, bans := unknownEngine(t, UnknownHostBlock, func(c *Config) {
		c.Whitelist = Whitelist{IPs: []string{"203.0.113.7"}}
		c.UnknownHost.Probes = []string{"192.0.2.0/24", "198.18.0.9"}
	})
	exempt := unknownCount("exempt")
	ips := []string{"10.1.2.3", "192.168.1.5", "104.16.0.1", "203.0.113.7", "192.0.2.77", "198.18.0.9", "pas-une-ip"}
	for _, ip := range ips {
		for i := 0; i < 20; i++ {
			e.NoteUnknownHost(ip, "x.test")
		}
	}
	if len(*bans) != 0 {
		t.Fatalf("réseau privé, Cloudflare, liste blanche et sondes déclarées ne sont jamais notés : %+v", *bans)
	}
	if unknownCount("exempt") != exempt+float64(20*len(ips)) {
		t.Fatal("les accès exemptés sont comptés")
	}
}

// Une IP aux accès réguliers est une sonde probable : proposée à l'exemption, plus notée.
func TestUnknownHostRegularCadenceIsAProbeNotAScanner(t *testing.T) {
	e, now, bans := unknownEngine(t, UnknownHostBlock)
	for i := 0; i < 40; i++ {
		*now = now.Add(30 * time.Second)
		e.NoteUnknownHost("198.51.100.9", "supervision.test")
	}
	if len(*bans) != 0 {
		t.Fatalf("une sonde toutes les 30 s ne doit pas être bannie : %+v", *bans)
	}
	probes := e.UnknownHostProbes()
	if len(probes) != 1 || probes[0].IP != "198.51.100.9" || probes[0].IntervalSeconds != 30 || probes[0].Hits != 40 {
		t.Fatalf("la sonde est proposée à l'exemption : %+v", probes)
	}
	e.ForgetIP("198.51.100.9")
	if len(e.UnknownHostProbes()) != 0 {
		t.Fatal("l'effacement RGPD retire la sonde")
	}
}

func TestUnknownHostIrregularCadenceIsScored(t *testing.T) {
	e, now, bans := unknownEngine(t, UnknownHostBlock)
	for _, gap := range []time.Duration{time.Second, 60 * time.Second, 3 * time.Second, 45 * time.Second, 2 * time.Second, 90 * time.Second, 4 * time.Second} {
		*now = now.Add(gap)
		e.NoteUnknownHost("198.51.100.9", "scan.test")
	}
	if len(*bans) != 1 || len(e.UnknownHostProbes()) != 0 {
		t.Fatalf("un scan irrégulier est noté et banni : %d bans, sondes %+v", len(*bans), e.UnknownHostProbes())
	}
}

func TestValidateUnknownHost(t *testing.T) {
	ok := Config{IPScore: IPScoreConfig{Enabled: true, BanThreshold: 6}, UnknownHost: UnknownHostConfig{Mode: UnknownHostBlock, Points: 2, Probes: []string{"192.0.2.0/24"}}}
	if err := ok.ValidateUnknownHost(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	many := make([]string, maxUnknownProbes+1)
	for i := range many {
		many[i] = "192.0.2.1"
	}
	for what, mut := range map[string]func(*Config){
		"mode inconnu":                  func(c *Config) { c.UnknownHost.Mode = "bloque" },
		"score cumulé absent":           func(c *Config) { c.IPScore.Enabled = false },
		"points négatifs":               func(c *Config) { c.UnknownHost.Points = -1 },
		"points au-dessus du maximum":   func(c *Config) { c.UnknownHost.Points = 9; c.IPScore.BanThreshold = 50 },
		"points au niveau du seuil ban": func(c *Config) { c.UnknownHost.Points = 5; c.IPScore.BanThreshold = 5 },
		"trop de sondes":                func(c *Config) { c.UnknownHost.Probes = many },
	} {
		c := ok
		mut(&c)
		if err := c.ValidateUnknownHost(); err == nil {
			t.Errorf("%s : la configuration devait être refusée", what)
		}
	}
	off := Config{UnknownHost: UnknownHostConfig{Mode: UnknownHostOff}}
	if err := off.ValidateUnknownHost(); err != nil {
		t.Fatalf("signal off sans score cumulé : %v", err)
	}
}
