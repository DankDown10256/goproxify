// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func item(t *testing.T, p Proposals, setting string) Proposal {
	t.Helper()
	for _, it := range p.Items {
		if it.Setting == setting {
			return it
		}
	}
	t.Fatalf("pas de proposition %q ; proposées : %d, écartées : %v", setting, len(p.Items), p.Skipped)
	return Proposal{}
}

func skipped(p Proposals, setting string) string {
	for _, s := range p.Skipped {
		if s.Setting == setting {
			return s.Reason
		}
	}
	return ""
}

// feed injecte n requêtes d'un même profil, avec pays, origine et corps.
func feed(c *Collector, n int, mk func(i int) Observed) {
	for i := 0; i < n; i++ {
		c.Observe(mk(i))
	}
}

func TestProposeMaxBodyFromObservedBodies(t *testing.T) {
	c, _ := NewCollectorForTest()
	feed(c, 300, func(i int) Observed {
		r := req("POST", "/api/items")
		r.ContentLength = int64(200 + i*10) // jusqu'à ≈ 3 Ko
		return obs("r1", "app.test", r, fmt.Sprintf("10.0.%d.1", i%5), 201, "application/json", true)
	})
	p, ok := c.Proposals("r1", Current{Host: "app.test"}, nil)
	if !ok {
		t.Fatal("pas de propositions")
	}
	body := item(t, p, SettingMaxBody)
	if string(body.Value) != "16384" {
		t.Errorf("valeur %s, attendu 16384 (double du plus gros corps ≈ 6 Ko, palier 16 Ko)", body.Value)
	}
	if !body.Measured || body.WouldRefuse != 0 || body.Of != 300 {
		t.Errorf("mesure : %+v", body)
	}
	if !strings.Contains(body.Command, "goproxify proxy option r1 max_body_size '16384'") {
		t.Errorf("commande : %s", body.Command)
	}
}

func TestProposeMaxBodySkips(t *testing.T) {
	// Corps de taille inconnue : rien n'est mesurable.
	c, _ := NewCollectorForTest()
	feed(c, 150, func(i int) Observed {
		return obs("r1", "app.test", req("POST", "/up"), "10.0.0.1", 200, "", true) // req() annonce -1
	})
	p, _ := c.Proposals("r1", Current{}, nil)
	if skipped(p, SettingMaxBody) == "" || !strings.Contains(skipped(p, SettingMaxBody), "inconnu") {
		t.Errorf("corps de taille inconnue : %v", p.Skipped)
	}

	// Limite actuelle déjà plus basse que la proposition.
	c, _ = NewCollectorForTest()
	feed(c, 150, func(i int) Observed {
		r := req("POST", "/up")
		r.ContentLength = 1 << 20
		return obs("r1", "app.test", r, "10.0.0.1", 200, "", true)
	})
	p, _ = c.Proposals("r1", Current{MaxBodySize: 2 << 20}, nil)
	if skipped(p, SettingMaxBody) == "" {
		t.Errorf("la limite actuelle est déjà proche : %v", p.Items)
	}
	p, _ = c.Proposals("r1", Current{MaxBodySize: -1}, nil)
	if got := item(t, p, SettingMaxBody); got.Current != "illimité" || string(got.Value) != "2097152" {
		t.Errorf("proxy illimité : %+v", got)
	}
}

func TestProposeNothingBelowMinimumVolume(t *testing.T) {
	c, _ := NewCollectorForTest()
	feed(c, 20, func(i int) Observed { return obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true) })
	p, _ := c.Proposals("r1", Current{}, nil)
	if len(p.Items) != 0 || len(p.Skipped) != 6 {
		t.Errorf("propositions %d, écartées %d ; attendu 0 et 6", len(p.Items), len(p.Skipped))
	}
}

func TestProposeGeoCoversTrafficAndRefusesTheRest(t *testing.T) {
	c := NewCollector(Options{Now: time.Now, Country: func(ip string) string {
		switch {
		case strings.HasPrefix(ip, "10.1."):
			return "FR"
		case strings.HasPrefix(ip, "10.2."):
			return "BE"
		}
		return "CN"
	}})
	feed(c, 1000, func(i int) Observed {
		ip := fmt.Sprintf("10.1.%d.%d", i%200, i%250)
		if i%10 == 0 {
			ip = fmt.Sprintf("10.2.%d.1", i%100)
		}
		if i == 7 {
			ip = "10.3.0.1" // un seul client chinois sur mille
		}
		return obs("r1", "app.test", req("GET", "/"), ip, 200, "", true)
	})
	p, _ := c.Proposals("r1", Current{Host: "app.test"}, nil)
	geo := item(t, p, SettingGeo)
	var v struct {
		Mode      string
		Countries []string
	}
	if err := json.Unmarshal(geo.Value, &v); err != nil || v.Mode != "allow" || strings.Join(v.Countries, ",") != "BE,FR" {
		t.Fatalf("valeur %s (%v)", geo.Value, err)
	}
	if !geo.Measured || geo.WouldRefuse != 1 || geo.Of != 1000 {
		t.Errorf("refus mesuré : %d sur %d", geo.WouldRefuse, geo.Of)
	}

	// Un service mondial n'a pas de liste de pays à proposer.
	world := NewCollector(Options{Now: time.Now, Country: func(ip string) string { return "C" + ip[len(ip)-1:] + ip[len(ip)-2:len(ip)-1] }})
	feed(world, 2000, func(i int) Observed {
		return obs("r1", "app.test", req("GET", "/"), fmt.Sprintf("10.0.%d.%d", i%100, i%100), 200, "", true)
	})
	p, _ = world.Proposals("r1", Current{}, nil)
	if !strings.Contains(skipped(p, SettingGeo), "mondial") {
		t.Errorf("service mondial : %v", p.Skipped)
	}

	// Sans résolveur de pays (base absente), aucune proposition.
	none, _ := NewCollectorForTest()
	feed(none, 200, func(i int) Observed { return obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true) })
	p, _ = none.Proposals("r1", Current{}, nil)
	if !strings.Contains(skipped(p, SettingGeo), "pays est inconnu") {
		t.Errorf("sans base GeoIP : %v", p.Skipped)
	}
}

func TestProposeIPFilterOnlyForFewNetworks(t *testing.T) {
	c, _ := NewCollectorForTest()
	feed(c, 400, func(i int) Observed {
		ip := fmt.Sprintf("192.168.1.%d", i%200)
		if i%4 == 0 {
			ip = fmt.Sprintf("10.20.30.%d", i%200)
		}
		return obs("r1", "intra.test", req("GET", "/"), ip, 200, "", true)
	})
	p, _ := c.Proposals("r1", Current{}, nil)
	f := item(t, p, SettingIPFilter)
	var v struct {
		Mode  string
		CIDRs []string
	}
	if err := json.Unmarshal(f.Value, &v); err != nil || v.Mode != "allow" || strings.Join(v.CIDRs, ",") != "192.168.1.0/24,10.20.30.0/24" {
		t.Fatalf("valeur %s (%v)", f.Value, err)
	}
	if strings.Contains(strings.Join(f.Evidence, " "), "192.168.1.5") {
		t.Error("une adresse exacte figure dans la justification")
	}

	// Un service public (beaucoup de réseaux) n'a pas de liste d'IP autorisées.
	pub, _ := NewCollectorForTest()
	feed(pub, 600, func(i int) Observed {
		return obs("r1", "pub.test", req("GET", "/"), fmt.Sprintf("10.%d.%d.1", i%30, i%7), 200, "", true)
	})
	p, _ = pub.Proposals("r1", Current{}, nil)
	if !strings.Contains(skipped(p, SettingIPFilter), "service public") {
		t.Errorf("service public : %v", p.Skipped)
	}

	// IPv6 : réseau /48.
	v6, _ := NewCollectorForTest()
	feed(v6, 200, func(i int) Observed {
		return obs("r1", "a.test", req("GET", "/"), fmt.Sprintf("2001:db8:1:%x::%x", i, i+1), 200, "", true)
	})
	p, _ = v6.Proposals("r1", Current{}, nil)
	if got := item(t, p, SettingIPFilter); !strings.Contains(string(got.Value), "2001:db8:1::/48") {
		t.Errorf("IPv6 : %s", got.Value)
	}
}

func TestProposeCORSIgnoresSameOrigin(t *testing.T) {
	c, _ := NewCollectorForTest()
	feed(c, 300, func(i int) Observed {
		r := req("GET", "/api/data")
		switch i % 3 {
		case 0:
			r.Header.Set("Origin", "https://app.partenaire.test")
		case 1:
			r.Header.Set("Origin", "https://api.test") // même origine que le proxy
		}
		if i%50 == 0 {
			r.Method = http.MethodPut
		}
		return obs("r1", "api.test", r, "10.0.0.1", 200, "", true)
	})
	p, _ := c.Proposals("r1", Current{Host: "api.test"}, nil)
	cors := item(t, p, SettingCORS)
	var v struct {
		AllowedOrigins []string `json:"allowed_origins"`
		AllowedMethods []string `json:"allowed_methods"`
	}
	if err := json.Unmarshal(cors.Value, &v); err != nil || strings.Join(v.AllowedOrigins, ",") != "https://app.partenaire.test" {
		t.Fatalf("origines %s (%v)", cors.Value, err)
	}
	if strings.Join(v.AllowedMethods, ",") != "GET,PUT" {
		t.Errorf("méthodes %v", v.AllowedMethods)
	}

	// Aucun trafic inter-origines : pas de CORS à proposer.
	none, _ := NewCollectorForTest()
	feed(none, 200, func(i int) Observed { return obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true) })
	p, _ = none.Proposals("r1", Current{}, nil)
	if !strings.Contains(skipped(p, SettingCORS), "autre origine") {
		t.Errorf("sans origine : %v", p.Skipped)
	}
}

func TestProposeRateFromReadyReferences(t *testing.T) {
	c, _ := NewCollectorForTest()
	feed(c, 200, func(i int) Observed { return obs("r1", "a.test", req("GET", "/"), "10.0.0.1", 200, "", true) })

	p, _ := c.Proposals("r1", Current{}, []RateRef{{Hour: 9, Median: 4, Threshold: 20, Ready: false}})
	if !strings.Contains(skipped(p, SettingRate), "en apprentissage") {
		t.Errorf("références froides : %v", p.Skipped)
	}

	refs := []RateRef{{Hour: 9, Median: 4, Threshold: 120, Ready: true}, {Hour: 10, Median: 6, Threshold: 300, Ready: true}, {Hour: 3, Threshold: 900}}
	p, _ = c.Proposals("r1", Current{}, refs)
	rate := item(t, p, SettingRate)
	if string(rate.Value) != `{"burst":20,"rps":10}` {
		t.Errorf("valeur %s, attendu 10 rps (double de 300 req/min) et rafale 20 ; l'heure non prête est ignorée", rate.Value)
	}
	if rate.Measured {
		t.Error("le débit par IP n'est pas mesuré sur le profil")
	}
	p, _ = c.Proposals("r1", Current{RateLimit: true}, refs)
	if skipped(p, SettingRate) == "" {
		t.Error("un rate limit existant ne se remplace pas")
	}
}

func TestProposalsKeepAdministratorSettings(t *testing.T) {
	c, _ := NewCollectorForTest()
	feed(c, 300, func(i int) Observed {
		r := req("GET", "/")
		r.Header.Set("Origin", "https://autre.test")
		return obs("r1", "a.test", r, "10.0.0.1", 200, "", true)
	})
	p, _ := c.Proposals("r1", Current{Host: "a.test", GeoIP: true, IPFilter: true, CORS: true, RateLimit: true}, []RateRef{{Ready: true, Threshold: 60}})
	for _, s := range []string{SettingGeo, SettingIPFilter, SettingCORS, SettingRate} {
		if skipped(p, s) == "" || !strings.Contains(skipped(p, s), "déjà") {
			t.Errorf("%s : %q", s, skipped(p, s))
		}
	}
}

func TestRangeKeyRoundTripAndMapped(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77": "203.0.113.0/24", "::ffff:198.51.100.9": "198.51.100.0/24", "2001:db8:abcd:1234::5": "2001:db8:abcd::/48",
	} {
		k := rangeKey(in)
		if k == 0 || rangeCIDR(k) != want {
			t.Errorf("%s → %q, attendu %q", in, rangeCIDR(k), want)
		}
	}
	if rangeKey("pas une ip") != 0 {
		t.Error("une IP illisible doit rendre 0")
	}
}

func TestNiceBytes(t *testing.T) {
	for in, want := range map[int64]int64{1: 16 << 10, 16 << 10: 16 << 10, 16<<10 + 1: 32 << 10, 3 << 20: 5 << 20, 1 << 40: 100 << 20} {
		if got := niceBytes(in); got != want {
			t.Errorf("niceBytes(%d) = %d, attendu %d", in, got, want)
		}
	}
}

// NewCollectorForTest : collecteur à horloge fixe, sans résolveur de pays ni d'AS.
func NewCollectorForTest() (*Collector, *clock) { return newTest() }
