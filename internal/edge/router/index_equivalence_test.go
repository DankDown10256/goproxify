// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router_test

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Les recherches linéaires d'avant l'index (ADR 0020, étape 1), gardées ici comme référence : l'index doit rendre les
// mêmes verdicts, et la même raison, qui est celle du premier ban de la liste qui correspond.

var legacyPrivate = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7", "169.254.0.0/16"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func legacyIsPrivate(ip net.IP) bool {
	for _, n := range legacyPrivate {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type legacyBan struct {
	b  *router.RuntimeBan
	ip net.IP
	nw *net.IPNet
}

func legacyBans(bans []*router.RuntimeBan) []legacyBan {
	now := time.Now()
	var out []legacyBan
	for _, b := range bans {
		if b == nil || b.IP == "" {
			continue
		}
		if b.ExpiresAt != nil && !b.ExpiresAt.IsZero() && b.ExpiresAt.Before(now) {
			continue
		}
		lb := legacyBan{b: b}
		if _, n, err := net.ParseCIDR(b.IP); err == nil {
			lb.nw = n
		} else if ip := net.ParseIP(b.IP); ip != nil {
			lb.ip = ip
		} else {
			continue
		}
		out = append(out, lb)
	}
	return out
}

func legacyBanCheck(list []legacyBan, ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil || legacyIsPrivate(ip) {
		return false, ""
	}
	now := time.Now()
	for _, lb := range list {
		b := lb.b
		if b.ExpiresAt != nil && !b.ExpiresAt.IsZero() && b.ExpiresAt.Before(now) {
			continue
		}
		matched := false
		if lb.nw != nil {
			matched = lb.nw.Contains(ip)
		} else if lb.ip != nil {
			matched = lb.ip.Equal(ip)
		}
		if matched {
			reason := b.Source
			if b.Reason != "" {
				if reason != "" {
					reason += ": "
				}
				reason += b.Reason
			}
			if reason == "" {
				reason = b.IP
			}
			return true, reason
		}
	}
	return false, ""
}

type legacyProfile struct {
	p    *router.IPProfile
	nets []*net.IPNet
}

func legacyProfiles(in []*router.IPProfile) []legacyProfile {
	var out []legacyProfile
	for _, p := range in {
		lp := legacyProfile{p: p}
		for _, cidr := range p.CIDRs {
			if !strings.Contains(cidr, "/") {
				if ip := net.ParseIP(cidr); ip != nil {
					if ip.To4() != nil {
						cidr += "/32"
					} else {
						cidr += "/128"
					}
				}
			}
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				lp.nets = append(lp.nets, n)
			}
		}
		out = append(out, lp)
	}
	return out
}

func (lp legacyProfile) contains(ip net.IP) bool {
	for _, n := range lp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func legacyIsAllowed(list []legacyProfile, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if legacyIsPrivate(ip) {
		return true
	}
	for _, lp := range list {
		if lp.p.Mode == "allow" && lp.contains(ip) {
			return true
		}
	}
	return false
}

func legacyIsWhitelisted(list []legacyProfile, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, lp := range list {
		if lp.p.ID == router.WhitelistProfileID && lp.p.Mode == "allow" && lp.contains(ip) {
			return true
		}
	}
	return false
}

func legacyProfileCheck(list []legacyProfile, ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil || legacyIsPrivate(ip) {
		return false, ""
	}
	for _, lp := range list {
		if lp.p.Mode == "allow" && lp.contains(ip) {
			return false, ""
		}
	}
	for _, lp := range list {
		if lp.p.Mode == "deny" && lp.contains(ip) {
			return true, lp.p.Name
		}
	}
	return false, ""
}

// gen produit des adresses et des bans dans un espace restreint, pour que les chevauchements et les correspondances soient
// fréquents.
type gen struct {
	r     *rand.Rand
	pools [][2]int
	exact []string
}

func newGen(seed uint64) *gen {
	g := &gen{r: rand.New(rand.NewPCG(seed, seed+1))}
	for i := 0; i < 48; i++ {
		g.pools = append(g.pools, [2]int{[]int{198, 203, 100, 45, 91}[g.r.IntN(5)], g.r.IntN(256)})
	}
	return g
}

func (g *gen) v4() string {
	p := g.pools[g.r.IntN(len(g.pools))]
	return fmt.Sprintf("%d.%d.%d.%d", p[0], p[1], g.r.IntN(256), g.r.IntN(256))
}

func (g *gen) v6() string {
	return fmt.Sprintf("2001:db8:%x:%x::%x", g.r.IntN(8), g.r.IntN(8), g.r.IntN(65536))
}

func (g *gen) cidr() string {
	if g.r.IntN(4) == 0 {
		return fmt.Sprintf("%s/%d", g.v6(), []int{32, 48, 56, 64, 96, 128}[g.r.IntN(6)])
	}
	return fmt.Sprintf("%s/%d", g.v4(), 8+g.r.IntN(25))
}

func (g *gen) ban(i int) *router.RuntimeBan {
	b := &router.RuntimeBan{ID: fmt.Sprint(i), Source: []string{"", "crowdsec", "threat", "fail2ban"}[g.r.IntN(4)]}
	if g.r.IntN(2) == 0 {
		b.Reason = fmt.Sprintf("raison %d", i)
	}
	switch k := g.r.IntN(20); {
	case k < 9:
		b.IP = g.v4()
		g.exact = append(g.exact, b.IP)
	case k < 11:
		b.IP = g.v6()
		g.exact = append(g.exact, b.IP)
	case k < 17:
		b.IP = g.cidr()
	case k == 17:
		b.IP = "::ffff:" + g.v4()
	case k == 18:
		b.IP = fmt.Sprintf("%s/24", g.v4()) // non canonique : l'hôte n'est pas à zéro
	default:
		b.IP = []string{"", "pas-une-ip", "300.1.1.1"}[g.r.IntN(3)]
	}
	switch g.r.IntN(6) {
	case 0:
		t := time.Now().Add(-time.Hour)
		b.ExpiresAt = &t
	case 1:
		t := time.Now().Add(time.Hour)
		b.ExpiresAt = &t
	case 2:
		b.ExpiresAt = &time.Time{}
	}
	return b
}

func (g *gen) probe() string {
	switch k := g.r.IntN(20); {
	case k < 8:
		return g.v4()
	case k < 10:
		return g.v6()
	case k < 14 && len(g.exact) > 0:
		return g.exact[g.r.IntN(len(g.exact))]
	case k == 14:
		return "10.1.2.3"
	case k == 15:
		return "::ffff:" + g.v4()
	case k == 16:
		return "fe80::1%eth0"
	case k == 17:
		return []string{"", "pas-une-ip", "1.2.3", "203.0.113.7:443"}[g.r.IntN(4)]
	default:
		return fmt.Sprintf("%d.%d.%d.%d", g.r.IntN(256), g.r.IntN(256), g.r.IntN(256), g.r.IntN(256))
	}
}

func TestBanStoreIndexMatchesLinearScan(t *testing.T) {
	g := newGen(7)
	var bans []*router.RuntimeBan
	for i := 0; i < 3000; i++ {
		bans = append(bans, g.ban(i))
	}
	store := router.NewBanStore()
	store.Replace(bans)
	ref := legacyBans(bans)
	if store.Len() != len(ref) {
		t.Fatalf("Len = %d, attendu %d", store.Len(), len(ref))
	}

	blocked := 0
	for i := 0; i < 40000; i++ {
		p := g.probe()
		gotB, gotR := store.CheckBlocked(p)
		wantB, wantR := legacyBanCheck(ref, p)
		if gotB != wantB || gotR != wantR {
			t.Fatalf("CheckBlocked(%q) = %v %q, ancienne recherche : %v %q", p, gotB, gotR, wantB, wantR)
		}
		if wantB {
			blocked++
		}
	}
	if blocked < 2000 {
		t.Fatalf("le jeu d'essai ne bloque que %d adresses sur 40000 : il ne prouve pas assez", blocked)
	}
}

func TestProfileStoreIndexMatchesLinearScan(t *testing.T) {
	g := newGen(11)
	var profiles []*router.IPProfile
	for i := 0; i < 150; i++ {
		p := &router.IPProfile{ID: fmt.Sprintf("p%d", i), Name: fmt.Sprintf("profil %d", i), Mode: []string{"allow", "deny", "deny", "autre"}[g.r.IntN(4)]}
		if i%25 == 0 {
			p.ID = router.WhitelistProfileID
			p.Mode = "allow"
		}
		for j, n := 0, 1+g.r.IntN(8); j < n; j++ {
			switch g.r.IntN(5) {
			case 0:
				p.CIDRs = append(p.CIDRs, g.v4()) // IP seule, sans masque
			case 1:
				p.CIDRs = append(p.CIDRs, g.v6())
			case 2:
				p.CIDRs = append(p.CIDRs, "pas-un-cidr")
			default:
				p.CIDRs = append(p.CIDRs, g.cidr())
			}
		}
		profiles = append(profiles, p)
	}
	store := router.NewIPProfileStore()
	store.Replace(profiles)
	ref := legacyProfiles(profiles)

	blocked, allowed, wl := 0, 0, 0
	for i := 0; i < 40000; i++ {
		p := g.probe()
		if gotB, gotN := store.CheckBlocked(p); true {
			wantB, wantN := legacyProfileCheck(ref, p)
			if gotB != wantB || gotN != wantN {
				t.Fatalf("CheckBlocked(%q) = %v %q, ancienne recherche : %v %q", p, gotB, gotN, wantB, wantN)
			}
			if wantB {
				blocked++
			}
		}
		if got, want := store.IsAllowed(p), legacyIsAllowed(ref, p); got != want {
			t.Fatalf("IsAllowed(%q) = %v, ancienne recherche : %v", p, got, want)
		} else if want {
			allowed++
		}
		if got, want := store.IsWhitelisted(p), legacyIsWhitelisted(ref, p); got != want {
			t.Fatalf("IsWhitelisted(%q) = %v, ancienne recherche : %v", p, got, want)
		} else if want {
			wl++
		}
	}
	if blocked < 500 || allowed < 500 || wl < 100 {
		t.Fatalf("jeu d'essai trop pauvre : %d bloquées, %d autorisées, %d en liste blanche", blocked, allowed, wl)
	}
}

func benchBans(n int) ([]*router.RuntimeBan, []string) {
	g := newGen(3)
	var bans []*router.RuntimeBan
	for len(bans) < n {
		b := g.ban(len(bans))
		b.ExpiresAt = nil
		if b.IP == "" || b.IP == "pas-une-ip" || b.IP == "300.1.1.1" {
			continue
		}
		bans = append(bans, b)
	}
	probes := make([]string, 4096)
	for i := range probes {
		probes[i] = g.probe()
	}
	return bans, probes
}

// Le coût d'une vérification ne doit plus croître avec le nombre de bans (ADR 0020, étape 1).
func BenchmarkBanStoreCheckBlocked(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		bans, probes := benchBans(n)
		store := router.NewBanStore()
		store.Replace(bans)
		b.Run(fmt.Sprintf("index/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				store.CheckBlocked(probes[i%len(probes)])
			}
		})
		ref := legacyBans(bans)
		b.Run(fmt.Sprintf("lineaire/%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				legacyBanCheck(ref, probes[i%len(probes)])
			}
		})
	}
}
