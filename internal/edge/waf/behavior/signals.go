// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"math"
	"sync"
	"time"
)

// Noms des signaux de comportement. Les huit premiers existaient avant l'ADR 0011 et comptent dans le score du WAF ; les
// suivants naissent en `detect` : listés et expliqués, ils ne comptent que si Ephor les passe en `block`.
const (
	SignalHigh4xxRate      = "high_4xx_rate"
	SignalPathScanning     = "path_scanning"
	SignalWAFAccumulation  = "waf_score_accumulation"
	SignalUARotation       = "ua_rotation"
	SignalRequestBurst     = "request_burst"
	SignalHighPostRatio    = "high_post_ratio"
	SignalHighPathEntropy  = "high_path_entropy"
	SignalDistributedScan  = "distributed_scan"
	SignalUATLSMismatch    = "ua_tls_mismatch"
	SignalNoAssets         = "no_assets"
	SignalRegularInterval  = "regular_interval"
	SignalScanBreadth      = "scan_breadth"
	SignalASNAggregate     = "asn_aggregate"
	SignalRateDeviation    = "rate_deviation"
	SignalHAPeer           = "ha_peer"           // note reçue d'une passerelle du groupe HA
	SignalRestored         = "restored"          // note relue du disque au démarrage
	SignalCrowdSec         = "crowdsec"          // décision de CrowdSec prise en entrée
	SignalSurface          = "surface_violation" // requête hors de la politique de surface du proxy (ADR 0016), refusée par le backend
	minPagesNoAssets       = 25
	minIntervals           = 12
	minRegularMean         = 100 * time.Millisecond
	maxRegularMean         = 30 * time.Second
	maxRegularCV           = 0.10
	minScanBreadthPaths    = 10
	minASNIPs              = 8
	minASNEvents           = 30
	minASNBadPercent       = 60
	minTLSMismatchRequests = 3
)

// AllSignals liste les signaux dont Ephor règle le mode.
var AllSignals = []string{
	SignalHigh4xxRate, SignalPathScanning, SignalWAFAccumulation, SignalUARotation, SignalRequestBurst,
	SignalHighPostRatio, SignalHighPathEntropy, SignalDistributedScan,
	SignalUATLSMismatch, SignalNoAssets, SignalRegularInterval, SignalScanBreadth, SignalASNAggregate, SignalRateDeviation,
	SignalCrowdSec, SignalSurface,
}

// legacyExt : les signaux venus d'ailleurs qui comptent dans le score du WAF (ils remplacent l'ancien événement synthétique).
func legacyExt(name string) bool { return name == SignalHAPeer || name == SignalRestored }

type scratch struct {
	paths, uas, errPaths map[uint32]struct{}
}

var scratchPool = sync.Pool{New: func() any {
	return &scratch{
		paths:    make(map[uint32]struct{}, 32),
		uas:      make(map[uint32]struct{}, 8),
		errPaths: make(map[uint32]struct{}, 32),
	}
}}

// analyze calcule le score du WAF (signaux historiques) et la liste de tous les signaux à partir de la fenêtre de l'IP.
// p.mu doit être tenu.
func (s *Store) analyze(p *Profile, ip string, now time.Time) (total int, signals []Signal) {
	add := func(name string, score int, detect bool) {
		signals = append(signals, Signal{Name: name, Score: score, Detect: detect})
		if !detect {
			total += score
		}
	}

	events := p.events
	if n := len(events); n > 0 {
		sc := scratchPool.Get().(*scratch)
		clear(sc.paths)
		clear(sc.uas)
		clear(sc.errPaths)

		var count4xx, wafSum, writes, pages, assets, mismatches int
		for _, e := range events {
			is4xx := e.status >= 400 && e.status < 500
			if is4xx {
				count4xx++
				sc.errPaths[e.pathHash] = struct{}{}
			}
			wafSum += int(e.waf)
			if e.method == 'W' {
				writes++
			}
			sc.paths[e.pathHash] = struct{}{}
			sc.uas[e.uaHash] = struct{}{}
			if e.flags&flagPage != 0 {
				pages++
			}
			if e.flags&flagAsset != 0 {
				assets++
			}
			if e.flags&flagTLSMismatch != 0 {
				mismatches++
			}
		}
		nPaths, nUAs, nErrPaths := len(sc.paths), len(sc.uas), len(sc.errPaths)
		scratchPool.Put(sc)

		if n >= 5 && count4xx*100/n >= 40 {
			add(SignalHigh4xxRate, 4, false)
		}
		if nPaths >= 15 {
			add(SignalPathScanning, 3, false)
		}
		if wafSum >= 8 {
			sc := 3
			if wafSum >= 15 {
				sc = 5
			}
			add(SignalWAFAccumulation, sc, false)
		}
		if nUAs >= 3 {
			add(SignalUARotation, 3, false)
		}
		if burstCount(events, 10*time.Second) >= 30 {
			add(SignalRequestBurst, 4, false)
		}
		if n >= 10 && writes*100/n >= 70 {
			add(SignalHighPostRatio, 2, false)
		}
		if n >= 20 && pathEntropy(nPaths, n) > 0.85 {
			add(SignalHighPathEntropy, 2, false)
		}

		// Signaux nés avec l'ADR 0011 : en `detect` d'abord.
		if mismatches >= minTLSMismatchRequests {
			add(SignalUATLSMismatch, 4, true)
		}
		if pages >= minPagesNoAssets && assets == 0 {
			add(SignalNoAssets, 2, true)
		}
		if regularIntervals(events) {
			add(SignalRegularInterval, 2, true)
		}
		if n >= minScanBreadthPaths && nErrPaths >= minScanBreadthPaths && nErrPaths*100/n >= 50 {
			add(SignalScanBreadth, 3, true)
		}
	}

	if p.asn != 0 {
		if pts, ok := s.asnSignal(p.asn, now); ok {
			add(SignalASNAggregate, pts, true)
		}
	}
	for name, e := range p.ext {
		if e.until.After(now) {
			add(name, e.points, !legacyExt(name))
			if e.cold {
				signals[len(signals)-1].Cold = true
			}
		}
	}
	return total, signals
}

func burstCount(events []rec, d time.Duration) int {
	if len(events) == 0 {
		return 0
	}
	cutoff := events[len(events)-1].at - int64(d)
	count := 0
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].at < cutoff {
			break
		}
		count++
	}
	return count
}

// pathEntropy : part de chemins distincts parmi les requêtes, ramenée à [0, 1].
func pathEntropy(unique, total int) float64 {
	if total <= 1 || unique <= 1 {
		return 0
	}
	u := float64(unique)
	p := u / float64(total)
	if p <= 0 || p > 1 {
		return 0
	}
	h := -p * math.Log2(p) * u / math.Log2(float64(total))
	if h > 1 {
		h = 1
	}
	return h
}

// regularIntervals : les vingt dernières requêtes arrivent à intervalles presque identiques (coefficient de variation faible,
// intervalle moyen entre 100 ms et 30 s) — le rythme d'un script, pas d'une personne. Plus rapide que 100 ms, c'est une
// rafale (request_burst) ; plus lent que 30 s, la série ne tient pas dans la fenêtre.
func regularIntervals(events []rec) bool {
	n := len(events)
	if n < minIntervals+1 {
		return false
	}
	if n > 21 {
		events = events[n-21:]
		n = 21
	}
	k := float64(n - 1)
	var sum, sumSq float64
	for i := 1; i < n; i++ {
		d := float64(events[i].at - events[i-1].at)
		if d < 0 {
			return false
		}
		sum += d
		sumSq += d * d
	}
	mean := sum / k
	if mean < float64(minRegularMean) || mean > float64(maxRegularMean) {
		return false
	}
	variance := sumSq/k - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)/mean < maxRegularCV
}

// asnSignal : plusieurs IP du même ASN, dont la majorité des requêtes tourne mal, sur dix fenêtres — l'attaque distribuée
// qui reste sous les seuils de chaque adresse et de chaque /24.
func (s *Store) asnSignal(asn uint32, now time.Time) (int, bool) {
	s.asnMu.RLock()
	ap, ok := s.asnProfs[asn]
	s.asnMu.RUnlock()
	if !ok {
		return 0, false
	}
	ap.mu.Lock()
	defer ap.mu.Unlock()
	purgeASN(ap, now, s.window*asnWindowFactor)
	if len(ap.events) < minASNEvents {
		return 0, false
	}
	ips := make(map[uint32]struct{}, 16)
	bad := 0
	for _, e := range ap.events {
		ips[e.ip] = struct{}{}
		if e.bad {
			bad++
		}
	}
	if len(ips) < minASNIPs || bad*100/len(ap.events) < minASNBadPercent {
		return 0, false
	}
	return 4, true
}
