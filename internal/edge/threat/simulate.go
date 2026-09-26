// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// SimEvent est une requête historique à rejouer (issue des access logs).
type SimEvent struct {
	Time   time.Time
	IP     string
	UA     string // vide si inconnu : les règles UA ne sont alors pas évaluées
	Path   string
	Status int // statut réellement renvoyé à l'époque
}

// SimBan est un ban qui aurait été posé pendant le rejeu.
type SimBan struct {
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// SimIPStat résume l'impact du rejeu sur une IP.
type SimIPStat struct {
	IP           string   `json:"ip"`
	Blocked      int      `json:"blocked"`
	LegitBlocked int      `json:"legit_blocked"`
	Reasons      []string `json:"reasons"`
	SamplePaths  []string `json:"sample_paths"`
}

// SimReport est le résultat d'un rejeu. LegitBlocked compte les requêtes qui
// auraient été bloquées alors qu'elles avaient abouti (statut < 400) : c'est un
// indicateur de faux positifs, pas une certitude (un attaquant peut obtenir un 200).
type SimReport struct {
	Events       int            `json:"events"`
	Blocked      int            `json:"blocked"`
	BlockedByBan int            `json:"blocked_by_ban"` // sous-ensemble de Blocked : IP déjà bannie pendant le rejeu
	LegitBlocked int            `json:"legit_blocked"`
	BlockedIPs   int            `json:"blocked_ips"`
	ByReason     map[string]int `json:"by_reason"`
	Bans         []SimBan       `json:"bans"`
	TopIPs       []SimIPStat    `json:"top_ips"`
}

const (
	simTopIPs       = 10
	simSamplePaths  = 3
	simReasonsPerIP = 5
)

// Simulate rejoue des événements historiques contre cfg, en mode "block", avec la
// même logique que Check/RecordStatus mais sur l'horloge des événements.
// Non simulés : listes par défaut (téléchargées), limiteur global GlobalRPS.
func Simulate(cfg Config, events []SimEvent) SimReport {
	cfg.Enabled = true
	cfg.Mode = "block"
	cfg.Lists = ListsConfig{}
	cfg.GlobalRPS = 0
	cfg.defaults()

	events = append([]SimEvent(nil), events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })

	var cur time.Time
	report := SimReport{ByReason: map[string]int{}, Bans: []SimBan{}, TopIPs: []SimIPStat{}}
	banned := map[string]time.Time{}

	e := New(slog.New(slog.NewTextHandler(io.Discard, nil)), func(ip, reason string, _ time.Time) {
		report.Bans = append(report.Bans, SimBan{IP: ip, Reason: reason, At: cur})
		banned[ip] = cur.Add(cfg.BanDuration.Duration)
	})
	e.sim = true
	e.counters.now = func() time.Time { return cur }
	e.UpdateConfig(cfg)

	stats := map[string]*SimIPStat{}
	block := func(ev SimEvent, reason string) {
		report.Blocked++
		report.ByReason[reason]++
		st := stats[ev.IP]
		if st == nil {
			st = &SimIPStat{IP: ev.IP}
			stats[ev.IP] = st
		}
		st.Blocked++
		if ev.Status < 400 {
			report.LegitBlocked++
			st.LegitBlocked++
		}
		if len(st.Reasons) < simReasonsPerIP && !contains(st.Reasons, reason) {
			st.Reasons = append(st.Reasons, reason)
		}
		if len(st.SamplePaths) < simSamplePaths && !contains(st.SamplePaths, ev.Path) {
			st.SamplePaths = append(st.SamplePaths, ev.Path)
		}
	}

	for _, ev := range events {
		cur = ev.Time
		report.Events++
		if until, ok := banned[ev.IP]; ok {
			if cur.Before(until) {
				report.BlockedByBan++
				block(ev, "ban")
				continue
			}
			delete(banned, ev.IP)
		}
		req := &http.Request{Header: http.Header{}, URL: &url.URL{Path: ev.Path}}
		if ev.UA != "" {
			req.Header.Set("User-Agent", ev.UA)
		}
		if blocked, reason := e.Check(req, ev.IP); blocked {
			block(ev, reason)
			continue
		}
		e.RecordStatus(ev.IP, ev.Status)
	}

	report.BlockedIPs = len(stats)
	for _, st := range stats {
		report.TopIPs = append(report.TopIPs, *st)
	}
	sort.Slice(report.TopIPs, func(i, j int) bool {
		if report.TopIPs[i].Blocked != report.TopIPs[j].Blocked {
			return report.TopIPs[i].Blocked > report.TopIPs[j].Blocked
		}
		return report.TopIPs[i].IP < report.TopIPs[j].IP
	})
	if len(report.TopIPs) > simTopIPs {
		report.TopIPs = report.TopIPs[:simTopIPs]
	}
	return report
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
