// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"sort"
	"time"

	"github.com/vincamok/goproxify/internal/edge/seasonal"
)

// SimSeasonalRoute résume ce que la référence saisonnière aurait fait d'une route pendant le rejeu.
type SimSeasonalRoute struct {
	Route string `json:"route"`
	// Warm : à la fin du rejeu, le créneau courant avait assez d'échantillons pour être cru. Sinon la fenêtre rejouée est trop
	// courte (ou tronquée) pour juger cette route : élargir la fenêtre avant de conclure quoi que ce soit.
	Warm bool `json:"warm"`
	// Warnings et Probables : alertes ouvertes en avertissement, et alertes qui ont atteint l'attaque probable.
	Warnings  int `json:"warnings"`
	Probables int `json:"probables"`
	// AlertSeconds : durée cumulée des alertes.
	AlertSeconds int `json:"alert_seconds"`
	// HardenedRequests : requêtes arrivées pendant que la route aurait été durcie, de la part d'IP sans historique (mode block) ;
	// HardenedServed : parmi elles, celles qui avaient abouti (statut < 400), c'est-à-dire le trafic que le profil durci aurait
	// pu gêner à tort. Un indicateur de faux positifs, pas une certitude.
	HardenedRequests int `json:"hardened_requests,omitempty"`
	HardenedServed   int `json:"hardened_served,omitempty"`
}

// SimSeasonal est la part « référence saisonnière » d'un rapport de rejeu.
type SimSeasonal struct {
	Mode   string             `json:"mode"`
	Events []seasonal.Event   `json:"events"`
	Routes []SimSeasonalRoute `json:"routes"`
}

// simSeasonal rejoue le suivi du trafic sur l'horloge des événements : une tranche de dix secondes par tick, y compris les tranches
// vides (une nuit calme fait partie de ce que la référence apprend).
type simSeasonal struct {
	e      *Engine
	events []seasonal.Event
	next   time.Time
	routes map[string]*SimSeasonalRoute
}

func newSimSeasonal(e *Engine, now func() time.Time) *simSeasonal {
	s := &simSeasonal{e: e, routes: map[string]*SimSeasonalRoute{}}
	e.seasonal = seasonal.New(now, func(ev seasonal.Event) { s.events = append(s.events, ev) })
	return s
}

func (s *simSeasonal) route(name string) *SimSeasonalRoute {
	r := s.routes[name]
	if r == nil {
		r = &SimSeasonalRoute{Route: name}
		s.routes[name] = r
	}
	return r
}

// advance joue les ticks échus avant un événement daté de t.
func (s *simSeasonal) advance(t time.Time) {
	if s.next.IsZero() {
		s.next = t.Truncate(seasonal.BucketSeconds * time.Second).Add(seasonal.BucketSeconds * time.Second)
	}
	for !s.next.After(t) {
		s.e.seasonal.Tick(s.next)
		s.next = s.next.Add(seasonal.BucketSeconds * time.Second)
	}
}

// exposure compte une requête reçue par une route durcie, de la part d'une IP que le profil durci aurait touchée.
func (s *simSeasonal) exposure(ev SimEvent) {
	if s.e.Hardening(ev.Route, ev.IP) == nil {
		return
	}
	r := s.route(ev.Route)
	r.HardenedRequests++
	if ev.Status < 400 {
		r.HardenedServed++
	}
}

func (s *simSeasonal) report(mode string, end time.Time) *SimSeasonal {
	s.advance(end)
	out := &SimSeasonal{Mode: mode, Events: s.events, Routes: []SimSeasonalRoute{}}
	if out.Events == nil {
		out.Events = []seasonal.Event{}
	}
	for _, ev := range s.events {
		r := s.route(ev.Route)
		switch {
		case ev.Kind == "start" && ev.Level == "warning":
			r.Warnings++
		case ev.Kind == "start" && ev.Level == "probable", ev.Kind == "escalate" && ev.Level == "probable":
			r.Probables++
		case ev.Kind == "end":
			r.AlertSeconds += int(ev.Duration.Seconds())
		}
	}
	for _, a := range s.e.seasonal.Active() {
		s.route(a.Route).AlertSeconds += int(end.Sub(a.At).Seconds())
	}
	warm := map[string]bool{}
	for _, st := range s.e.seasonal.Status() {
		warm[st.Route] = st.Warm
		s.route(st.Route)
	}
	for name, r := range s.routes {
		r.Warm = warm[name]
		out.Routes = append(out.Routes, *r)
	}
	sort.Slice(out.Routes, func(i, j int) bool {
		a, b := out.Routes[i], out.Routes[j]
		if a.Probables != b.Probables {
			return a.Probables > b.Probables
		}
		if a.Warnings != b.Warnings {
			return a.Warnings > b.Warnings
		}
		return a.Route < b.Route
	})
	return out
}
