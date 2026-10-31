// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package surface apprend la surface d'un proxy : ce que son trafic légitime utilise (méthodes, gabarits de chemin, types de
// contenu, tailles, paramètres, clients). Le profil est une description agrégée, sans valeur ni IP (ADR 0016). En mode
// `learn` il n'a aucun effet sur le trafic.
package surface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Modes d'un proxy. Seuls off et learn existent : detect et enforce arrivent avec la politique positive (ADR 0016, étapes 3 et 4).
const (
	ModeOff   = "off"
	ModeLearn = "learn"
)

// ValidateMode refuse un mode inconnu ou pas encore livré : une faute de frappe laisserait croire que le proxy est protégé.
func ValidateMode(m string) error {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", ModeOff, ModeLearn:
		return nil
	case "detect", "enforce":
		return fmt.Errorf("surface.mode : %q n'est pas encore disponible (apprentissage seul : off | learn)", m)
	}
	return fmt.Errorf("surface.mode : %q invalide (attendu : off | learn)", m)
}

// Types de proxy. Une API a une surface fermée, dont une liste de chemins est une bonne description ; un site (CMS, blog, contenu créé par
// les utilisateurs) a une surface ouverte, où cette liste n'aurait aucun sens.
const (
	TypeAPI  = "api"
	TypeSite = "site"
)

// ValidateType refuse un type inconnu.
func ValidateType(t string) error {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", TypeAPI, TypeSite:
		return nil
	}
	return fmt.Errorf("surface.type : %q invalide (attendu : api | site)", t)
}

// IsSite dit si le type est un site.
func IsSite(t string) bool { return strings.EqualFold(strings.TrimSpace(t), TypeSite) }

// Learning dit si le mode demande l'apprentissage.
func Learning(m string) bool { return strings.EqualFold(strings.TrimSpace(m), ModeLearn) }

const maxRoutes = 1000

// Options branche le collecteur sur le reste de la passerelle.
type Options struct {
	Now func() time.Time
	// Country et ASN donnent le pays (ISO 3166) et le numéro d'AS d'une IP ; nil ou zéro = inconnu.
	Country func(ip string) string
	ASN     func(ip string) uint32
}

// Collector tient les profils des proxies en apprentissage de cette passerelle, et ceux de ses pairs de groupe HA.
type Collector struct {
	opt    Options
	mu     sync.RWMutex
	routes map[string]*entry
	// peers : dernier profil reçu de chaque pair, par proxy. Remplacé à chaque échange, jamais additionné : la fusion est
	// idempotente (ADR 0014).
	peers map[string]map[string]*RouteProfile
}

type entry struct {
	mu sync.Mutex
	p  *RouteProfile
}

// NewCollector rend un collecteur vide.
func NewCollector(opt Options) *Collector {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Collector{opt: opt, routes: map[string]*entry{}, peers: map[string]map[string]*RouteProfile{}}
}

// Observed est une requête terminée. Path et RawQuery sont pris avant la chaîne de traitement, qui peut les réécrire.
type Observed struct {
	Route, Host    string
	Request        *http.Request
	Path, RawQuery string
	IP             string
	Status         int
	ResponseType   string // Content-Type de la réponse
	// Type : le type du proxy (api | site) tel que sa configuration le déclare, vide si elle ne le dit pas.
	Type string
	// Violation : raison pour laquelle le contrôle openapi du proxy a jugé la requête hors de la spécification, vide si elle est conforme.
	Violation string
	// Blocked : le contrôle openapi a refusé la requête (étape 4).
	Blocked bool
	// WAFHits : les règles du WAF déclenchées par la requête ; WAFBlocked : le WAF l'a refusée ; CleanApartFromWAF : l'IP est propre
	// si l'on met de côté ce que le WAF lui reproche (Clean, lui, l'exclut).
	WAFHits           []WAFHit
	WAFBlocked        bool
	CleanApartFromWAF bool
	// Clean : l'IP n'a ni note de risque, ni règle WAF déclenchée, ni signal d'Ephor. Seule une requête propre peut
	// apprendre quelque chose.
	Clean bool
}

// Observe verse au profil du proxy la requête terminée.
func (c *Collector) Observe(o Observed) {
	e := c.entryFor(o.Route, o.Host)
	if e == nil {
		return
	}
	r := o.Request
	in := input{
		Method: r.Method, Path: o.Path, RawQuery: o.RawQuery, Status: o.Status,
		ReqMedia: mediaType(r.Header.Get("Content-Type")), RespMedia: mediaType(o.ResponseType),
		BodyLen: r.ContentLength, Header: r.Header, IP: o.IP, Proto: r.Proto, TLS: tlsName(r), Origin: r.Header.Get("Origin"), Type: strings.ToLower(strings.TrimSpace(o.Type)), Violation: o.Violation, Blocked: o.Blocked, WAFHits: o.WAFHits, WAFBlocked: o.WAFBlocked, CleanApartFromWAF: o.CleanApartFromWAF, Clean: o.Clean,
	}
	if o.Clean && (o.Status == 0 || learnable(o.Status)) {
		if c.opt.Country != nil {
			in.Country = c.opt.Country(o.IP)
		}
		if c.opt.ASN != nil {
			in.ASN = c.opt.ASN(o.IP)
		}
	}
	now := c.opt.Now()
	e.mu.Lock()
	if o.Host != "" {
		e.p.Host = o.Host
	}
	e.p.observe(&in, now)
	e.mu.Unlock()
}

func (c *Collector) entryFor(id, host string) *entry {
	c.mu.RLock()
	e := c.routes[id]
	c.mu.RUnlock()
	if e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e = c.routes[id]; e != nil {
		return e
	}
	if len(c.routes) >= maxRoutes {
		return nil
	}
	e = &entry{p: newRouteProfile(host)}
	c.routes[id] = e
	return e
}

func mediaType(ct string) string {
	if ct == "" {
		return ""
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	for i := 0; i < len(ct); i++ {
		if ct[i] >= 'A' && ct[i] <= 'Z' {
			return strings.ToLower(ct)
		}
	}
	return ct
}

func tlsName(r *http.Request) string {
	if r.TLS == nil {
		return "clair"
	}
	switch r.TLS.Version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return "TLS"
}

// Reset efface le profil local d'un proxy : l'apprentissage repart de zéro (l'application a changé). Rend faux s'il n'y en avait pas.
func (c *Collector) Reset(routeID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.routes[routeID]
	delete(c.routes, routeID)
	// Ce que les pairs avaient envoyé sur ce proxy s'efface aussi ; ils seront remis à zéro à leur tour.
	for _, m := range c.peers {
		delete(m, routeID)
	}
	return ok
}

// Forget oublie les profils des proxies que keep refuse (proxy supprimé), les siens comme ceux des pairs.
func (c *Collector) Forget(keep func(routeID string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.routes {
		if !keep(id) {
			delete(c.routes, id)
		}
	}
	for _, m := range c.peers {
		for id := range m {
			if !keep(id) {
				delete(m, id)
			}
		}
	}
}

// Payload est ce qu'une passerelle donne à ses pairs : ses profils locaux, jamais ceux qu'elle a reçus d'eux.
type Payload struct {
	Routes map[string]json.RawMessage `json:"routes"`
}

// Export rend les profils locaux.
func (c *Collector) Export() Payload {
	c.mu.RLock()
	ids := make(map[string]*entry, len(c.routes))
	for id, e := range c.routes {
		ids[id] = e
	}
	c.mu.RUnlock()
	out := Payload{Routes: make(map[string]json.RawMessage, len(ids))}
	for id, e := range ids {
		e.mu.Lock()
		b, err := json.Marshal(e.p)
		e.mu.Unlock()
		if err == nil {
			out.Routes[id] = b
		}
	}
	return out
}

// ApplyPeer remplace ce que l'on sait du pair name par son dernier envoi.
func (c *Collector) ApplyPeer(name string, p Payload) {
	profiles := make(map[string]*RouteProfile, len(p.Routes))
	for id, raw := range p.Routes {
		if len(profiles) >= maxRoutes {
			break
		}
		var rp RouteProfile
		if json.Unmarshal(raw, &rp) != nil {
			continue
		}
		rp.normalize()
		profiles[id] = &rp
	}
	c.mu.Lock()
	c.peers[name] = profiles
	c.mu.Unlock()
}

// RetainPeers oublie les pairs qui ne sont plus dans le groupe.
func (c *Collector) RetainPeers(names []string) {
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		keep[n] = true
	}
	c.mu.Lock()
	for n := range c.peers {
		if !keep[n] {
			delete(c.peers, n)
		}
	}
	c.mu.Unlock()
}

// State est la copie locale chiffrée du collecteur (ADR 0006) : un redémarrage, même Admin coupé, ne remet pas
// l'apprentissage à zéro.
type State struct {
	Routes map[string]json.RawMessage          `json:"routes"`
	Peers  map[string]map[string]*RouteProfile `json:"peers,omitempty"`
}

// Snapshot copie l'état à sauvegarder.
func (c *Collector) Snapshot() State {
	local := c.Export()
	c.mu.RLock()
	defer c.mu.RUnlock()
	st := State{Routes: local.Routes, Peers: make(map[string]map[string]*RouteProfile, len(c.peers))}
	for n, m := range c.peers {
		cp := make(map[string]*RouteProfile, len(m))
		for id, p := range m {
			cp[id] = p
		}
		st.Peers[n] = cp
	}
	return st
}

// Restore recharge un état sauvegardé. À appeler avant la première requête.
func (c *Collector) Restore(st State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, raw := range st.Routes {
		if len(c.routes) >= maxRoutes {
			break
		}
		var rp RouteProfile
		if json.Unmarshal(raw, &rp) != nil {
			continue
		}
		rp.normalize()
		c.routes[id] = &entry{p: &rp}
	}
	for n, m := range st.Peers {
		cp := make(map[string]*RouteProfile, len(m))
		for id, p := range m {
			if p == nil {
				continue
			}
			p.normalize()
			cp[id] = p
		}
		c.peers[n] = cp
	}
}

// merged rend le profil du proxy vu par le groupe : le sien et celui de chaque pair. members vaut le nombre de profils fusionnés.
func (c *Collector) merged(routeID string) (rp *RouteProfile, members int) {
	c.mu.RLock()
	e := c.routes[routeID]
	var others []*RouteProfile
	for _, m := range c.peers {
		if p := m[routeID]; p != nil {
			others = append(others, p)
		}
	}
	c.mu.RUnlock()
	if e != nil {
		e.mu.Lock()
		rp = e.p.clone()
		e.mu.Unlock()
		members = 1
	}
	for _, o := range others {
		if rp == nil {
			rp = newRouteProfile(o.Host)
		}
		rp.mergeFrom(o)
		members++
	}
	return rp, members
}

// Routes rend les identifiants des proxies dont la passerelle connaît un profil, le sien ou celui d'un pair.
func (c *Collector) Routes() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := map[string]bool{}
	for id := range c.routes {
		seen[id] = true
	}
	for _, m := range c.peers {
		for id := range m {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// ForgetViolations efface les violations désignées par leurs clés ("raison MÉTHODE chemin") du profil local et de ceux des pairs :
// la politique les couvre désormais, leur compte ne dit plus rien. Rend le nombre d'entrées effacées dans le profil local.
func (c *Collector) ForgetViolations(routeID string, keys []string) int {
	c.mu.RLock()
	e := c.routes[routeID]
	c.mu.RUnlock()
	n := 0
	if e != nil {
		e.mu.Lock()
		n = e.p.forgetViolations(keys)
		e.mu.Unlock()
	}
	c.mu.Lock()
	for _, m := range c.peers {
		// Le profil d'un pair n'est jamais modifié sur place (il est lu sans verrou) : on le remplace par une copie corrigée.
		if p := m[routeID]; p != nil {
			cp := p.clone()
			if cp.forgetViolations(keys) > 0 {
				m[routeID] = cp
			}
		}
	}
	c.mu.Unlock()
	return n
}

func (rp *RouteProfile) forgetViolations(keys []string) int {
	n := 0
	for _, k := range keys {
		v, ok := rp.Violations[k]
		if !ok {
			continue
		}
		reason := k
		if i := strings.IndexByte(k, ' '); i > 0 {
			reason = k[:i]
		}
		if rp.ViolationTotals[reason] -= v.Count; rp.ViolationTotals[reason] <= 0 {
			delete(rp.ViolationTotals, reason)
		}
		if rp.BlockedTotals != nil {
			if rp.BlockedTotals[reason] -= v.Blocked; rp.BlockedTotals[reason] <= 0 {
				delete(rp.BlockedTotals, reason)
			}
		}
		delete(rp.Violations, k)
		n++
	}
	return n
}

// Suggestions rend les ajouts suggérés pour le proxy, vu par le groupe. Vide si la passerelle n'a pas de profil.
func (c *Collector) Suggestions(routeID string) []Suggestion {
	rp, _ := c.merged(routeID)
	if rp == nil {
		return nil
	}
	return suggestionsOf(rp)
}
