// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// Modes d'un signal de comportement (ADR 0011).
const (
	BehaviorOff    = "off"    // ignoré
	BehaviorDetect = "detect" // calculé, affiché et tracé ; ne compte pas dans la note qui bannit
	BehaviorBlock  = "block"  // compte dans la note commune de l'IP
)

// BehaviorConfig règle la note commune : le magasin comportemental de la passerelle, qu'Ephor alimente avec toutes les
// requêtes, que le WAF complète avec le score de ses règles et où CrowdSec verse ses décisions.
//
// Tout signal naît en `detect` : il est calculé, expliqué et compté dans une note « fantôme » (le ban qu'il aurait provoqué est
// journalisé et compté par `gpx_threat_shadow_bans_total`), sans jamais bannir. Il passe en `block` après lecture de la
// simulation sur les logs (`legit_blocked`), jamais d'office. Un signal fondé sur une référence encore trop jeune reste en
// `detect` quel que soit son mode.
type BehaviorConfig struct {
	// Mode : mode des signaux absents de Signals. "detect" (défaut), "block", ou "off" : Ephor ne verse plus rien au magasin.
	Mode string `json:"mode,omitempty"`
	// Signals : mode par signal (voir behavior.AllSignals), qui l'emporte sur Mode.
	Signals map[string]string `json:"signals,omitempty"`
	// TLSFamilies complète la table livrée (famille de navigateurs → empreintes de suites de chiffrement, partie « b » d'un JA4).
	TLSFamilies map[string][]string `json:"tls_families,omitempty"`
	// NoTrust coupe le bonus de confiance (un point par centaine de requêtes propres et par jour d'historique sans signal, ajouté
	// au seuil de ban des IP à longue histoire propre).
	NoTrust bool `json:"no_trust,omitempty"`
	// ReferenceMinAge : ancienneté minimale d'une route avant que ses références apprises comptent (défaut 24 h).
	ReferenceMinAge Duration `json:"reference_min_age,omitempty"`
}

// Validate refuse un mode, un signal ou une empreinte inconnus : une faute de frappe laisserait un signal dans un mode que
// l'administrateur n'a pas voulu.
func (c BehaviorConfig) Validate() error {
	checkMode := func(what, m string) error {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "", BehaviorOff, BehaviorDetect, BehaviorBlock:
			return nil
		}
		return fmt.Errorf("%s : %q invalide (attendu : off | detect | block)", what, m)
	}
	if err := checkMode("behavior.mode", c.Mode); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, n := range behavior.AllSignals {
		known[n] = true
	}
	for name, m := range c.Signals {
		if !known[name] {
			return fmt.Errorf("behavior.signals : signal %q inconnu", name)
		}
		if err := checkMode("behavior.signals["+name+"]", m); err != nil {
			return err
		}
	}
	for fam, hashes := range c.TLSFamilies {
		if strings.TrimSpace(fam) == "" {
			return fmt.Errorf("behavior.tls_families : famille vide")
		}
		for _, h := range hashes {
			h = strings.TrimSpace(h)
			if len(h) != 12 || strings.Trim(strings.ToLower(h), "0123456789abcdef") != "" {
				return fmt.Errorf("behavior.tls_families[%s] : %q n'est pas l'empreinte des suites de chiffrement d'un JA4 (12 caractères hexadécimaux)", fam, h)
			}
		}
	}
	if d := c.ReferenceMinAge.Duration; d < 0 || d > 30*24*time.Hour {
		return fmt.Errorf("behavior.reference_min_age : %s hors de 0 – 30 jours", d)
	}
	return nil
}

func (c BehaviorConfig) off() bool { return strings.EqualFold(c.Mode, BehaviorOff) }

// modeOf retourne le mode effectif d'un signal.
func (c BehaviorConfig) modeOf(name string) string {
	if m, ok := c.Signals[name]; ok {
		return normalizeMode(m)
	}
	return normalizeMode(c.Mode)
}

func normalizeMode(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case BehaviorOff:
		return BehaviorOff
	case BehaviorBlock:
		return BehaviorBlock
	}
	return BehaviorDetect
}

// SetBehaviorStore branche le magasin comportemental de la passerelle (le même que celui du WAF).
func (e *Engine) SetBehaviorStore(st *behavior.Store) {
	e.mu.Lock()
	e.behavior = st
	cfg := e.cfg
	e.mu.Unlock()
	e.applyBehaviorConfig(st, cfg)
}

func (e *Engine) applyBehaviorConfig(st *behavior.Store, cfg Config) {
	if st == nil {
		return
	}
	st.SetTLSFamilies(cfg.Behavior.TLSFamilies)
	st.SetReferenceMinAge(cfg.Behavior.ReferenceMinAge.Duration)
}

// Observe verse au magasin comportemental la requête terminée (sauf si le WAF l'y a déjà versée), puis alimente les compteurs
// 4xx d'Ephor. route est l'hôte de la route qui l'a servie.
func (e *Engine) Observe(r *http.Request, ip, route string, status int) {
	e.mu.RLock()
	cfg := e.cfg
	st := e.behavior
	e.mu.RUnlock()
	if cfg.Enabled && st != nil && !cfg.Behavior.off() {
		obs := behavior.ObservationFrom(r.Context())
		if !obs.Recorded() {
			ev := behavior.EventFromRequest(r, status, obs.WAFScore(), route)
			ev.At = e.counters.now()
			st.Record(ip, ev)
		}
	}
	e.RecordResponse(ip, r.URL.Path, status)
	if cfg.Enabled && cfg.TLSReputation.Enabled {
		e.observeTLSReputation(r, ip, status, behavior.ObservationFrom(r.Context()))
	}
	if cfg.Enabled && cfg.Enumeration.Active() {
		e.observeEnumeration(r.URL.Path, ip, route, cfg)
	}
	if cfg.Enabled && cfg.Seasonal.Active() {
		e.seasonal.Record(route, ip, status, r.URL.Path)
	}
	e.observeThresholds(r, ip, route, status, behavior.ObservationFrom(r.Context()))
}

// NoteDecision verse au magasin une décision d'un autre moteur (CrowdSec) : elle pèse sur la note de l'IP jusqu'à
// l'expiration du ban qu'elle a causé, ou une heure pour un ban permanent.
func (e *Engine) NoteDecision(ip, signal string, points int, until time.Time) {
	e.mu.RLock()
	cfg := e.cfg
	st := e.behavior
	e.mu.RUnlock()
	if st == nil || !cfg.Enabled || cfg.Behavior.off() {
		return
	}
	if until.IsZero() {
		until = e.counters.now().Add(time.Hour)
	}
	st.AddSignal(ip, signal, points, until)
}

// ForgetIP efface ce que le moteur et le magasin comportemental gardent d'une IP (ordre d'effacement RGPD).
func (e *Engine) ForgetIP(ip string) {
	e.counters.reset(ip)
	e.unknown.forget(ip)
	e.thresholdCounters.forget(ip)
	e.enum.forget(ip)
	e.mu.RLock()
	st := e.behavior
	e.mu.RUnlock()
	if st != nil {
		st.Forget(ip)
	}
}

// note est la part de la note d'une IP qui vient des signaux de comportement.
type note struct {
	counted    []router.BanSignal // signaux en `block` : comptent dans la note qui bannit
	countedPts float64
	shadowPts  float64 // ce que la note compterait si tous les signaux actifs étaient en `block`
}

// behaviorNote évalue les signaux de comportement de l'IP selon leurs modes. Un signal en `off` est ignoré ; un signal dont
// la référence est trop jeune ne compte jamais.
func (e *Engine) behaviorNote(ip string, cfg Config) note {
	var n note
	e.mu.RLock()
	st := e.behavior
	e.mu.RUnlock()
	if st == nil || cfg.Behavior.off() {
		return n
	}
	for _, sg := range st.Signals(ip) {
		mode := cfg.Behavior.modeOf(sg.Name)
		if mode == BehaviorOff {
			continue
		}
		n.shadowPts += float64(sg.Score)
		if mode == BehaviorBlock && !sg.Cold {
			n.countedPts += float64(sg.Score)
			n.counted = append(n.counted, router.BanSignal{Name: sg.Name, Points: float64(sg.Score)})
		}
	}
	return n
}

// trustBonus : points ajoutés au seuil de ban d'une IP à longue histoire propre.
// shadow journalise et compte le ban que la note aurait provoqué sans le mode `detect`.
func (e *Engine) shadow(ip string, acc, behaviorPts, threshold float64, why string) {
	if !e.sim {
		threatShadowBansTotal.Inc()
	}
	if ok, _ := e.sigLog.Allow("shadow|" + ip); ok {
		e.log.Info("ephor: note fantôme au-dessus du seuil ("+why+")", "ip", ip, "score", acc, "comportement", behaviorPts, "seuil", threshold)
	}
}

func (e *Engine) trustBonus(ip string, cfg Config) float64 {
	e.mu.RLock()
	st := e.behavior
	e.mu.RUnlock()
	if st == nil || cfg.Behavior.NoTrust || cfg.Behavior.off() {
		return 0
	}
	return float64(st.TrustBonus(ip))
}

// decideNote compare la note commune de l'IP au seuil de ban. La note est le score cumulé d'Ephor (listes, débit, erreurs) plus
// les signaux de comportement en `block` ; le seuil s'élève du bonus de confiance de l'IP. En `detect`, la note fantôme (tous
// les signaux actifs) est comparée au même seuil : le ban qu'elle aurait posé est journalisé et compté, rien de plus.
// Retourne le ban à poser (nil s'il n'y en a pas). dry : le moteur est en mode `detect`, rien n'est posé.
func (e *Engine) decideNote(ip string, acc float64, immediate, dry bool, cfg Config) []router.BanSignal {
	bn := e.behaviorNote(ip, cfg)
	// La confiance ne fait que relever le seuil : sous le seuil de base, même tous signaux comptés, rien à décider.
	if !immediate && acc+bn.shadowPts < cfg.IPScore.BanThreshold {
		return nil
	}
	threshold := cfg.IPScore.BanThreshold + e.trustBonus(ip, cfg)
	if !immediate && acc+bn.countedPts < threshold {
		if bn.shadowPts > bn.countedPts && acc+bn.shadowPts >= threshold {
			e.shadow(ip, acc, bn.shadowPts, threshold, "signaux en detect")
		}
		return nil
	}
	if dry {
		e.shadow(ip, acc, bn.countedPts, threshold, "mode detect")
		return nil
	}
	why := e.counters.scoreBreakdown(ip)
	why = append(why, bn.counted...)
	sort.SliceStable(why, func(i, j int) bool { return why[i].Points > why[j].Points })
	if len(why) == 0 {
		why = []router.BanSignal{{Name: "score", Points: acc}}
	}
	return why
}
