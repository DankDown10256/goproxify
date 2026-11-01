// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/seasonal"
)

// Modes de la référence saisonnière.
const (
	SeasonalOff    = "off"    // rien n'est appris ni mesuré (défaut)
	SeasonalDetect = "detect" // le trafic de chaque route est appris et les écarts sont signalés, sans autre effet
	SeasonalBlock  = "block"  // en plus, une attaque probable durcit la route : défi et plafond pour les IP sans historique
)

// SeasonalConfig règle la référence saisonnière du trafic (ADR 0020, étape 3) : le débit, les IP distinctes, la part d'erreurs et la
// concentration sur un chemin de chaque route, appris par créneau (jour de la semaine × heure, UTC). Un écart de volume donne un
// avertissement ; accompagné d'un écart de nature, une attaque probable. Désactivée par défaut, elle naît en `detect`.
type SeasonalConfig struct {
	// Mode : off (défaut) | detect | block. En block, une attaque probable durcit la route (défi à preuve de travail et plafond pour les IP sans historique).
	Mode string `json:"mode,omitempty"`
	// FloorRPS : débit (req/s) sous lequel aucun écart de volume ne compte, quelle que soit la référence (défaut 20).
	FloorRPS float64 `json:"floor_rps,omitempty"`
	// FastFactor : multiple de la moyenne du créneau qui déclenche la fenêtre rapide, dix secondes (défaut 10).
	FastFactor float64 `json:"fast_factor,omitempty"`
	// SlowSigmas : écarts-types au-dessus de la moyenne pour la fenêtre lente, une minute (défaut 4).
	SlowSigmas float64 `json:"slow_sigmas,omitempty"`
	// MinHours : heures d'observation qu'un créneau doit avoir vues avant d'être cru (défaut 2). Avant, il reste froid et ne compte jamais.
	MinHours float64 `json:"min_hours,omitempty"`
	// CapFactor : en `block`, multiple de la moyenne du créneau qui plafonne les IP sans historique pendant une attaque probable (défaut 3).
	CapFactor float64 `json:"cap_factor,omitempty"`
}

func (c SeasonalConfig) mode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case SeasonalDetect:
		return SeasonalDetect
	case SeasonalBlock:
		return SeasonalBlock
	}
	return SeasonalOff
}

// Active : la référence saisonnière est en `detect` ou en `block`.
func (c SeasonalConfig) Active() bool { return c.mode() != SeasonalOff }

func (c SeasonalConfig) params() seasonal.Params {
	return seasonal.Params{
		FloorRPS:   c.FloorRPS,
		FastFactor: c.FastFactor,
		SlowSigmas: c.SlowSigmas,
		// Une heure de créneau compte 360 tranches de dix secondes.
		MinSamples: int(c.MinHours * 3600 / seasonal.BucketSeconds),
		Harden:     c.mode() == SeasonalBlock,
		CapFactor:  c.CapFactor,
	}
}

// ValidateSeasonal refuse un réglage de la référence saisonnière qui ne pourrait jamais servir.
func (c Config) ValidateSeasonal() error {
	s := c.Seasonal
	switch strings.ToLower(strings.TrimSpace(s.Mode)) {
	case "", SeasonalOff, SeasonalDetect, SeasonalBlock:
	default:
		return fmt.Errorf("seasonal.mode : %q invalide (attendu : off | detect | block)", s.Mode)
	}
	if s.FloorRPS < 0 || s.FloorRPS > 1e6 {
		return fmt.Errorf("seasonal.floor_rps : %v hors de 0 à 1000000", s.FloorRPS)
	}
	if s.FastFactor != 0 && (s.FastFactor < 2 || s.FastFactor > 1000) {
		return fmt.Errorf("seasonal.fast_factor : %v hors de 2 à 1000", s.FastFactor)
	}
	if s.SlowSigmas != 0 && (s.SlowSigmas < 1 || s.SlowSigmas > 20) {
		return fmt.Errorf("seasonal.slow_sigmas : %v hors de 1 à 20", s.SlowSigmas)
	}
	if s.MinHours != 0 && (s.MinHours < 0.1 || s.MinHours > 168) {
		return fmt.Errorf("seasonal.min_hours : %v hors de 0,1 à 168", s.MinHours)
	}
	if s.CapFactor != 0 && (s.CapFactor < 1 || s.CapFactor > 100) {
		return fmt.Errorf("seasonal.cap_factor : %v hors de 1 à 100", s.CapFactor)
	}
	if strings.ToLower(strings.TrimSpace(s.Mode)) == SeasonalBlock && !c.Challenge.Active() {
		return fmt.Errorf("seasonal.mode block : demande challenge.mode detect ou block (le profil durci sert le défi à preuve de travail)")
	}
	return nil
}

func (e *Engine) seasonalActive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Enabled && e.cfg.Seasonal.Active()
}

// runSeasonal clôt une tranche de dix secondes par tick tant que la référence est active.
func (e *Engine) runSeasonal(ctx context.Context) {
	defer close(e.seasonalDone)
	tk := time.NewTicker(seasonal.BucketSeconds * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			e.SeasonalTick(e.counters.now())
		}
	}
}

func (e *Engine) onSeasonalEvent(ev seasonal.Event) {
	e.seasonalDirty.Store(true)
	e.inc2(threatSeasonalTotal, ev.Kind, ev.Level)
	switch ev.Kind {
	case "end":
		e.log.Info("ephor: écart de trafic terminé", "route", ev.Route, "niveau", ev.Level, "duree", ev.Duration.Round(time.Second), "pic_rps", ev.Peak)
	default:
		e.log.Warn("ephor: trafic hors de sa référence saisonnière", "route", ev.Route, "evenement", ev.Kind, "niveau", ev.Level,
			"rps", ev.RPS, "attendu_rps", ev.Expected, "natures", ev.Natures)
	}
}

// SeasonalStatus décrit la référence de chaque route (pour l'affichage de l'Admin).
func (e *Engine) SeasonalStatus() []seasonal.RouteStatus { return e.seasonal.Status() }

// SeasonalEvents retourne les derniers changements d'état des alertes, du plus récent au plus ancien.
func (e *Engine) SeasonalEvents() []seasonal.Event { return e.seasonal.Events() }

// SeasonalActive retourne les alertes de trafic en cours.
func (e *Engine) SeasonalActive() []seasonal.Event { return e.seasonal.Active() }

// SeasonalMode : le mode appliqué (off | detect).
func (e *Engine) SeasonalMode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.cfg.Enabled {
		return SeasonalOff
	}
	return e.cfg.Seasonal.mode()
}

// seasonalResend : tant qu'une alerte dure, la passerelle redit toutes les alertes en cours à cette cadence, pour qu'une coupure du
// lien avec l'Admin ne fasse pas manquer une alerte.
const seasonalResend = time.Minute

// SetSeasonalNotify branche l'envoi des alertes de trafic en cours à l'Admin. fn reçoit TOUTES les alertes en cours, liste vide
// comprise (elles sont finies).
func (e *Engine) SetSeasonalNotify(fn func(active []seasonal.Event)) {
	e.mu.Lock()
	e.seasonalNotify = fn
	e.mu.Unlock()
}

func (e *Engine) notifySeasonal() {
	e.mu.RLock()
	fn := e.seasonalNotify
	e.mu.RUnlock()
	if fn == nil {
		return
	}
	now := e.counters.now()
	active := e.seasonal.Active()
	if !e.seasonalDirty.Swap(false) && (len(active) == 0 || now.Sub(e.seasonalSent) < seasonalResend) {
		return
	}
	e.seasonalSent = now
	fn(active)
}

// Hardening retourne le profil durci de la route qui sert la requête quand il s'applique à cette IP : la route est en attaque
// probable (mode `block`) et l'IP n'a pas d'historique propre. Les habitués, la liste blanche d'Ephor et les IP de confiance
// passent comme d'ordinaire. nil : rien à imposer. Chemin des requêtes : une lecture sans verrou tant qu'aucune route n'est durcie.
func (e *Engine) Hardening(host, ip string) *seasonal.Hard {
	h := e.seasonal.Hardened(host)
	if h == nil {
		return nil
	}
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	e.mu.RUnlock()
	if !cfg.Enabled || cfg.Seasonal.mode() != SeasonalBlock || wl.allowedIP(ip) || e.trustBonus(ip, cfg) > 0 {
		return nil
	}
	return h
}

// CountHarden compte une mesure du profil durci : challenged (page de défi servie) ou shed (plafond atteint, 503).
func (e *Engine) CountHarden(result string) { e.inc(threatSeasonalHardenTotal, result) }

// RecordHardened verse au suivi une requête que le profil durci a écartée avant la route : sans elle, le volume de l'attaque
// disparaîtrait des mesures, l'alerte se croirait finie et la route serait relâchée en pleine attaque.
func (e *Engine) RecordHardened(host, ip string, r *http.Request, status int) {
	e.seasonal.Record(host, ip, status, r.URL.Path)
}

// SeasonalTick clôt une tranche de dix secondes et prévient l'Admin des alertes. Appelé par la boucle du moteur ; exporté pour que
// les tests de la passerelle jouent le temps.
func (e *Engine) SeasonalTick(now time.Time) {
	if !e.seasonalActive() {
		return
	}
	e.seasonal.Tick(now)
	e.notifySeasonal()
}
