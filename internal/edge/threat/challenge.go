// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Modes du défi gradué.
const (
	ChallengeOff    = "off"    // aucun défi (défaut)
	ChallengeDetect = "detect" // calculé et compté (gpx_threat_challenge_total{result="shadow"}), jamais servi
	ChallengeBlock  = "block"  // servi aux IP dont la note a franchi le seuil
)

// ChallengeConfig règle le défi à preuve de travail que la passerelle impose à une IP dont la note monte, entre « laisser passer »
// et « bannir » (ADR 0020, étape 1.b). Un humain ne le remarque presque pas ; un robot qui fait des milliers de requêtes paie cher,
// et une IP partagée (NAT, CGNAT) n'est pas bannie à tort.
//
// Il s'appuie sur le score cumulé : ip_score.enabled est requis. Il naît en `detect`, comme tout nouveau signal.
// Seule une navigation (GET ou HEAD qui demande du HTML) peut recevoir la page de défi ; les autres requêtes (API, images, POST)
// et les chemins exemptés restent sur la voie du ban. Une route qui a son propre défi n'est pas défiée deux fois.
type ChallengeConfig struct {
	// Mode : off (défaut) | detect | block.
	Mode string `json:"mode,omitempty"`
	// Threshold : note commune à partir de laquelle l'IP reçoit le défi, sous le seuil de ban (ip_score.ban_threshold).
	// 0 : la moitié du seuil de ban. Le bonus de confiance des IP à longue histoire propre relève ce seuil, comme celui du ban.
	Threshold float64 `json:"threshold,omitempty"`
	// Difficulty : bits de tête à zéro de la preuve (1 à 24, défaut 16 : environ une seconde sur un navigateur).
	Difficulty int `json:"difficulty,omitempty"`
	// TTL : durée de validité de la preuve (défaut 24 h).
	TTL Duration `json:"ttl,omitempty"`
	// ExemptPaths : préfixes de chemin jamais défiés (APIs, webhooks). /.well-known/ l'est toujours.
	ExemptPaths []string `json:"exempt_paths,omitempty"`
	// Secret : signature de la preuve, à partager entre les membres d'un groupe HA (sinon chacun a le sien et re-défie après un
	// redémarrage ou d'un membre à l'autre).
	Secret string `json:"secret,omitempty"`
}

func (c ChallengeConfig) mode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case ChallengeDetect:
		return ChallengeDetect
	case ChallengeBlock:
		return ChallengeBlock
	}
	return ChallengeOff
}

// Active : le défi est en `detect` ou en `block`.
func (c ChallengeConfig) Active() bool { return c.mode() != ChallengeOff }

// ValidateChallenge refuse un réglage du défi qui ne pourrait jamais servir ou qui serait mal compris.
func (c Config) ValidateChallenge() error {
	ch := c.Challenge
	switch strings.ToLower(strings.TrimSpace(ch.Mode)) {
	case "", ChallengeOff, ChallengeDetect, ChallengeBlock:
	default:
		return fmt.Errorf("challenge.mode : %q invalide (attendu : off | detect | block)", ch.Mode)
	}
	if ch.Threshold < 0 {
		return fmt.Errorf("challenge.threshold : %v négatif", ch.Threshold)
	}
	if ch.Difficulty < 0 || ch.Difficulty > 24 {
		return fmt.Errorf("challenge.difficulty : %d hors de 1 – 24", ch.Difficulty)
	}
	if d := ch.TTL.Duration; d < 0 || (d > 0 && d < time.Minute) {
		return fmt.Errorf("challenge.ttl : %s inférieur à une minute", d)
	}
	for _, p := range ch.ExemptPaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("challenge.exempt_paths : %q doit commencer par /", p)
		}
	}
	if !ch.Active() {
		return nil
	}
	if !c.IPScore.Enabled {
		return fmt.Errorf("challenge : demande ip_score.enabled (le défi s'appuie sur le score cumulé)")
	}
	ban := c.IPScore.BanThreshold
	if ban <= 0 {
		ban = defaultScoreBanThreshold
	}
	if ch.Threshold >= ban {
		return fmt.Errorf("challenge.threshold : %v doit rester sous le seuil de ban (%v), sinon l'IP est bannie avant d'être défiée", ch.Threshold, ban)
	}
	return nil
}

// Challenge retourne le réglage du défi gradué (défauts appliqués).
func (e *Engine) Challenge() ChallengeConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Challenge
}

// ChallengeDue dit si l'IP doit recevoir le défi pour cette requête : sa note commune (score cumulé d'Ephor plus signaux de
// comportement) a franchi le seuil du défi, sans avoir encore atteint celui du ban. En `detect`, le défi qui aurait été imposé est
// compté et tracé, et la réponse est toujours non.
func (e *Engine) ChallengeDue(r *http.Request, ip string) bool {
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	e.mu.RUnlock()
	mode := cfg.Challenge.mode()
	if !cfg.Enabled || mode == ChallengeOff || !cfg.IPScore.Enabled || wl.allowedIP(ip) || wl.allowedUA(r.Header.Get("User-Agent")) || wl.allowedPath(r.URL.Path) {
		return false
	}
	acc := e.counters.currentScore(ip)
	bn := e.behaviorNote(ip, cfg)
	threshold := cfg.Challenge.Threshold + e.trustBonus(ip, cfg)
	if mode == ChallengeBlock {
		return acc+bn.countedPts >= threshold
	}
	if acc+bn.shadowPts >= threshold {
		e.CountChallenge("shadow")
		if ok, _ := e.sigLog.Allow("challenge|" + ip); ok {
			e.log.Info("ephor: défi qui aurait été imposé (mode detect)", "ip", ip, "score", acc, "comportement", bn.shadowPts, "seuil", threshold)
		}
	}
	return false
}

// CountChallenge compte une issue du défi : served (page servie), shadow (mode detect), solved ou failed (solution reçue).
func (e *Engine) CountChallenge(result string) {
	e.inc(threatChallengeTotal, result)
}
