// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"net/http"
	"strings"
)

// Modes des leurres.
const (
	DecoyOff    = "off"    // aucun leurre (défaut)
	DecoyDetect = "detect" // un accès est compté et journalisé, sans effet sur la note
	DecoyBlock  = "block"  // un accès verse le signal `decoy` à la note commune de l'IP
)

const maxDecoyPaths = 200

// defaultDecoys : des chemins qu'aucune application ne sert à un visiteur ordinaire (dépôts, secrets et sauvegardes oubliés au pied
// d'un site). Une entrée qui finit par « / » est un préfixe ; les autres sont exactes. La comparaison ignore la casse.
var defaultDecoys = []string{
	"/.git/", "/.svn/", "/.hg/", "/.aws/", "/.ssh/", "/.ds_store",
	"/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/backup.zip", "/site-backup.zip",
	"/wp-config.php.bak", "/wp-config.php~", "/.env.bak", "/.env.old",
}

// DecoyConfig règle les leurres (ADR 0020, étape 2.a) : des chemins que l'application n'utilise jamais. Quiconque les demande est
// presque sûrement un scanner, avec très peu de risque de se tromper.
//
// Un leurre ne compte jamais sur un chemin que le trafic légitime d'un proxy utilise : un chemin du profil de surface appris, ou
// une location déclarée sur la route. Il naît en `detect`. Désactivé par défaut.
type DecoyConfig struct {
	// Mode : off (défaut) | detect | block.
	Mode string `json:"mode,omitempty"`
	// Paths : chemins en plus du jeu par défaut. Un chemin qui finit par « / » est un préfixe, les autres sont exacts.
	Paths []string `json:"paths,omitempty"`
	// NoDefaults retire le jeu par défaut : seuls Paths servent de leurres.
	NoDefaults bool `json:"no_defaults,omitempty"`
}

func (c DecoyConfig) mode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case DecoyDetect:
		return DecoyDetect
	case DecoyBlock:
		return DecoyBlock
	}
	return DecoyOff
}

// Active : les leurres sont en `detect` ou en `block`.
func (c DecoyConfig) Active() bool { return c.mode() != DecoyOff }

// ValidateDecoys refuse un réglage de leurres mal formé.
func (c Config) ValidateDecoys() error {
	switch strings.ToLower(strings.TrimSpace(c.Decoys.Mode)) {
	case "", DecoyOff, DecoyDetect, DecoyBlock:
	default:
		return fmt.Errorf("decoys.mode : %q invalide (attendu : off | detect | block)", c.Decoys.Mode)
	}
	if len(c.Decoys.Paths) > maxDecoyPaths {
		return fmt.Errorf("decoys.paths : %d chemins, au plus %d", len(c.Decoys.Paths), maxDecoyPaths)
	}
	for _, p := range c.Decoys.Paths {
		if !strings.HasPrefix(p, "/") || len(p) < 2 {
			return fmt.Errorf("decoys.paths : %q doit commencer par / et en dire plus (« / » seul piégerait tout)", p)
		}
	}
	return nil
}

type decoySet struct {
	exact    map[string]struct{}
	prefixes []string
}

func buildDecoys(c DecoyConfig) *decoySet {
	if !c.Active() {
		return nil
	}
	d := &decoySet{exact: map[string]struct{}{}}
	add := func(p string) {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			return
		}
		if strings.HasSuffix(p, "/") {
			d.prefixes = append(d.prefixes, p)
			return
		}
		d.exact[p] = struct{}{}
	}
	if !c.NoDefaults {
		for _, p := range defaultDecoys {
			add(p)
		}
	}
	for _, p := range c.Paths {
		add(p)
	}
	return d
}

func (d *decoySet) match(path string) bool {
	if d == nil {
		return false
	}
	p := strings.ToLower(path)
	if _, ok := d.exact[strings.TrimSuffix(p, "/")]; ok {
		return true
	}
	if _, ok := d.exact[p]; ok {
		return true
	}
	for _, pre := range d.prefixes {
		if strings.HasPrefix(p, pre) || p == strings.TrimSuffix(pre, "/") {
			return true
		}
	}
	return false
}

// SetDecoyGuard fournit le garde-fou des leurres : il dit si le trafic légitime de la route qui sert la requête utilise ce chemin
// (profil de surface appris, location déclarée). Sans lui, aucun chemin n'est protégé.
func (e *Engine) SetDecoyGuard(fn func(r *http.Request) bool) {
	e.mu.Lock()
	e.decoyGuard = fn
	e.mu.Unlock()
}

// decoySignal dit si la requête touche un leurre qui doit verser le signal `decoy` à la note. En `detect`, l'accès est compté et
// journalisé, jamais versé. Un chemin que l'application sert est écarté et compté (result="skipped").
func (e *Engine) decoySignal(cfg Config, ds *decoySet, r *http.Request, ip string) bool {
	if !ds.match(r.URL.Path) {
		return false
	}
	e.mu.RLock()
	guard := e.decoyGuard
	e.mu.RUnlock()
	if guard != nil && guard(r) {
		e.inc(threatDecoyTotal, "skipped")
		return false
	}
	if cfg.Decoys.mode() == DecoyDetect {
		e.inc(threatDecoyTotal, "shadow")
		if ok, _ := e.sigLog.Allow("decoy|" + ip); ok {
			e.log.Info("ephor: leurre touché (mode detect)", "ip", ip, "chemin", clipValue(r.URL.Path))
		}
		return false
	}
	e.inc(threatDecoyTotal, "hit")
	return true
}
