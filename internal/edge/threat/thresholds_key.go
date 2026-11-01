// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// Clés de comptage d'un Seuil (ADR 0020, étape 4.a). Par défaut un Seuil compte par IP. Une attaque par bourrage d'identifiants
// change d'IP mais vise les mêmes comptes, ou garde la même pile TLS, ou reste dans le même opérateur : le Seuil peut alors compter
// par compte, par empreinte JA4 ou par ASN.
const (
	ThresholdByIP      = "ip"
	ThresholdByAccount = "account"
	ThresholdByJA4     = "ja4"
	ThresholdByASN     = "asn"

	// ThresholdProtect : l'action des Seuils à clé autre que l'IP. Aucun ban : une clé n'est pas une adresse, et bannir un compte
	// ou une empreinte permettrait à un attaquant de punir sa victime. Le dépassement place la clé sous protection.
	ThresholdProtect = "protect"
)

const (
	defaultProtectFor  = 15 * time.Minute
	minProtectFor      = time.Minute
	maxProtectFor      = 24 * time.Hour
	defaultProtectRate = 3 // tentatives par minute admises pour l'ensemble des IP sans historique
	maxProtectRate     = 600
	maxLoginRoutes     = 20
	loginBodyMax       = 8 << 10
	accountMaxLen      = 256
	protectedCap       = 4096
)

// LoginRoute déclare une route de connexion dont le corps est lu pour en tirer l'identifiant du compte visé. La lecture est limitée à
// ces routes, aux requêtes POST et à loginBodyMax octets ; l'identifiant n'est jamais conservé : seule son empreinte HMAC, avec une
// clé propre à la passerelle et à son processus, sert de clé de comptage.
type LoginRoute struct {
	// Host : nom de la route ; vide = toutes.
	Host string `json:"host,omitempty"`
	// Path : préfixe du chemin de connexion (« /login »).
	Path string `json:"path"`
	// Field : nom du champ qui porte l'identifiant, dans un corps JSON (clé de premier niveau) ou un formulaire.
	Field string `json:"field"`
}

func (c Config) validateKeyedThreshold(what string, r ThresholdRule) error {
	switch strings.ToLower(strings.TrimSpace(r.By)) {
	case "", ThresholdByIP:
		if r.ProtectFor.Duration != 0 || r.Limit != 0 {
			return fmt.Errorf("%s : protect_for et limit demandent by account, ja4 ou asn", what)
		}
		if strings.EqualFold(strings.TrimSpace(r.Action), ThresholdProtect) {
			return fmt.Errorf("%s.action : protect demande by account, ja4 ou asn (un Seuil par IP bannit ou verse des points)", what)
		}
		return nil
	case ThresholdByAccount, ThresholdByJA4, ThresholdByASN:
	default:
		return fmt.Errorf("%s.by : %q invalide (attendu : ip | account | ja4 | asn)", what, r.By)
	}
	if a := strings.ToLower(strings.TrimSpace(r.Action)); a != "" && a != ThresholdProtect {
		return fmt.Errorf("%s.action : %q impossible avec by %s (attendu : protect) — bannir une clé ne désigne aucune adresse", what, r.Action, r.By)
	}
	if d := r.ProtectFor.Duration; d != 0 && (d < minProtectFor || d > maxProtectFor) {
		return fmt.Errorf("%s.protect_for : %s hors de %s – %s", what, d, minProtectFor, maxProtectFor)
	}
	if r.Limit < 0 || r.Limit > maxProtectRate {
		return fmt.Errorf("%s.limit : %d hors de 1 – %d", what, r.Limit, maxProtectRate)
	}
	if strings.EqualFold(strings.TrimSpace(r.By), ThresholdByAccount) {
		if len(c.Thresholds.Logins) == 0 {
			return fmt.Errorf("%s : by account demande au moins une route de connexion (thresholds.logins)", what)
		}
		if len(r.Methods) > 0 && !containsFold(r.Methods, http.MethodPost) {
			return fmt.Errorf("%s.methods : by account ne lit que les POST de connexion", what)
		}
	}
	return nil
}

func containsFold(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

// ValidateLogins refuse une déclaration de routes de connexion mal formée.
func (c Config) ValidateLogins() error {
	l := c.Thresholds.Logins
	if len(l) > maxLoginRoutes {
		return fmt.Errorf("thresholds.logins : %d routes, au plus %d", len(l), maxLoginRoutes)
	}
	for i, lr := range l {
		what := fmt.Sprintf("thresholds.logins[%d]", i)
		if !strings.HasPrefix(lr.Path, "/") {
			return fmt.Errorf("%s.path : %q doit commencer par /", what, lr.Path)
		}
		if strings.TrimSpace(lr.Field) == "" || len(lr.Field) > 64 {
			return fmt.Errorf("%s.field : nom de champ attendu (64 caractères au plus)", what)
		}
	}
	return nil
}

// byKey normalise la clé d'un Seuil.
func (r ThresholdRule) byKey() string {
	switch strings.ToLower(strings.TrimSpace(r.By)) {
	case ThresholdByAccount:
		return ThresholdByAccount
	case ThresholdByJA4:
		return ThresholdByJA4
	case ThresholdByASN:
		return ThresholdByASN
	}
	return ThresholdByIP
}

func (r ThresholdRule) protectFor() time.Duration {
	if r.ProtectFor.Duration <= 0 {
		return defaultProtectFor
	}
	return r.ProtectFor.Duration
}

func (r ThresholdRule) limit() int {
	if r.Limit <= 0 {
		return defaultProtectRate
	}
	return r.Limit
}

// matchesRequest : la part du filtre qu'une requête décide avant la réponse (méthode, route, chemin).
func (ct *compiledThreshold) matchesRequest(r *http.Request, route string) bool {
	if len(ct.methods) > 0 && !ct.methods[r.Method] {
		return false
	}
	if len(ct.hosts) > 0 && !ct.hosts[strings.ToLower(route)] {
		return false
	}
	if len(ct.rule.Paths) > 0 {
		for _, p := range ct.rule.Paths {
			if strings.HasPrefix(r.URL.Path, p) {
				return true
			}
		}
		return false
	}
	return true
}

// ── Compte visé ──────────────────────────────────────────────────────────────

func newAccountKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

// accountFingerprint est l'empreinte HMAC d'un identifiant normalisé (minuscules, sans espaces de bord).
func (e *Engine) accountFingerprint(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" || len(id) > accountMaxLen {
		return ""
	}
	m := hmac.New(sha256.New, e.accountKey)
	m.Write([]byte(id)) //nolint:errcheck
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func (lr LoginRoute) matches(r *http.Request, route string) bool {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, lr.Path) {
		return false
	}
	return lr.Host == "" || strings.EqualFold(lr.Host, route)
}

// accountOf lit l'identifiant visé par une connexion et le rend sous forme d'empreinte. Le corps est lu une fois, au plus
// loginBodyMax octets, puis remis à la requête pour le backend.
func (e *Engine) accountOf(r *http.Request, route string, logins []LoginRoute, obs *behavior.Observation) string {
	if fp := obs.Account(); fp != "" {
		return fp
	}
	var lr *LoginRoute
	for i := range logins {
		if logins[i].matches(r, route) {
			lr = &logins[i]
			break
		}
	}
	if lr == nil || r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(r.Body, loginBodyMax))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	var id string
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(ct, "application/json"):
		var doc map[string]json.RawMessage
		if json.Unmarshal(buf, &doc) == nil {
			if raw, ok := doc[lr.Field]; ok {
				var s string
				if json.Unmarshal(raw, &s) == nil {
					id = s
				} else if n, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
					id = strconv.FormatInt(n, 10)
				}
			}
		}
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if v, err := url.ParseQuery(string(buf)); err == nil {
			id = v.Get(lr.Field)
		}
	}
	fp := e.accountFingerprint(id)
	obs.NoteAccount(fp)
	return fp
}

// keyOf donne la clé de comptage d'une requête pour un Seuil à clé ; vide quand la requête n'en a pas.
func (e *Engine) keyOf(ct *compiledThreshold, r *http.Request, route, ip string, logins []LoginRoute, obs *behavior.Observation) string {
	switch ct.by {
	case ThresholdByAccount:
		if fp := e.accountOf(r, route, logins, obs); fp != "" {
			return "acct:" + fp
		}
	case ThresholdByJA4:
		if fp := tlsfp.FromContext(r.Context()); fp != nil && fp.JA4 != "" {
			// Une pile de navigateur connue est partagée par des millions de visiteurs : elle ne désigne jamais un client.
			e.mu.RLock()
			st := e.behavior
			e.mu.RUnlock()
			if st != nil && st.IsBrowserJA4(fp.JA4) {
				return ""
			}
			return "ja4:" + fp.JA4
		}
	case ThresholdByASN:
		e.mu.RLock()
		st := e.behavior
		e.mu.RUnlock()
		if st != nil {
			if asn := st.ASNOf(ip); asn != 0 {
				return "asn:" + strconv.FormatUint(uint64(asn), 10)
			}
		}
	}
	return ""
}

// ── Clés sous protection ─────────────────────────────────────────────────────

// attemptBucket admet limit tentatives par minute pour l'ensemble des IP sans historique d'une clé protégée.
type attemptBucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64 // jetons par seconde
	last   time.Time
}

func newAttemptBucket(limit int, now time.Time) *attemptBucket {
	return &attemptBucket{tokens: float64(limit), max: float64(limit), rate: float64(limit) / 60, last: now}
}

func (b *attemptBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens += d * b.rate
		if b.tokens > b.max {
			b.tokens = b.max
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

type protectedKey struct {
	until  time.Time
	bucket *attemptBucket
}

// protectedStore tient les clés sous protection : en mémoire, bornée, jamais écrite sur disque (elle ne porte que des empreintes et
// des durées de quelques minutes).
type protectedStore struct {
	mu  sync.Mutex
	m   map[string]*protectedKey
	now func() time.Time
}

func newProtectedStore(now func() time.Time) *protectedStore {
	return &protectedStore{m: map[string]*protectedKey{}, now: now}
}

func (p *protectedStore) mark(key string, dur time.Duration, limit int) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.m) >= protectedCap {
		for k, v := range p.m {
			if !v.until.After(now) {
				delete(p.m, k)
			}
		}
		for k := range p.m {
			if len(p.m) < protectedCap {
				break
			}
			delete(p.m, k)
		}
	}
	p.m[key] = &protectedKey{until: now.Add(dur), bucket: newAttemptBucket(limit, now)}
}

// get rend la protection en cours d'une clé, nil si elle n'est pas protégée ou si la protection est échue.
func (p *protectedStore) get(key string) *protectedKey {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	pk := p.m[key]
	if pk == nil {
		return nil
	}
	if !pk.until.After(now) {
		delete(p.m, key)
		return nil
	}
	return pk
}

func (p *protectedStore) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}

// KeyGuard est la protection qui s'applique à une requête : sa clé est sous protection et l'IP n'a pas d'historique propre.
type KeyGuard struct {
	pk   *protectedKey
	Rule string
	By   string
}

// Allow prélève une tentative sur le plafond de la clé ; faux quand il est atteint.
func (g *KeyGuard) Allow(now time.Time) bool { return g.pk.bucket.allow(now) }

// KeyProtection lit la requête avant la route (le corps d'une connexion, au plus 8 Ko, y compris en `detect` : les compteurs en ont
// besoin) et retourne la protection qui la concerne, nil sinon. Un Seuil à clé ne bannit jamais : l'IP sans historique propre dont la
// requête vise une clé protégée est soumise au défi (navigation) ou à la limitation de tentatives de la clé.
// Les habitués, la liste blanche d'Ephor et les IP de confiance passent.
func (e *Engine) KeyProtection(r *http.Request, route, ip string) *KeyGuard {
	e.mu.RLock()
	rules := e.keyRules
	logins := e.logins
	enabled := e.cfg.Enabled
	e.mu.RUnlock()
	if !enabled || len(rules) == 0 {
		return nil
	}
	obs := behavior.ObservationFrom(r.Context())
	var guard *KeyGuard
	for _, ct := range rules {
		if !ct.matchesRequest(r, route) {
			continue
		}
		key := e.keyOf(ct, r, route, ip, logins, obs)
		if key == "" || ct.mode != ThresholdBlock || guard != nil {
			continue
		}
		pk := e.protected.get(ct.rule.Name + "|" + key)
		if pk == nil {
			continue
		}
		e.mu.RLock()
		cfg, wl := e.cfg, e.wl
		e.mu.RUnlock()
		if wl.allowedIP(ip) || e.trustBonus(ip, cfg) > 0 {
			continue
		}
		guard = &KeyGuard{pk: pk, Rule: ct.rule.Name, By: ct.by}
	}
	return guard
}

// CountKey compte une issue d'un Seuil à clé : challenged (défi servi), limited (plafond de la clé atteint).
func (e *Engine) CountKey(result string) { e.inc(threatThresholdTotal, result) }

// observeKeyed évalue les Seuils à clé sur une réponse rendue.
func (e *Engine) observeKeyed(cfg Config, rules []*compiledThreshold, logins []LoginRoute, r *http.Request, ip, route string, status int, obs *behavior.Observation) {
	for _, ct := range rules {
		if !ct.matches(r, route, status, obs) {
			continue
		}
		key := e.keyOf(ct, r, route, ip, logins, obs)
		if key == "" {
			continue
		}
		n := e.keyCounters.recordKey(ct.rule.Name, ct.rule.Window.Duration, key)
		if n < ct.rule.Count {
			continue
		}
		e.keyCounters.resetKey(ct.rule.Name, key)
		e.keyTriggered(ct, key, n)
	}
}

func (e *Engine) keyTriggered(ct *compiledThreshold, key string, n int) {
	short := key
	if i := strings.IndexByte(key, ':'); i >= 0 && len(key) > i+9 {
		short = key[:i+1] + key[i+1:i+9]
	}
	if ct.mode == ThresholdDetect {
		e.inc(threatThresholdTotal, "key_shadow")
		if ok, _ := e.sigLog.Allow("seuil|" + ct.rule.Name + "|" + key); ok {
			e.log.Info("ephor: seuil à clé dépassé (mode detect)", "seuil", ct.rule.Name, "cle", short, "evenements", n, "fenetre", ct.rule.Window.Duration.String())
		}
		return
	}
	e.protected.mark(ct.rule.Name+"|"+key, ct.rule.protectFor(), ct.rule.limit())
	e.inc(threatThresholdTotal, "protect")
	e.log.Warn("ephor: clé placée sous protection", "seuil", ct.rule.Name, "cle", short, "evenements", n, "duree", ct.rule.protectFor().String(), "tentatives_par_minute", ct.rule.limit())
}

// ProtectedKeys retourne le nombre de clés sous protection.
func (e *Engine) ProtectedKeys() int { return e.protected.len() }

func (s *thresholdStore) recordKey(rule string, window time.Duration, key string) int {
	now := s.now()
	k := rule + "|" + key
	sh := s.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.m[k]
	if b == nil || b.window != window {
		if len(sh.m) >= thresholdShardCap {
			evictOldest(sh.m)
		}
		b = &bucketWindow{window: window}
		sh.m[k] = b
	}
	return b.add(now)
}

func (s *thresholdStore) resetKey(rule, key string) {
	k := rule + "|" + key
	sh := s.shard(k)
	sh.mu.Lock()
	delete(sh.m, k)
	sh.mu.Unlock()
}

func keyedThresholds(all []*compiledThreshold) []*compiledThreshold {
	var out []*compiledThreshold
	for _, ct := range all {
		if ct.by != ThresholdByIP {
			out = append(out, ct)
		}
	}
	return out
}
