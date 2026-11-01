// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package domainwatch surveille les domaines déclarés dans l'Admin, indépendamment du trafic (ADR 0020, étape 4.d) : un certificat émis
// hors de GoProxify (journaux de transparence), des enregistrements CAA absents ou qui excluraient l'autorité de GoProxify, un nom qui
// pointe vers une cible qui n'existe plus (risque de détournement).
//
// Ces vérifications envoient des noms de domaine à des services extérieurs (un journal de transparence, un résolveur DNS) : tout est
// désactivé par défaut et chaque vérification s'active séparément. Les requêtes sont espacées.
package domainwatch

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

const (
	configKey = "domain_watch_config"
	stateKey  = "domain_watch_state"

	maxDomains          = 200
	defaultIntervalH    = 24
	minIntervalH        = 6
	maxIntervalH        = 168
	defaultCAIssuer     = "letsencrypt.org"
	defaultCTEndpoint   = "https://crt.sh"
	tooWideAuthorities  = 4
	manualRunCooldown   = 5 * time.Minute
	maxTrustedIssuers   = 20
	maxFindingsReturned = 500
)

// Statuts d'un constat.
const (
	StatusOpen     = "open"     // à traiter
	StatusResolved = "resolved" // n'est plus constaté
	StatusBaseline = "baseline" // déjà là quand la surveillance a commencé : listé, jamais alerté
	StatusOurs     = "ours"     // certificat émis par GoProxify
	StatusTrusted  = "trusted"  // émetteur toléré par l'administrateur
	StatusAccepted = "accepted" // reconnu par l'administrateur
)

// Vérifications.
const (
	CheckCT       = "ct"
	CheckCAA      = "caa"
	CheckDangling = "dangling"
)

// Config est la configuration de la surveillance. Tout est désactivé par défaut.
type Config struct {
	// Enabled : interrupteur général ; sans lui aucune vérification ne tourne.
	Enabled bool `json:"enabled"`
	// CT : consulte un journal de transparence des certificats (envoie les noms de domaine à CTEndpoint).
	CT bool `json:"ct"`
	// CAA : interroge le DNS pour les enregistrements CAA (envoie les noms au résolveur).
	CAA bool `json:"caa"`
	// Dangling : cherche un nom dont le CNAME pointe vers une cible qui n'existe plus (envoie les noms au résolveur).
	Dangling bool `json:"dangling"`
	// CTEndpoint : service qui répond à /?q=<nom>&output=json comme crt.sh (https obligatoire). Vide : crt.sh.
	CTEndpoint string `json:"ct_endpoint,omitempty"`
	// Resolver : résolveur DNS « hôte:port ». Vide : celui du système (/etc/resolv.conf).
	Resolver string `json:"resolver,omitempty"`
	// IntervalHours : cadence des vérifications, de 6 h à 7 jours (défaut 24 h).
	IntervalHours int `json:"interval_hours,omitempty"`
	// TrustedIssuers : fragments du nom de l'émetteur toléré pour un certificat qui n'est pas de GoProxify (un CDN, un autre service
	// qui émet pour vos domaines en connaissance de cause).
	TrustedIssuers []string `json:"trusted_issuers,omitempty"`
	// CAIssuer : identifiant CAA de l'autorité qu'utilise GoProxify (défaut letsencrypt.org).
	CAIssuer string `json:"ca_issuer,omitempty"`
}

func (c Config) interval() time.Duration {
	h := c.IntervalHours
	if h <= 0 {
		h = defaultIntervalH
	}
	return time.Duration(h) * time.Hour
}

func (c Config) caIssuer() string {
	if v := strings.ToLower(strings.TrimSpace(c.CAIssuer)); v != "" {
		return v
	}
	return defaultCAIssuer
}

func (c Config) ctEndpoint() string {
	if v := strings.TrimRight(strings.TrimSpace(c.CTEndpoint), "/"); v != "" {
		return v
	}
	return defaultCTEndpoint
}

// Active : au moins une vérification tourne.
func (c Config) Active() bool { return c.Enabled && (c.CT || c.CAA || c.Dangling) }

// Validate refuse un réglage qui ne pourrait pas servir. checkURL contrôle l'adresse du journal de transparence (https, pas d'adresse
// privée) ; nil la laisse passer (tests).
func (c Config) Validate(checkURL func(string) error) error {
	if c.IntervalHours != 0 && (c.IntervalHours < minIntervalH || c.IntervalHours > maxIntervalH) {
		return fmt.Errorf("interval_hours : %d hors de %d – %d", c.IntervalHours, minIntervalH, maxIntervalH)
	}
	if len(c.TrustedIssuers) > maxTrustedIssuers {
		return fmt.Errorf("trusted_issuers : %d entrées, au plus %d", len(c.TrustedIssuers), maxTrustedIssuers)
	}
	for _, t := range c.TrustedIssuers {
		if strings.TrimSpace(t) == "" || len(t) > 100 {
			return errors.New("trusted_issuers : entrée vide ou trop longue")
		}
	}
	if v := strings.TrimSpace(c.CTEndpoint); v != "" {
		if !strings.HasPrefix(strings.ToLower(v), "https://") {
			return errors.New("ct_endpoint : https obligatoire")
		}
		if checkURL != nil {
			if err := checkURL(v); err != nil {
				return fmt.Errorf("ct_endpoint : %w", err)
			}
		}
	}
	if v := strings.TrimSpace(c.Resolver); v != "" && !strings.Contains(v, ":") {
		return errors.New("resolver : « hôte:port » attendu (ex. 9.9.9.9:53)")
	}
	if v := strings.TrimSpace(c.CAIssuer); v != "" && (strings.ContainsAny(v, " \t\"") || len(v) > 100) {
		return errors.New("ca_issuer : un nom de domaine attendu (ex. letsencrypt.org)")
	}
	return nil
}

// State est l'état de la dernière exécution.
type State struct {
	LastRun    time.Time `json:"last_run,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	Domains    int       `json:"domains"`
	Running    bool      `json:"running,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// Finding est un constat de la surveillance.
type Finding struct {
	Domain    string          `json:"domain"`
	Check     string          `json:"check"`
	Key       string          `json:"key"`
	Status    string          `json:"status"`
	Severity  string          `json:"severity"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	FirstSeen time.Time       `json:"first_seen"`
	LastSeen  time.Time       `json:"last_seen"`
}

// CTEntry est une ligne d'un journal de transparence.
type CTEntry struct {
	Serial    string    `json:"serial"`
	Issuer    string    `json:"issuer"`
	Names     []string  `json:"names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	ID        int64     `json:"id,omitempty"`
}

// CTFetcher lit les certificats émis pour un nom.
type CTFetcher interface {
	Fetch(ctx context.Context, endpoint, domain string) ([]CTEntry, error)
}

// DNSClient interroge un résolveur.
type DNSClient interface {
	CAA(ctx context.Context, name string) (records []CAARecord, err error)
	// Dangling rend la cible d'un CNAME qui n'existe plus, vide sinon.
	Dangling(ctx context.Context, name string) (target string, err error)
}

// CAARecord est un enregistrement CAA.
type CAARecord struct {
	Tag, Value string
}

// Watcher fait tourner la surveillance.
type Watcher struct {
	DB    *sql.DB
	Log   *slog.Logger
	Alert func(alerting.Event)
	CT    CTFetcher
	// DNS construit le client DNS pour un résolveur donné (« » : celui du système).
	DNS func(resolver string) (DNSClient, error)
	// CheckURL contrôle l'adresse du journal de transparence.
	CheckURL func(string) error

	Now   func() time.Time
	Sleep func(time.Duration)

	mu      sync.Mutex
	running bool
	lastMan time.Time
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watcher) sleep(d time.Duration) {
	if w.Sleep != nil {
		w.Sleep(d)
		return
	}
	time.Sleep(d)
}

// Migrate crée la table des constats.
func Migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS domain_watch (
		domain     TEXT NOT NULL,
		check_name TEXT NOT NULL,
		key        TEXT NOT NULL,
		status     TEXT NOT NULL,
		severity   TEXT NOT NULL DEFAULT 'info',
		detail     TEXT NOT NULL DEFAULT '{}',
		first_seen DATETIME NOT NULL,
		last_seen  DATETIME NOT NULL,
		PRIMARY KEY (domain, check_name, key)
	)`)
	return err
}

// Config lit la configuration (désactivée si absente).
func (w *Watcher) Config() Config {
	var raw string
	var c Config
	if w.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, configKey).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	return c
}

// SetConfig valide et enregistre la configuration.
func (w *Watcher) SetConfig(c Config) error {
	if err := c.Validate(w.CheckURL); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	_, err := w.DB.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, configKey, string(b))
	return err
}

// State lit l'état de la dernière exécution.
func (w *Watcher) State() State {
	var raw string
	var s State
	if w.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, stateKey).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	w.mu.Lock()
	s.Running = w.running
	w.mu.Unlock()
	return s
}

func (w *Watcher) saveState(s State) {
	s.Running = false
	b, _ := json.Marshal(s)
	_, _ = w.DB.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, stateKey, string(b))
}

// Findings liste les constats, les ouverts d'abord. status vide : tous.
func (w *Watcher) Findings(status string) ([]Finding, error) {
	q := `SELECT domain, check_name, key, status, severity, detail, first_seen, last_seen FROM domain_watch`
	var args []any
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, last_seen DESC LIMIT ?`
	args = append(args, maxFindingsReturned)
	rows, err := w.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		var detail string
		if err := rows.Scan(&f.Domain, &f.Check, &f.Key, &f.Status, &f.Severity, &detail, &f.FirstSeen, &f.LastSeen); err != nil {
			return nil, err
		}
		f.Detail = json.RawMessage(detail)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Accept marque un constat comme reconnu : il ne compte plus et ne ré-alerte pas.
func (w *Watcher) Accept(domain, check, key string) (bool, error) {
	res, err := w.DB.Exec(`UPDATE domain_watch SET status=? WHERE domain=? AND check_name=? AND key=? AND status IN (?, ?)`,
		StatusAccepted, domain, check, key, StatusOpen, StatusBaseline)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ErrBusy : une exécution est en cours ou la dernière manuelle est trop récente.
var ErrBusy = errors.New("une analyse est déjà en cours, ou la dernière à la demande date de moins de 5 minutes")

// RunNow lance une analyse à la demande, en arrière-plan. Au plus une toutes les cinq minutes.
func (w *Watcher) RunNow() error {
	w.mu.Lock()
	if w.running || w.now().Sub(w.lastMan) < manualRunCooldown {
		w.mu.Unlock()
		return ErrBusy
	}
	w.lastMan = w.now()
	w.mu.Unlock()
	go w.Run(context.Background()) //nolint:errcheck
	return nil
}

// Start vérifie chaque minute si une analyse est due.
func (w *Watcher) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c := w.Config()
				if !c.Active() {
					continue
				}
				if last := w.State().LastRun; last.IsZero() || w.now().Sub(last) >= c.interval() {
					w.Run(ctx) //nolint:errcheck
				}
			}
		}
	}()
}

// declaredDomains rend les noms déclarés dans l'Admin, sans joker, sans doublon, au plus maxDomains.
func (w *Watcher) declaredDomains() ([]string, error) {
	rows, err := w.DB.Query(`SELECT domain FROM domains`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		d = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(d), "*."), "."))
		if d == "" || !strings.Contains(d, ".") || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) > maxDomains {
		out = out[:maxDomains]
	}
	return out, rows.Err()
}

// ownSerials rend les numéros de série des certificats que GoProxify détient, et les enregistre : un certificat renouvelé reste reconnu
// comme le sien après le suivant.
func (w *Watcher) ownSerials() (map[string]bool, error) {
	own := map[string]bool{}
	rows, err := w.DB.Query(`SELECT domain, cert_pem FROM certs WHERE cert_pem != ''`)
	if err != nil {
		return nil, err
	}
	type dc struct{ domain, serial string }
	var found []dc
	for rows.Next() {
		var domain, certPEM string
		if err := rows.Scan(&domain, &certPEM); err != nil {
			rows.Close()
			return nil, err
		}
		if s := leafSerial([]byte(certPEM)); s != "" {
			found = append(found, dc{domain, s})
		}
	}
	rows.Close()
	now := w.now().UTC()
	for _, f := range found {
		own[f.serial] = true
		d := strings.ToLower(strings.TrimPrefix(f.domain, "*."))
		_, _ = w.DB.Exec(`INSERT INTO domain_watch (domain, check_name, key, status, severity, detail, first_seen, last_seen)
			VALUES (?, ?, ?, ?, 'info', '{}', ?, ?)
			ON CONFLICT(domain, check_name, key) DO UPDATE SET last_seen=excluded.last_seen`, d, CheckCT, f.serial, StatusOurs, now, now)
	}
	rows2, err := w.DB.Query(`SELECT key FROM domain_watch WHERE check_name=? AND status=?`, CheckCT, StatusOurs)
	if err != nil {
		return own, nil
	}
	defer rows2.Close()
	for rows2.Next() {
		var k string
		if rows2.Scan(&k) == nil {
			own[k] = true
		}
	}
	return own, nil
}

// leafSerial rend le numéro de série (hexadécimal, sans zéros de tête) du premier certificat d'une chaîne PEM.
func leafSerial(chain []byte) string {
	for {
		var blk *pem.Block
		blk, chain = pem.Decode(chain)
		if blk == nil {
			return ""
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return ""
		}
		return normSerial(c.SerialNumber)
	}
}

func normSerial(n *big.Int) string { return strings.ToLower(n.Text(16)) }

// normSerialText normalise un numéro de série hexadécimal rendu par un journal (casse, zéros de tête, séparateurs).
func normSerialText(s string) string {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	s = strings.TrimLeft(s, "0")
	return s
}

// Run fait une analyse complète. Une analyse à la fois.
func (w *Watcher) Run(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return ErrBusy
	}
	w.running = true
	w.mu.Unlock()
	defer func() { w.mu.Lock(); w.running = false; w.mu.Unlock() }()

	cfg := w.Config()
	start := w.now()
	st := State{LastRun: start}
	if !cfg.Active() {
		return nil
	}
	domains, err := w.declaredDomains()
	if err != nil {
		st.LastError = err.Error()
		w.saveState(st)
		return err
	}
	st.Domains = len(domains)
	var errs []string
	own, err := w.ownSerials()
	if err != nil {
		errs = append(errs, "certificats : "+err.Error())
	}
	var dns DNSClient
	if cfg.CAA || cfg.Dangling {
		if w.DNS == nil {
			errs = append(errs, "dns : aucun client")
		} else if dns, err = w.DNS(cfg.Resolver); err != nil {
			errs = append(errs, "dns : "+err.Error())
		}
	}
	for i, d := range domains {
		if ctx.Err() != nil {
			break
		}
		if cfg.CT && w.CT != nil {
			if i > 0 {
				w.sleep(3 * time.Second)
			}
			if err := w.checkCT(ctx, cfg, d, own); err != nil {
				errs = append(errs, fmt.Sprintf("ct %s : %v", d, err))
			}
		}
		if dns != nil {
			if cfg.CAA {
				w.sleep(200 * time.Millisecond)
				if err := w.checkCAA(ctx, cfg, dns, d); err != nil {
					errs = append(errs, fmt.Sprintf("caa %s : %v", d, err))
				}
			}
			if cfg.Dangling {
				w.sleep(200 * time.Millisecond)
				if err := w.checkDangling(ctx, dns, d); err != nil {
					errs = append(errs, fmt.Sprintf("dangling %s : %v", d, err))
				}
			}
		}
	}
	if len(errs) > 0 {
		if len(errs) > 5 {
			errs = append(errs[:5], fmt.Sprintf("… et %d autres", len(errs)-5))
		}
		st.LastError = strings.Join(errs, " ; ")
	}
	st.DurationMS = w.now().Sub(start).Milliseconds()
	w.saveState(st)
	return nil
}

func (w *Watcher) emit(domain, check, finding, severity string, detail map[string]any) {
	if w.Alert == nil {
		return
	}
	sev := alerting.SevInfo
	switch severity {
	case "warning":
		sev = alerting.SevWarning
	case "critical":
		sev = alerting.SevCritical
	}
	d := map[string]any{"domain": domain, "check": check, "finding": finding}
	for k, v := range detail {
		d[k] = v
	}
	w.Alert(alerting.Event{Trigger: alerting.TriggerDomainWatch, Severity: sev, Domain: domain, Detail: d})
}

// setFinding enregistre un constat dont la présence est connue. Rend vrai quand il vient d'apparaître (ou de réapparaître) : l'appelant
// alerte alors une fois.
func (w *Watcher) setFinding(domain, check, key string, present bool, severity string, detail map[string]any) bool {
	now := w.now().UTC()
	b, _ := json.Marshal(detail)
	var status string
	err := w.DB.QueryRow(`SELECT status FROM domain_watch WHERE domain=? AND check_name=? AND key=?`, domain, check, key).Scan(&status)
	exists := err == nil
	switch {
	case present && !exists:
		_, _ = w.DB.Exec(`INSERT INTO domain_watch (domain, check_name, key, status, severity, detail, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)`,
			domain, check, key, StatusOpen, severity, string(b), now, now)
		return true
	case present && status == StatusResolved:
		_, _ = w.DB.Exec(`UPDATE domain_watch SET status=?, severity=?, detail=?, first_seen=?, last_seen=? WHERE domain=? AND check_name=? AND key=?`,
			StatusOpen, severity, string(b), now, now, domain, check, key)
		return true
	case present:
		_, _ = w.DB.Exec(`UPDATE domain_watch SET detail=?, last_seen=? WHERE domain=? AND check_name=? AND key=?`, string(b), now, domain, check, key)
	case exists && status == StatusOpen:
		_, _ = w.DB.Exec(`UPDATE domain_watch SET status=?, last_seen=? WHERE domain=? AND check_name=? AND key=?`, StatusResolved, now, domain, check, key)
	}
	return false
}
