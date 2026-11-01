// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package domainwatch

import (
	"context"
	"encoding/json"
	"strings"
)

const maxCTEntriesPerDomain = 500

const baselinePrefix = "domain_watch_ct_baseline:"

func (w *Watcher) hasBaseline(domain string) bool {
	var v string
	return w.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, baselinePrefix+domain).Scan(&v) == nil
}

func (w *Watcher) markBaseline(domain string) {
	_, _ = w.DB.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`, baselinePrefix+domain, w.now().UTC().Format("2006-01-02T15:04:05Z"))
}

// checkCT compare les certificats que le journal de transparence connaît pour le domaine à ceux de GoProxify. Un certificat qui n'est ni
// de GoProxify, ni d'un émetteur toléré, et qui apparaît après la première analyse du domaine est signalé ; ceux qui existaient déjà à la
// première analyse sont listés (baseline) sans alerte : on ne sait pas s'ils sont légitimes, l'administrateur les passe en revue.
func (w *Watcher) checkCT(ctx context.Context, cfg Config, domain string, own map[string]bool) error {
	entries, err := w.CT.Fetch(ctx, cfg.ctEndpoint(), domain)
	if err != nil {
		return err
	}
	if len(entries) > maxCTEntriesPerDomain {
		entries = entries[:maxCTEntriesPerDomain]
	}
	first := !w.hasBaseline(domain)
	now := w.now().UTC()
	for _, e := range entries {
		serial := normSerialText(e.Serial)
		if serial == "" {
			continue
		}
		detail, _ := json.Marshal(map[string]any{"issuer": e.Issuer, "names": e.Names, "not_before": e.NotBefore, "not_after": e.NotAfter})
		status, severity := StatusOpen, "critical"
		switch {
		case own[serial]:
			status, severity = StatusOurs, "info"
		case issuerTrusted(e.Issuer, cfg.TrustedIssuers):
			status, severity = StatusTrusted, "info"
		case first:
			status, severity = StatusBaseline, "info"
		}
		var existing string
		err := w.DB.QueryRow(`SELECT status FROM domain_watch WHERE domain=? AND check_name=? AND key=?`, domain, CheckCT, serial).Scan(&existing)
		if err == nil {
			_, _ = w.DB.Exec(`UPDATE domain_watch SET last_seen=? WHERE domain=? AND check_name=? AND key=?`, now, domain, CheckCT, serial)
			// Un certificat jusque-là inconnu qui devient celui de GoProxify ou d'un émetteur toléré cesse d'être à traiter.
			if (status == StatusOurs || status == StatusTrusted) && existing != status && existing != StatusAccepted {
				_, _ = w.DB.Exec(`UPDATE domain_watch SET status=?, severity='info' WHERE domain=? AND check_name=? AND key=?`, status, domain, CheckCT, serial)
			}
			continue
		}
		_, _ = w.DB.Exec(`INSERT INTO domain_watch (domain, check_name, key, status, severity, detail, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)`,
			domain, CheckCT, serial, status, severity, string(detail), now, now)
		if status == StatusOpen {
			w.emit(domain, CheckCT, "unexpected_certificate", "critical", map[string]any{
				"issuer": e.Issuer, "serial": serial, "names": strings.Join(e.Names, ", "), "not_before": e.NotBefore.Format("2006-01-02"),
			})
		}
	}
	w.markBaseline(domain)
	return nil
}

func issuerTrusted(issuer string, trusted []string) bool {
	issuer = strings.ToLower(issuer)
	for _, t := range trusted {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" && strings.Contains(issuer, t) {
			return true
		}
	}
	return false
}

// checkCAA évalue les enregistrements CAA qui s'appliquent au domaine : absents, trop larges, ou qui n'autoriseraient pas l'autorité que
// GoProxify utilise (les renouvellements échoueraient).
func (w *Watcher) checkCAA(ctx context.Context, cfg Config, dns DNSClient, domain string) error {
	recs, err := dns.CAA(ctx, domain)
	if err != nil {
		return err
	}
	issuers := map[string]bool{}
	hasIssue := false
	for _, r := range recs {
		if strings.EqualFold(r.Tag, "issue") {
			hasIssue = true
			if id := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Value, ";", 2)[0])); id != "" {
				issuers[id] = true
			}
		}
	}
	list := make([]string, 0, len(issuers))
	for id := range issuers {
		list = append(list, id)
	}
	missing := len(recs) == 0
	excludes := hasIssue && !issuers[cfg.caIssuer()]
	wide := len(issuers) >= tooWideAuthorities
	if w.setFinding(domain, CheckCAA, "caa_missing", missing, "info", map[string]any{}) {
		w.emit(domain, CheckCAA, "caa_missing", "info", nil)
	}
	if w.setFinding(domain, CheckCAA, "caa_excludes_ca", excludes, "warning", map[string]any{"authorities": list, "expected": cfg.caIssuer()}) {
		w.emit(domain, CheckCAA, "caa_excludes_ca", "warning", map[string]any{"expected": cfg.caIssuer(), "authorities": strings.Join(list, ", ")})
	}
	if w.setFinding(domain, CheckCAA, "caa_too_wide", wide, "info", map[string]any{"authorities": list}) {
		w.emit(domain, CheckCAA, "caa_too_wide", "info", map[string]any{"authorities": strings.Join(list, ", ")})
	}
	return nil
}

// checkDangling cherche un nom dont le CNAME pointe vers une cible qui n'existe plus : qui la réenregistre détourne le nom.
func (w *Watcher) checkDangling(ctx context.Context, dns DNSClient, domain string) error {
	target, err := dns.Dangling(ctx, domain)
	if err != nil {
		return err
	}
	if w.setFinding(domain, CheckDangling, "dangling_cname", target != "", "warning", map[string]any{"target": target}) {
		w.emit(domain, CheckDangling, "dangling_cname", "warning", map[string]any{"target": target})
	}
	return nil
}
