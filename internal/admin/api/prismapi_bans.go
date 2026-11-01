// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

var prismSourceLabels = map[string]string{
	"threat":   "Ephor",
	"fleet":    "Seuils multi-passerelles",
	"crowdsec": "CrowdSec",
	"native":   "Manuel",
	"agent":    "Agent",
}

var ephorTechniqueLabels = map[string]string{
	"ip":           "Liste d'IP malveillantes",
	"custom_ip":    "Liste d'IP personnalisée",
	"ua":           "User-Agent suspect",
	"custom_ua":    "User-Agent personnalisé",
	"path":         "Chemin sensible (scan)",
	"custom_path":  "Chemin personnalisé",
	"decoy":        "Leurre touché",
	"unknown_host": "Hôte inconnu",
	"rate":         "Débit excessif",
}

// sourceLabel donne le libellé d'une source de ban. Celle d'un plugin de détection ("plugin:coraza") porte le
// nom du plugin.
func sourceLabel(src string) string {
	if l, ok := prismSourceLabels[src]; ok {
		return l
	}
	if name, ok := strings.CutPrefix(src, edgews.PluginBanSourcePrefix); ok && name != "" {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return src
}

// banTechnique déduit la technique de détection d'un ban à partir de sa source et de sa raison.
func banTechnique(source, reason string) (key, label string) {
	reason = strings.TrimSpace(reason)
	if strings.HasPrefix(source, edgews.PluginBanSourcePrefix) {
		return "denials", "Trop de refus"
	}
	switch source {
	case "threat":
		key = strings.TrimSpace(strings.TrimPrefix(reason, "threat:"))
		if l, ok := ephorTechniqueLabels[key]; ok {
			return key, l
		}
	case "fleet":
		key = strings.TrimSpace(strings.TrimPrefix(reason, "Seuils multi-passerelles :"))
		if key == "" || strings.Contains(key, "erreurs en") {
			return "errors", "Trop d'erreurs HTTP"
		}
	}
	if key == "" {
		key = reason
	}
	if key == "" {
		return "unknown", "Non précisé"
	}
	return key, key
}

// bansBreakdown ventile les bans actifs par source puis par technique de détection.
func (h *PrismHandler) bansBreakdown(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT source, reason, COUNT(*) FROM security_bans
		WHERE expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP
		GROUP BY source, reason`)
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		Source      string `json:"source"`
		SourceLabel string `json:"source_label"`
		Ephor       bool   `json:"ephor"`
		Technique   string `json:"technique"`
		Label       string `json:"label"`
		Count       int    `json:"count"`
	}
	agg := map[string]*row{}
	for rows.Next() {
		var src, reason string
		var n int
		if rows.Scan(&src, &reason, &n) != nil {
			continue
		}
		key, label := banTechnique(src, reason)
		k := src + "\x00" + key
		if cur, ok := agg[k]; ok {
			cur.Count += n
			continue
		}
		agg[k] = &row{Source: src, SourceLabel: sourceLabel(src), Ephor: src == "threat", Technique: key, Label: label, Count: n}
	}
	out := make([]row, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	jsonOK(w, out)
}

// ipScan ré-analyse une IP à la demande : bans actifs, historique, décisions de menace et activité récente.
func (h *PrismHandler) ipScan(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "ip invalide", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	p := prismParams(r)

	type ban struct {
		Source      string `json:"source"`
		SourceLabel string `json:"source_label"`
		Ephor       bool   `json:"ephor"`
		Technique   string `json:"technique"`
		Reason      string `json:"reason"`
		Since       string `json:"since"`
		ExpiresAt   string `json:"expires_at,omitempty"`
	}
	type threat struct {
		Scenario    string `json:"scenario"`
		Origin      string `json:"origin"`
		Occurrences int    `json:"occurrences"`
		LastSeen    string `json:"last_seen"`
	}
	type pathStat struct {
		Path     string `json:"path"`
		Requests int    `json:"requests"`
		Errors   int    `json:"errors"`
	}
	out := struct {
		IP         string     `json:"ip"`
		ScannedAt  string     `json:"scanned_at"`
		Verdict    string     `json:"verdict"`
		Bans       []ban      `json:"bans"`
		BanHistory int        `json:"ban_history"`
		Threats    []threat   `json:"threats"`
		Requests   int        `json:"requests"`
		Errors     int        `json:"errors"`
		FirstSeen  string     `json:"first_seen,omitempty"`
		LastSeen   string     `json:"last_seen,omitempty"`
		TopPaths   []pathStat `json:"top_paths"`
		// IPTruncated : les logs de la période portent cette valeur tronquée par l'anonymisation
		// RGPD — l'activité est celle de tout un /24 ou /48, pas d'un client.
		IPTruncated bool `json:"ip_truncated,omitempty"`
	}{IP: ip, ScannedAt: time.Now().UTC().Format(time.RFC3339), Bans: []ban{}, Threats: []threat{}, TopPaths: []pathStat{}}

	if rows, err := h.DB.QueryContext(ctx, `
		SELECT source, reason, COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', created_at),''), COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', expires_at),'')
		FROM security_bans WHERE ip = ? AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
		ORDER BY created_at DESC`, ip); err == nil {
		for rows.Next() {
			var b ban
			if rows.Scan(&b.Source, &b.Reason, &b.Since, &b.ExpiresAt) != nil {
				continue
			}
			b.Ephor = b.Source == "threat"
			b.SourceLabel = sourceLabel(b.Source)
			_, b.Technique = banTechnique(b.Source, b.Reason)
			out.Bans = append(out.Bans, b)
		}
		rows.Close()
	}
	h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ban_history WHERE ip = ? AND action = 'banned'`, ip).Scan(&out.BanHistory) //nolint:errcheck

	if rows, err := h.DB.QueryContext(ctx, `
		SELECT scenario, origin, occurrences, COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', last_seen_at),'')
		FROM security_threats WHERE ip = ? ORDER BY last_seen_at DESC LIMIT 10`, ip); err == nil {
		for rows.Next() {
			var t threat
			if rows.Scan(&t.Scenario, &t.Origin, &t.Occurrences, &t.LastSeen) == nil {
				out.Threats = append(out.Threats, t)
			}
		}
		rows.Close()
	}

	// L'activité de l'IP vient des bases de logs des passerelles ; sans passerelle il n'y en a pas.
	p.IP = ip
	if e := h.source(r, p); e != nil {
		tot, found, _, err := e.Totals(ctx, p)
		paths, _, perr := e.Top(ctx, p, nil, "path", 5, false)
		if err != nil || perr != nil {
			prismJSONErr(w, errors.Join(err, perr), http.StatusBadGateway)
			return
		}
		if found {
			out.Requests, out.Errors = int(tot.Requests), int(tot.Errors)
			out.FirstSeen, out.LastSeen, out.IPTruncated = tot.FirstSeen, tot.LastSeen, tot.Truncated
		}
		for _, it := range paths {
			out.TopPaths = append(out.TopPaths, pathStat{Path: it.Value, Requests: int(it.Requests), Errors: int(it.Errors)})
		}
	}

	switch {
	case len(out.Bans) > 0:
		out.Verdict = "banned"
	case len(out.Threats) > 0 || out.BanHistory > 0 || (out.Requests >= 20 && out.Errors*2 >= out.Requests):
		out.Verdict = "suspect"
	default:
		out.Verdict = "clean"
	}
	jsonOK(w, out)
}
