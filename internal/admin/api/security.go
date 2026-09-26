// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/crowdsec"
	"github.com/vincamok/goproxify/internal/admin/fail2ban"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/admin/vulnscan"
	"github.com/vincamok/goproxify/internal/core/router"
)

// SecurityHandler expose le dashboard sécurité.
type SecurityHandler struct {
	DB         *sql.DB
	Log        *slog.Logger
	Store      *security.Store
	Fail2Ban   *fail2ban.Engine
	VulnScan   *vulnscan.Scanner
	CrowdSec   *crowdsec.Bouncer
	ScanCtx    context.Context
	// OnBansChange notifie un changement de bans (push vers les Cores).
	OnBansChange func()
	// OnThreatConfigChange envoie la config du moteur de détection au Core visé
	// (coreRef vide = tous les Cores).
	OnThreatConfigChange func(coreRef string, cfg any)
	// OnServerConfigChange envoie les timeouts HTTP/QUIC aux Cores (redémarrage requis).
	OnServerConfigChange func(cfg any)
}

func (h *SecurityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/security")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	sub := parts[0]
	id := ""
	if len(parts) == 2 {
		id = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && sub == "":
		h.overview(w, r)
	case r.Method == http.MethodGet && sub == "overview":
		h.overview(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "history":
		h.listBanHistory(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "countries":
		h.bansByCountry(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "export":
		h.exportBans(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "intel/kpis":
		h.intelKPIs(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "intel/by-reason":
		h.intelByReason(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "intel/by-source":
		h.intelBySource(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "intel/timeline":
		h.intelTimeline(w, r)
	case r.Method == http.MethodGet && sub == "bans" && id == "intel/top-ips":
		h.intelTopIPs(w, r)
	case r.Method == http.MethodGet && sub == "bans":
		h.listBans(w, r)
	case r.Method == http.MethodPost && sub == "bans":
		h.createBan(w, r)
	case r.Method == http.MethodPatch && sub == "bans" && id != "":
		h.updateBan(w, r, id)
	case r.Method == http.MethodDelete && sub == "bans" && id != "":
		h.deleteBan(w, r, id)
	case r.Method == http.MethodGet && sub == "threats":
		h.listThreats(w, r)
	case r.Method == http.MethodGet && sub == "cves":
		h.listCVEs(w, r)
	case r.Method == http.MethodPatch && sub == "cves" && id != "":
		h.updateCVE(w, r, id)
	case r.Method == http.MethodGet && sub == "headers":
		h.headers(w, r)
	case r.Method == http.MethodGet && sub == "timeline":
		h.timeline(w, r)
	case r.Method == http.MethodGet && sub == "ip-timeline":
		h.ipTimeline(w, r)
	// Fail2Ban
	case r.Method == http.MethodGet && sub == "fail2ban":
		h.getF2BConfig(w, r)
	case r.Method == http.MethodPut && sub == "fail2ban":
		h.putF2BConfig(w, r)
	// VulnScan
	case r.Method == http.MethodGet && sub == "vulnscan" && id == "config":
		h.getVulnscanConfig(w, r)
	case r.Method == http.MethodPut && sub == "vulnscan" && id == "config":
		h.putVulnscanConfig(w, r)
	case r.Method == http.MethodGet && sub == "vulnscan":
		h.getVulnscanState(w, r)
	case r.Method == http.MethodPost && sub == "vulnscan":
		h.triggerVulnscan(w, r)
	// CrowdSec
	case r.Method == http.MethodGet && sub == "crowdsec":
		h.getCrowdSecConfig(w, r)
	case r.Method == http.MethodPut && sub == "crowdsec":
		h.putCrowdSecConfig(w, r)
	// IPS provider switch (mutual exclusivity)
	case r.Method == http.MethodGet && sub == "ips-provider":
		h.getIPSProvider(w, r)
	case r.Method == http.MethodPut && sub == "ips-provider":
		h.putIPSProvider(w, r)
	// Moteur de détection automatique (threat engine)
	case r.Method == http.MethodGet && sub == "threat-config":
		h.getThreatConfig(w, r)
	case r.Method == http.MethodPut && sub == "threat-config":
		h.putThreatConfig(w, r)
	// Timeouts HTTP/QUIC (statiques — redémarrage Core requis)
	case r.Method == http.MethodGet && sub == "server-config":
		h.getServerConfig(w, r)
	case r.Method == http.MethodPut && sub == "server-config":
		h.putServerConfig(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *SecurityHandler) overview(w http.ResponseWriter, r *http.Request) {
	proxies := h.Store.LoadProxies()
	ov := h.Store.GetOverview(proxies)

	// Ajoute les certs depuis la DB
	certs := h.loadCertStatus(r)
	jsonOK(w, map[string]any{
		"overview": ov,
		"certs":    certs,
	})
}

func (h *SecurityHandler) loadCertStatus(r *http.Request) []map[string]any {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT domain, issuer, expires_at, updated_at FROM certs ORDER BY expires_at ASC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	now := time.Now()
	for rows.Next() {
		var domain, issuer, expiresAt, updatedAt string
		if err := rows.Scan(&domain, &issuer, &expiresAt, &updatedAt); err != nil {
			continue
		}
		exp, _ := time.Parse("2006-01-02T15:04:05Z", expiresAt)
		if exp.IsZero() {
			exp, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
		}
		daysLeft := int(exp.Sub(now).Hours() / 24)
		status := "valid"
		if exp.Before(now) {
			status = "expired"
		} else if daysLeft <= 30 {
			status = "expiring"
		}
		out = append(out, map[string]any{
			"domain": domain, "issuer": issuer, "expires_at": expiresAt,
			"days_left": daysLeft, "status": status,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// ── Bans ─────────────────────────────────────────────────────────────────────

func (h *SecurityHandler) listBans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var clauses []string
	var args []any
	if v := q.Get("ip"); v != "" {
		clauses = append(clauses, "ip LIKE ?")
		args = append(args, "%"+v+"%")
	}
	if v := q.Get("domain"); v != "" {
		clauses = append(clauses, "domain=?")
		args = append(args, v)
	}
	if v := q.Get("source"); v != "" {
		clauses = append(clauses, "source=?")
		args = append(args, v)
	}
	if q.Get("active") == "true" {
		clauses = append(clauses, "(expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)")
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, domain, reason, source, expires_at, strftime('%Y-%m-%dT%H:%M:%SZ', created_at) FROM security_bans`+where+` ORDER BY created_at DESC LIMIT 200`,
		args...)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []security.Ban
	for rows.Next() {
		var b security.Ban
		var exp sql.NullString
		var createdAt string
		if err := rows.Scan(&b.ID, &b.IP, &b.Domain, &b.Reason, &b.Source, &exp, &createdAt); err != nil {
			if h.Log != nil {
				h.Log.Warn("security bans: scan", "err", err)
			}
			continue
		}
		if exp.Valid {
			s := exp.String
			b.ExpiresAt = &s
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, b)
	}
	if out == nil {
		out = []security.Ban{}
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) createBan(w http.ResponseWriter, r *http.Request) {
	var body security.Ban
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.IP == "" {
		http.Error(w, "ip requis", http.StatusBadRequest)
		return
	}
	if body.Source == "" {
		body.Source = "native"
	}
	id := uuid.New().String()
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, body.IP, body.Domain, body.Reason, body.Source, body.ExpiresAt,
	)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	h.DB.ExecContext(r.Context(), //nolint:errcheck
		`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?, ?, 'banned', ?, ?, ?)`,
		body.IP, body.Domain, body.Reason, body.Source, id,
	)
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"id": id})
}

func (h *SecurityHandler) updateBan(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Permanent *bool   `json:"permanent"`
		ExpiresAt *string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	// permanent=true (ou expires_at null explicite) → ban sans expiration
	if body.Permanent != nil && *body.Permanent {
		if _, err := h.DB.ExecContext(r.Context(), `UPDATE security_bans SET expires_at=NULL WHERE id=?`, id); err != nil {
			secJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		if h.OnBansChange != nil {
			h.OnBansChange()
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if body.ExpiresAt != nil {
		if *body.ExpiresAt == "" {
			if _, err := h.DB.ExecContext(r.Context(), `UPDATE security_bans SET expires_at=NULL WHERE id=?`, id); err != nil {
				secJSONErr(w, err, http.StatusInternalServerError)
				return
			}
		} else {
			if _, err := h.DB.ExecContext(r.Context(), `UPDATE security_bans SET expires_at=? WHERE id=?`, *body.ExpiresAt, id); err != nil {
				secJSONErr(w, err, http.StatusInternalServerError)
				return
			}
		}
		if h.OnBansChange != nil {
			h.OnBansChange()
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeErr(w, r, http.StatusBadRequest, "api.err.json")
}

func (h *SecurityHandler) deleteBan(w http.ResponseWriter, r *http.Request, id string) {
	var ip, domain, reason, source string
	h.DB.QueryRowContext(r.Context(), //nolint:errcheck
		`SELECT ip, domain, reason, source FROM security_bans WHERE id=?`, id,
	).Scan(&ip, &domain, &reason, &source)
	h.DB.ExecContext(r.Context(), `DELETE FROM security_bans WHERE id=?`, id) //nolint:errcheck
	if ip != "" {
		h.DB.ExecContext(r.Context(), //nolint:errcheck
			`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?, ?, 'unbanned', ?, ?, ?)`,
			ip, domain, reason, source, id,
		)
	}
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SecurityHandler) listBanHistory(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip requis", http.StatusBadRequest)
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, domain, action, reason, source, ban_id, strftime('%Y-%m-%dT%H:%M:%SZ', created_at) FROM security_ban_history WHERE ip=? ORDER BY created_at DESC LIMIT 100`,
		ip)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []security.BanEvent
	for rows.Next() {
		var ev security.BanEvent
		var createdAt string
		if err := rows.Scan(&ev.ID, &ev.IP, &ev.Domain, &ev.Action, &ev.Reason, &ev.Source, &ev.BanID, &createdAt); err != nil {
			continue
		}
		ev.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, ev)
	}
	if out == nil {
		out = []security.BanEvent{}
	}
	jsonOK(w, out)
}

// bansByCountry retourne le nombre de bans actifs par pays (joint geoip_cache).
func (h *SecurityHandler) bansByCountry(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT COALESCE(g.country_code, 'XX') AS cc,
		       COALESCE(g.country_name, 'Unknown') AS name,
		       COUNT(*) AS cnt
		FROM security_bans b
		LEFT JOIN geoip_cache g ON g.ip = b.ip
		WHERE b.expires_at IS NULL OR b.expires_at = '' OR b.expires_at > CURRENT_TIMESTAMP
		GROUP BY cc, name
		ORDER BY cnt DESC`)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		CountryCode string `json:"country_code"`
		CountryName string `json:"country_name"`
		Count       int    `json:"count"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.CountryCode, &r.CountryName, &r.Count); err != nil {
			continue
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	jsonOK(w, out)
}

// ── Timeline IP ───────────────────────────────────────────────────────────────

func (h *SecurityHandler) ipTimeline(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip requis", http.StatusBadRequest)
		return
	}

	type Event struct {
		Kind      string    `json:"kind"` // "ban" | "unban" | "threat"
		Source    string    `json:"source"`
		Reason    string    `json:"reason"`
		CreatedAt time.Time `json:"created_at"`
	}

	var events []Event

	// Bans / débans
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT action, reason, source, strftime('%Y-%m-%dT%H:%M:%SZ', created_at)
		 FROM security_ban_history WHERE ip=? ORDER BY created_at DESC LIMIT 200`, ip)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ev Event
			var ts string
			if rows.Scan(&ev.Kind, &ev.Reason, &ev.Source, &ts) == nil {
				ev.CreatedAt, _ = time.Parse(time.RFC3339, ts)
				if ev.Kind == "unbanned" {
					ev.Kind = "unban"
				} else {
					ev.Kind = "ban"
				}
				events = append(events, ev)
			}
		}
	}

	// Décisions CrowdSec / Sentinel (threats)
	rows2, err := h.DB.QueryContext(r.Context(),
		`SELECT scenario, origin, strftime('%Y-%m-%dT%H:%M:%SZ', created_at)
		 FROM security_threats WHERE ip=? ORDER BY created_at DESC LIMIT 200`, ip)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var scenario, origin, ts string
			if rows2.Scan(&scenario, &origin, &ts) == nil {
				ev := Event{Kind: "threat", Source: origin, Reason: scenario}
				ev.CreatedAt, _ = time.Parse(time.RFC3339, ts)
				events = append(events, ev)
			}
		}
	}

	// Tri global par date décroissante
	for i := 0; i < len(events)-1; i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].CreatedAt.After(events[i].CreatedAt) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}

	if events == nil {
		events = []Event{}
	}
	jsonOK(w, events)
}

// ── Threats ───────────────────────────────────────────────────────────────────

func (h *SecurityHandler) listThreats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if v, _ := strconv.Atoi(q.Get("limit")); v > 0 && v <= 500 {
		limit = v
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, scenario, origin, type, duration, core_name, occurrences,
		        strftime('%Y-%m-%dT%H:%M:%SZ', last_seen_at), strftime('%Y-%m-%dT%H:%M:%SZ', created_at)
		 FROM security_threats ORDER BY last_seen_at DESC LIMIT ?`,
		limit)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []security.Threat
	for rows.Next() {
		var t security.Threat
		var lastSeenAt, createdAt string
		if err := rows.Scan(&t.ID, &t.IP, &t.Scenario, &t.Origin, &t.Type, &t.Duration, &t.CoreName, &t.Occurrences, &lastSeenAt, &createdAt); err != nil {
			continue
		}
		t.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeenAt)
		t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, t)
	}
	if out == nil {
		out = []security.Threat{}
	}
	jsonOK(w, out)
}

// ── CVEs ──────────────────────────────────────────────────────────────────────

func (h *SecurityHandler) listCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var clauses []string
	var args []any
	if v := q.Get("status"); v != "" {
		clauses = append(clauses, "status=?")
		args = append(args, v)
	}
	if q.Get("critical") == "true" {
		clauses = append(clauses, "cvss_score>=7")
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, backend_url, cve_id, cvss_score, description, status, core_name, detected_at FROM security_cves`+where+` ORDER BY cvss_score DESC, detected_at DESC`,
		args...)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []security.CVE
	for rows.Next() {
		var c security.CVE
		var detectedAt string
		if err := rows.Scan(&c.ID, &c.BackendURL, &c.CVEID, &c.CVSSScore, &c.Description, &c.Status, &c.CoreName, &detectedAt); err != nil {
			continue
		}
		c.DetectedAt, _ = time.Parse("2006-01-02 15:04:05", detectedAt)
		out = append(out, c)
	}
	if out == nil {
		out = []security.CVE{}
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) updateCVE(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	h.DB.ExecContext(r.Context(), `UPDATE security_cves SET status=? WHERE id=?`, body.Status, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// ── Headers ───────────────────────────────────────────────────────────────────

func (h *SecurityHandler) headers(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, config FROM proxies WHERE enabled=1 ORDER BY name`)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []security.HeaderCheck
	for rows.Next() {
		var id, name, cfgJSON string
		if err := rows.Scan(&id, &name, &cfgJSON); err != nil {
			continue
		}
		var cfg router.Route
		_ = json.Unmarshal([]byte(cfgJSON), &cfg)
		if domain != "" && cfg.Host != domain {
			continue
		}
		out = append(out, security.ComputeHeaderScore(id, name, cfg.Host, cfg))
	}
	if out == nil {
		out = []security.HeaderCheck{}
	}
	jsonOK(w, out)
}

// ── Timeline ─────────────────────────────────────────────────────────────────

func (h *SecurityHandler) timeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if v, _ := strconv.Atoi(q.Get("limit")); v > 0 && v <= 500 {
		limit = v
	}
	source := q.Get("source") // ban | threat | cve | cert | all

	type event struct {
		Type      string `json:"type"`
		CreatedAt string `json:"created_at"`
		IP        string `json:"ip,omitempty"`
		Domain    string `json:"domain,omitempty"`
		Summary   string `json:"summary"`
		Severity  string `json:"severity"`
		Source    string `json:"source,omitempty"`
	}
	var events []event

	banSourceLabel := map[string]string{
		"fail2ban": "Fail2Ban",
		"native":   "Natif",
		"crowdsec": "CrowdSec",
		"threat":   "Sentinel",
		"agent":    "Agent",
	}

	if source == "" || source == "ban" || source == "all" {
		rows, _ := h.DB.QueryContext(r.Context(),
			`SELECT ip, domain, source, reason, created_at FROM security_bans ORDER BY created_at DESC LIMIT ?`, limit)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var ip, domain, src, reason, ts string
				rows.Scan(&ip, &domain, &src, &reason, &ts) //nolint:errcheck
				label := banSourceLabel[src]
				if label == "" {
					label = src
				}
				events = append(events, event{Type: "ban", IP: ip, Domain: domain, CreatedAt: ts, Source: src,
					Summary: label + ": " + ip + " banni — " + reason, Severity: "warning"})
			}
		}
	}
	if source == "" || source == "threat" || source == "all" {
		rows, _ := h.DB.QueryContext(r.Context(),
			`SELECT ip, scenario, created_at FROM security_threats ORDER BY created_at DESC LIMIT ?`, limit)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var ip, scenario, ts string
				rows.Scan(&ip, &scenario, &ts) //nolint:errcheck
				events = append(events, event{Type: "threat", IP: ip, CreatedAt: ts,
					Summary: "CrowdSec : " + ip + " — " + scenario, Severity: "critical"})
			}
		}
	}
	if source == "" || source == "cve" || source == "all" {
		rows, _ := h.DB.QueryContext(r.Context(),
			`SELECT cve_id, backend_url, cvss_score, detected_at FROM security_cves WHERE status='open' ORDER BY detected_at DESC LIMIT ?`, limit)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var cveID, backend, ts string
				var cvss float64
				rows.Scan(&cveID, &backend, &cvss, &ts) //nolint:errcheck
				sev := "warning"
				if cvss >= 7 {
					sev = "critical"
				}
				events = append(events, event{Type: "cve", CreatedAt: ts,
					Summary: cveID + " (CVSS " + strconv.FormatFloat(cvss, 'f', 1, 64) + ") — " + backend, Severity: sev})
			}
		}
	}
	if len(events) == 0 {
		events = []event{}
	}
	if len(events) > limit {
		events = events[:limit]
	}
	jsonOK(w, events)
}

// ── Fail2Ban ──────────────────────────────────────────────────────────────────

func (h *SecurityHandler) getF2BConfig(w http.ResponseWriter, r *http.Request) {
	if h.Fail2Ban == nil {
		jsonOK(w, fail2ban.DefaultConfig())
		return
	}
	jsonOK(w, h.Fail2Ban.GetConfig())
}

func (h *SecurityHandler) putF2BConfig(w http.ResponseWriter, r *http.Request) {
	if h.Fail2Ban == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.fail2ban")
		return
	}
	var cfg fail2ban.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if err := h.Fail2Ban.SaveConfig(cfg); err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── VulnScan ──────────────────────────────────────────────────────────────────

func (h *SecurityHandler) getVulnscanState(w http.ResponseWriter, r *http.Request) {
	if h.VulnScan == nil {
		jsonOK(w, map[string]any{"running": false})
		return
	}
	jsonOK(w, h.VulnScan.GetState())
}

func (h *SecurityHandler) triggerVulnscan(w http.ResponseWriter, r *http.Request) {
	if h.VulnScan == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.vulnscan")
		return
	}
	ctx := h.ScanCtx
	if ctx == nil {
		ctx = context.Background()
	}
	h.VulnScan.RunNow(ctx)
	w.WriteHeader(http.StatusAccepted)
}

func (h *SecurityHandler) getVulnscanConfig(w http.ResponseWriter, r *http.Request) {
	var v string
	h.DB.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key='vulnscan_allow_private'`).Scan(&v) //nolint:errcheck
	jsonOK(w, map[string]bool{"allow_private": v == "1" || v == "true"})
}

func (h *SecurityHandler) putVulnscanConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AllowPrivate bool `json:"allow_private"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	val := "false"
	if body.AllowPrivate {
		val = "true"
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO settings (key, value) VALUES ('vulnscan_allow_private', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, val)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── CrowdSec ──────────────────────────────────────────────────────────────────

func (h *SecurityHandler) getCrowdSecConfig(w http.ResponseWriter, r *http.Request) {
	if h.CrowdSec == nil {
		jsonOK(w, crowdsec.DefaultConfig())
		return
	}
	jsonOK(w, h.CrowdSec.GetConfig())
}

func (h *SecurityHandler) putCrowdSecConfig(w http.ResponseWriter, r *http.Request) {
	if h.CrowdSec == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.crowdsec")
		return
	}
	var cfg crowdsec.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if err := h.CrowdSec.SaveConfig(cfg); err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	go h.CrowdSec.SyncNow(context.Background())
	w.WriteHeader(http.StatusNoContent)
}

// ── IPS Provider ─────────────────────────────────────────────────────────────

// ipsProviderKey retourne la clé settings pour un Core donné.
func ipsProviderKey(coreID string) string {
	if coreID == "" {
		return "ips_provider"
	}
	return "ips_provider:" + coreID
}

// threatConfigKey retourne la clé settings pour un Core donné.
func threatConfigKey(coreID string) string {
	if coreID == "" {
		return "threat_engine_config"
	}
	return "threat_engine_config:" + coreID
}

// getIPSProvider retourne le fournisseur IPS actif pour le Core demandé.
func (h *SecurityHandler) getIPSProvider(w http.ResponseWriter, r *http.Request) {
	coreID := r.URL.Query().Get("core")
	key := ipsProviderKey(coreID)
	row := h.DB.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key=?`, key)
	var provider string
	if err := row.Scan(&provider); err != nil {
		provider = "native"
	}
	if provider == "" || provider == "none" {
		provider = "native"
	}
	jsonOK(w, map[string]string{"provider": provider})
}

// putIPSProvider enregistre le fournisseur choisi pour le Core demandé.
func (h *SecurityHandler) putIPSProvider(w http.ResponseWriter, r *http.Request) {
	coreID := r.URL.Query().Get("core")
	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	switch req.Provider {
	case "native", "none", "fail2ban", "crowdsec":
	default:
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	provider := req.Provider
	if provider == "none" {
		provider = "native"
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		ipsProviderKey(coreID), provider)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Threat Config ─────────────────────────────────────────────────────────────

func (h *SecurityHandler) getThreatConfig(w http.ResponseWriter, r *http.Request) {
	coreID := r.URL.Query().Get("core")
	row := h.DB.QueryRowContext(r.Context(),
		`SELECT value FROM settings WHERE key=?`, threatConfigKey(coreID))
	var raw string
	if err := row.Scan(&raw); err != nil {
		jsonOK(w, map[string]any{"enabled": false})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(raw)) //nolint:errcheck
}

func (h *SecurityHandler) putThreatConfig(w http.ResponseWriter, r *http.Request) {
	coreID := r.URL.Query().Get("core")
	var cfg json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatConfigKey(coreID), string(cfg))
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if h.OnThreatConfigChange != nil {
		h.OnThreatConfigChange(coreID, cfg)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Server Config (timeouts HTTP/QUIC) ───────────────────────────────────────

func serverConfigKey(coreID string) string {
	if coreID == "" {
		return "server_config"
	}
	return "server_config:" + coreID
}

func (h *SecurityHandler) getServerConfig(w http.ResponseWriter, r *http.Request) {
	coreID := r.URL.Query().Get("core")
	row := h.DB.QueryRowContext(r.Context(),
		`SELECT value FROM settings WHERE key=?`, serverConfigKey(coreID))
	var raw string
	if err := row.Scan(&raw); err != nil {
		jsonOK(w, map[string]any{})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(raw)) //nolint:errcheck
}

func (h *SecurityHandler) putServerConfig(w http.ResponseWriter, r *http.Request) {
	coreID := r.URL.Query().Get("core")
	var cfg json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		serverConfigKey(coreID), string(cfg))
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if h.OnServerConfigChange != nil {
		h.OnServerConfigChange(cfg)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func secJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}

// ── Export bans ───────────────────────────────────────────────────────────────

func (h *SecurityHandler) exportBans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}

	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id, ip, domain, reason, source,
		       COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', expires_at), '') AS expires_at,
		       strftime('%Y-%m-%dT%H:%M:%SZ', created_at) AS created_at
		FROM security_bans ORDER BY created_at DESC LIMIT 10000`)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type row struct {
		ID        string `json:"id"`
		IP        string `json:"ip"`
		Domain    string `json:"domain"`
		Reason    string `json:"reason"`
		Source    string `json:"source"`
		ExpiresAt string `json:"expires_at"`
		CreatedAt string `json:"created_at"`
	}
	var bans []row
	for rows.Next() {
		var b row
		if rows.Scan(&b.ID, &b.IP, &b.Domain, &b.Reason, &b.Source, &b.ExpiresAt, &b.CreatedAt) == nil {
			bans = append(bans, b)
		}
	}
	if bans == nil {
		bans = []row{}
	}

	ts := time.Now().Format("20060102-150405")
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=bans-export-%s.json", ts))
		json.NewEncoder(w).Encode(bans) //nolint:errcheck
	default: // csv
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=bans-export-%s.csv", ts))
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "ip", "domain", "reason", "source", "expires_at", "created_at"})
		for _, b := range bans {
			_ = cw.Write([]string{b.ID, b.IP, b.Domain, b.Reason, b.Source, b.ExpiresAt, b.CreatedAt})
		}
		cw.Flush()
	}
}

// ── Ban Intelligence endpoints ────────────────────────────────────────────────

func (h *SecurityHandler) intelKPIs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var active, histTotal, recurring int
	h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_bans`).Scan(&active)                      //nolint:errcheck
	h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ban_history WHERE action='banned'`).Scan(&histTotal) //nolint:errcheck
	h.DB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ip) FROM security_ban_history WHERE action='banned' GROUP BY ip HAVING COUNT(*)>=3`).Scan(&recurring) //nolint:errcheck

	var bannedCount, unbannedCount int
	h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ban_history WHERE action='banned'`).Scan(&bannedCount)   //nolint:errcheck
	h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ban_history WHERE action='unbanned'`).Scan(&unbannedCount) //nolint:errcheck

	jsonOK(w, map[string]any{
		"active":        active,
		"history_total": histTotal,
		"recurring_ips": recurring,
		"unbanned":      unbannedCount,
		"rotation_ratio": func() float64 {
			if bannedCount == 0 {
				return 0
			}
			return float64(unbannedCount) / float64(bannedCount)
		}(),
	})
}

func (h *SecurityHandler) intelByReason(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT reason, COUNT(*) as n FROM security_ban_history WHERE action='banned'
		 GROUP BY reason ORDER BY n DESC LIMIT 30`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	defer rows.Close()
	type entry struct {
		Reason string `json:"reason"`
		Count  int    `json:"count"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		rows.Scan(&e.Reason, &e.Count) //nolint:errcheck
		out = append(out, e)
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) intelBySource(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT source, COUNT(*) as n FROM security_ban_history WHERE action='banned'
		 GROUP BY source ORDER BY n DESC`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	defer rows.Close()
	type entry struct {
		Source string `json:"source"`
		Count  int    `json:"count"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		rows.Scan(&e.Source, &e.Count) //nolint:errcheck
		out = append(out, e)
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) intelTimeline(w http.ResponseWriter, r *http.Request) {
	hours := 48
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02T15:04:05Z")
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as hour, COUNT(*) as n
		 FROM security_ban_history
		 WHERE action='banned' AND created_at >= ?
		 GROUP BY hour ORDER BY hour ASC`, since)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	defer rows.Close()
	type entry struct {
		Hour  string `json:"hour"`
		Count int    `json:"count"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		rows.Scan(&e.Hour, &e.Count) //nolint:errcheck
		out = append(out, e)
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) intelTopIPs(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT ip,
		        COUNT(*) as total_bans,
		        MAX(created_at) as last_seen,
		        (SELECT source FROM security_ban_history h2 WHERE h2.ip=h.ip AND h2.action='banned' GROUP BY source ORDER BY COUNT(*) DESC LIMIT 1) as main_source,
		        (SELECT reason FROM security_ban_history h3 WHERE h3.ip=h.ip AND h3.action='banned' GROUP BY reason ORDER BY COUNT(*) DESC LIMIT 1) as main_reason,
		        EXISTS(SELECT 1 FROM security_bans sb WHERE sb.ip=h.ip) as currently_banned
		 FROM security_ban_history h WHERE action='banned'
		 GROUP BY ip ORDER BY total_bans DESC LIMIT ?`, limit)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	defer rows.Close()
	type entry struct {
		IP             string `json:"ip"`
		TotalBans      int    `json:"total_bans"`
		LastSeen       string `json:"last_seen"`
		MainSource     string `json:"main_source"`
		MainReason     string `json:"main_reason"`
		CurrentlyBanned bool  `json:"currently_banned"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		var banned int
		rows.Scan(&e.IP, &e.TotalBans, &e.LastSeen, &e.MainSource, &e.MainReason, &banned) //nolint:errcheck
		e.CurrentlyBanned = banned == 1
		out = append(out, e)
	}
	jsonOK(w, out)
}

// ThreatConfigKey expose la clé settings de la config Sentinel d'un Core (outil MCP de simulation).
func ThreatConfigKey(coreID string) string { return threatConfigKey(coreID) }
