// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
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
	// Fail2Ban
	case r.Method == http.MethodGet && sub == "fail2ban":
		h.getF2BConfig(w, r)
	case r.Method == http.MethodPut && sub == "fail2ban":
		h.putF2BConfig(w, r)
	// VulnScan
	case r.Method == http.MethodGet && sub == "vulnscan":
		h.getVulnscanState(w, r)
	case r.Method == http.MethodPost && sub == "vulnscan":
		h.triggerVulnscan(w, r)
	// CrowdSec
	case r.Method == http.MethodGet && sub == "crowdsec":
		h.getCrowdSecConfig(w, r)
	case r.Method == http.MethodPut && sub == "crowdsec":
		h.putCrowdSecConfig(w, r)
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
		`SELECT id, ip, domain, reason, source, expires_at, created_at FROM security_bans`+where+` ORDER BY created_at DESC LIMIT 200`,
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
		b.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
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
	h.DB.ExecContext(r.Context(), `DELETE FROM security_bans WHERE id=?`, id) //nolint:errcheck
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Threats ───────────────────────────────────────────────────────────────────

func (h *SecurityHandler) listThreats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if v, _ := strconv.Atoi(q.Get("limit")); v > 0 && v <= 500 {
		limit = v
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, scenario, origin, type, duration, created_at FROM security_threats ORDER BY created_at DESC LIMIT ?`,
		limit)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []security.Threat
	for rows.Next() {
		var t security.Threat
		var createdAt string
		if err := rows.Scan(&t.ID, &t.IP, &t.Scenario, &t.Origin, &t.Type, &t.Duration, &createdAt); err != nil {
			continue
		}
		t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
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
		`SELECT id, backend_url, cve_id, cvss_score, description, status, detected_at FROM security_cves`+where+` ORDER BY cvss_score DESC, detected_at DESC`,
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
		if err := rows.Scan(&c.ID, &c.BackendURL, &c.CVEID, &c.CVSSScore, &c.Description, &c.Status, &detectedAt); err != nil {
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
	}
	var events []event

	if source == "" || source == "ban" || source == "all" {
		rows, _ := h.DB.QueryContext(r.Context(),
			`SELECT ip, domain, source, reason, created_at FROM security_bans ORDER BY created_at DESC LIMIT ?`, limit)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var ip, domain, src, reason, ts string
				rows.Scan(&ip, &domain, &src, &reason, &ts) //nolint:errcheck
				events = append(events, event{Type: "ban", IP: ip, Domain: domain, CreatedAt: ts,
					Summary: src + ": " + ip + " banni — " + reason, Severity: "warning"})
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

// ── Helpers ───────────────────────────────────────────────────────────────────

func secJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
