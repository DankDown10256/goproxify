// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

// --- Routes pour les Agents ----------------------------------------------

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		Ts        string `json:"ts"`
		Level     string `json:"level"`
		Component string `json:"component"`
		NodeName  string `json:"node_name"`
		Domain    string `json:"domain"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Status    int    `json:"status"`
		IP        string `json:"ip"`
		LatencyMs int64  `json:"latency_ms"`
		Bytes     int64  `json:"bytes"`
		Message   string `json:"message"`
		Referrer  string `json:"referrer"`
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	for _, item := range batch {
		ts, _ := time.Parse(time.RFC3339Nano, item.Ts)
		if ts.IsZero() {
			ts, _ = time.Parse(time.RFC3339, item.Ts)
		}
		if ts.IsZero() {
			ts = time.Now()
		}
		s.logStore.Write(logs.Entry{
			Ts:        ts,
			Level:     item.Level,
			Component: nvlStr(item.Component, "agent"),
			NodeName:  item.NodeName,
			Domain:    item.Domain,
			Method:    item.Method,
			Path:      item.Path,
			Status:    item.Status,
			IP:        item.IP,
			LatencyMs: item.LatencyMs,
			Bytes:     item.Bytes,
			Message:   item.Message,
			Referrer:  item.Referrer,
			RequestID: item.RequestID,
		})
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalBans(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		IP        string `json:"ip"`
		Domain    string `json:"domain"`
		Reason    string `json:"reason"`
		Source    string `json:"source"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	for _, b := range batch {
		src := b.Source
		if src == "" {
			src = "agent"
		}
		var exp any
		if b.ExpiresAt != "" {
			exp = b.ExpiresAt
		}
		s.db.Exec( //nolint:errcheck
			`INSERT OR IGNORE INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
			fmt.Sprintf("%s-%s-%s", b.IP, b.Domain, b.Source), b.IP, b.Domain, b.Reason, src, exp,
		)
	}
	if s.wsManager != nil {
		go s.wsManager.PushBans(context.Background())
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalThreats(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		IP       string `json:"ip"`
		Scenario string `json:"scenario"`
		Origin   string `json:"origin"`
		Type     string `json:"type"`
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	coreName := s.callerNodeName(r)
	changed := false
	for _, t := range batch {
		if t.IP == "" {
			continue
		}
		typ := nvlStr(t.Type, "ban")
		res, err := s.db.Exec(
			`INSERT INTO security_threats (ip, scenario, origin, type, duration, core_name) VALUES (?,?,?,?,?,?)
			 ON CONFLICT (ip, scenario) DO UPDATE SET
			   origin = excluded.origin, type = excluded.type, duration = excluded.duration,
			   core_name = excluded.core_name, occurrences = occurrences + 1, last_seen_at = CURRENT_TIMESTAMP`,
			t.IP, t.Scenario, t.Origin, typ, t.Duration, coreName,
		)
		if err != nil {
			continue
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			changed = true
		}
		if strings.EqualFold(typ, "ban") {
			id := "crowdsec:" + t.IP
			reason := t.Scenario
			if reason == "" {
				reason = "CrowdSec ban"
			}
			var expires any
			if d := strings.TrimSpace(t.Duration); d != "" && d != "-1" && d != "0" {
				if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
					expires = time.Now().Add(parsed).UTC().Format(time.RFC3339)
				}
			}
			if res, err := s.db.Exec(
				`INSERT OR REPLACE INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
				id, t.IP, "", reason, "crowdsec", expires,
			); err == nil {
				if rows, _ := res.RowsAffected(); rows > 0 {
					s.db.Exec( //nolint:errcheck
						`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?,?,'banned',?,?,?)`,
						t.IP, "", reason, "crowdsec", id)
				}
				changed = true
			}
		}
	}
	if changed && s.wsManager != nil {
		go s.wsManager.PushBans(context.Background())
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalCVEs(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		BackendURL  string  `json:"backend_url"`
		CVEID       string  `json:"cve_id"`
		CVSSScore   float64 `json:"cvss_score"`
		Description string  `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	coreName := s.callerNodeName(r)
	for _, c := range batch {
		s.db.Exec( //nolint:errcheck
			`INSERT INTO security_cves (backend_url, cve_id, cvss_score, description, core_name) VALUES (?,?,?,?,?)
			 ON CONFLICT (backend_url, cve_id) DO UPDATE SET core_name = excluded.core_name`,
			c.BackendURL, c.CVEID, c.CVSSScore, c.Description, coreName,
		)
	}
	w.WriteHeader(http.StatusAccepted)
}

// callerNodeName retrouve le Core/Agent émetteur à partir du token d'appairage
// utilisé pour authentifier la requête (route protégée par RequireBearerToken).
func (s *Server) callerNodeName(r *http.Request) string {
	tokenStr := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tokenStr == "" {
		return ""
	}
	var nodeName string
	s.db.QueryRowContext(r.Context(), //nolint:errcheck
		`SELECT node_name FROM tokens WHERE token_hash = ? OR token = ?`,
		auth.HashNodeToken(tokenStr), tokenStr,
	).Scan(&nodeName)
	return nodeName
}

func nvlStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

