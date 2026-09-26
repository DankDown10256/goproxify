// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Policy regroupe les restrictions d'accès du portail, définies par l'Admin.
type Policy struct {
	HoursEnabled        bool     `json:"hours_enabled"`
	Days                []int    `json:"days,omitempty"`       // 0 = dimanche … 6 = samedi
	StartTime           string   `json:"start_time,omitempty"` // HH:MM
	EndTime             string   `json:"end_time,omitempty"`   // HH:MM, après StartTime
	Timezone            string   `json:"timezone,omitempty"`   // nom IANA ; vide = UTC
	IPAllow             []string `json:"ip_allow,omitempty"`   // IP ou CIDR ; vide = pas de restriction
	IdleTimeoutMin      int      `json:"idle_timeout_min,omitempty"`
	RecordSessions      bool     `json:"record_sessions,omitempty"`       // enregistre la sortie des terminaux
	RecordRetentionDays int      `json:"record_retention_days,omitempty"` // 0 = conservation illimitée
}

func parseHM(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("heure %q invalide (HH:MM attendu)", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// Validate vérifie la politique avant de l'enregistrer.
func (p Policy) Validate() error {
	if p.HoursEnabled {
		if len(p.Days) == 0 {
			return fmt.Errorf("choisissez au moins un jour")
		}
		for _, d := range p.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("jour %d invalide", d)
			}
		}
		start, err := parseHM(p.StartTime)
		if err != nil {
			return err
		}
		end, err := parseHM(p.EndTime)
		if err != nil {
			return err
		}
		if end <= start {
			return fmt.Errorf("l'heure de fin doit suivre l'heure de début")
		}
		if p.Timezone != "" {
			if _, err := time.LoadLocation(p.Timezone); err != nil {
				return fmt.Errorf("fuseau %q inconnu", p.Timezone)
			}
		}
	}
	for _, e := range p.IPAllow {
		if _, _, err := parseIPOrCIDR(e); err != nil {
			return err
		}
	}
	if p.RecordRetentionDays < 0 || p.RecordRetentionDays > 3650 {
		return fmt.Errorf("conservation entre 0 et 3650 jours")
	}
	if p.IdleTimeoutMin < 0 || p.IdleTimeoutMin > 1440 {
		return fmt.Errorf("inactivité entre 0 et 1440 minutes")
	}
	return nil
}

func parseIPOrCIDR(s string) (net.IP, *net.IPNet, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil, fmt.Errorf("plage IP %q invalide", s)
		}
		return ip, n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, nil, fmt.Errorf("adresse IP %q invalide", s)
	}
	return ip, nil, nil
}

// AllowsTime indique si une nouvelle session est permise à cet instant.
func (p Policy) AllowsTime(now time.Time) bool {
	if !p.HoursEnabled {
		return true
	}
	loc := time.UTC
	if p.Timezone != "" {
		l, err := time.LoadLocation(p.Timezone)
		if err != nil {
			return false
		}
		loc = l
	}
	local := now.In(loc)
	dayOK := false
	for _, d := range p.Days {
		if d == int(local.Weekday()) {
			dayOK = true
			break
		}
	}
	start, err1 := parseHM(p.StartTime)
	end, err2 := parseHM(p.EndTime)
	if !dayOK || err1 != nil || err2 != nil {
		return false
	}
	m := local.Hour()*60 + local.Minute()
	return m >= start && m < end
}

// AllowsIP indique si l'adresse est autorisée ; sans liste, tout est permis.
func (p Policy) AllowsIP(ip net.IP) bool {
	if len(p.IPAllow) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, e := range p.IPAllow {
		allowed, n, err := parseIPOrCIDR(e)
		if err != nil {
			continue
		}
		if n != nil && n.Contains(ip) || n == nil && allowed.Equal(ip) {
			return true
		}
	}
	return false
}

// clientIP retourne l'adresse du client ; derrière la passerelle (pair local), la dernière entrée
// de X-Forwarded-For, ajoutée par la passerelle elle-même, fait foi.
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && peer.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip
			}
		}
	}
	return peer
}

// denyReason retourne le motif de refus d'une nouvelle connexion, ou "" si elle est permise.
func (p Policy) denyReason(ip net.IP, now time.Time) string {
	if !p.AllowsIP(ip) {
		return "adresse IP non autorisée"
	}
	if !p.AllowsTime(now) {
		return "accès hors plage horaire autorisée"
	}
	return ""
}

// policyBlocks refuse la requête (403) quand la politique du portail l'interdit.
func (h *HTTPServer) policyBlocks(w http.ResponseWriter, r *http.Request) bool {
	if h.policy == nil {
		return false
	}
	why := h.policy().denyReason(clientIP(r), time.Now())
	if why == "" {
		return false
	}
	h.emitAudit(AuditEvent{Actor: clientIP(r).String(), Success: false, Detail: "policy: " + why})
	http.Error(w, why, http.StatusForbidden)
	return true
}
