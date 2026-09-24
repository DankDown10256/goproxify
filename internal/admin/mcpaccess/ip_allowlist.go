// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package mcpaccess porte la configuration du périmètre d'accès MCP
// (allowlist d'IP sources) — paquet neutre partagé par internal/admin/mcp
// (application du contrôle) et internal/admin/api (édition côté admin), afin
// d'éviter le cycle d'import mcp ↔ api.
package mcpaccess

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/audit"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// settingKey est la clé de configuration (table settings) listant les IP/CIDR
// autorisés à appeler /mcp. Liste vide = pas de restriction (comportement historique).
const settingKey = "mcp.allowed_ips"

// AllowedIPs retourne la liste des IP/CIDR autorisés à utiliser le MCP.
func AllowedIPs(db *sql.DB) []string {
	raw := admindb.GetSetting(db, settingKey, "[]")
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// SetAllowedIPs remplace la liste des IP/CIDR autorisés.
func SetAllowedIPs(db *sql.DB, ips []string) error {
	cleaned := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			cleaned = append(cleaned, ip)
		}
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return err
	}
	return admindb.SetSetting(db, settingKey, string(b))
}

// IsValidIPOrCIDR valide une entrée d'allowlist avant écriture.
func IsValidIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// Allowed vérifie que l'IP appelante figure dans l'allowlist (ou qu'elle est vide).
func Allowed(db *sql.DB, r *http.Request) bool {
	if db == nil {
		return true
	}
	allowlist := AllowedIPs(db)
	if len(allowlist) == 0 {
		return true
	}
	clientIP := net.ParseIP(hostOnly(audit.IPFrom(r)))
	if clientIP == nil {
		return false
	}
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil && ip.Equal(clientIP) {
				return true
			}
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(clientIP) {
			return true
		}
	}
	return false
}

// hostOnly retire un éventuel port ("1.2.3.4:5678" → "1.2.3.4").
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
