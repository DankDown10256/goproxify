// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcpaccess

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// backendSettingKey liste les destinations (IP, CIDR, hôte exact ou "*.suffixe") vers lesquelles
// un outil MCP peut pointer un proxy. Un agent manipulé par prompt injection ne peut ainsi pas
// rediriger le trafic vers un backend externe. Liste explicitement vide = pas de restriction.
const backendSettingKey = "mcp.allowed_backends"

const defaultAllowedBackends = `["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","::1/128","fc00::/7","*.internal","*.local","*.svc","*.cluster.local"]`

// AllowedBackends retourne la liste des destinations de backend autorisées via MCP.
func AllowedBackends(db *sql.DB) []string {
	var out []string
	_ = json.Unmarshal([]byte(admindb.GetSetting(db, backendSettingKey, defaultAllowedBackends)), &out)
	return out
}

// SetAllowedBackends remplace la liste des destinations autorisées.
func SetAllowedBackends(db *sql.DB, entries []string) error {
	cleaned := make([]string, 0, len(entries))
	for _, e := range entries {
		if e = strings.TrimSpace(e); e != "" {
			cleaned = append(cleaned, e)
		}
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return err
	}
	return admindb.SetSetting(db, backendSettingKey, string(b))
}

// IsValidBackendEntry valide une entrée avant écriture.
func IsValidBackendEntry(s string) bool {
	if IsValidIPOrCIDR(s) {
		return true
	}
	h := strings.TrimPrefix(s, "*.")
	return h != "" && !strings.ContainsAny(h, "/:*@ ") && !strings.HasPrefix(h, ".")
}

// CheckBackend refuse un backend hors allowlist. Les noms d'hôte à label unique (services
// Docker/Kubernetes) ne sont jamais routables sur Internet et sont toujours acceptés.
func CheckBackend(db *sql.DB, backend string) error {
	if db == nil {
		return nil
	}
	return checkBackend(AllowedBackends(db), backend)
}

func checkBackend(allow []string, backend string) error {
	if len(allow) == 0 {
		return nil
	}
	host := backendHost(backend)
	if host == "" {
		return fmt.Errorf("backend invalide: %q", backend)
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, e := range allow {
			if matchIPEntry(e, ip) {
				return nil
			}
		}
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if !strings.Contains(host, ".") {
			return nil
		}
		for _, e := range allow {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == host || (strings.HasPrefix(e, "*.") && strings.HasSuffix(host, e[1:])) {
				return nil
			}
		}
	}
	return fmt.Errorf("backend %q hors de l'allowlist MCP des destinations (Accès MCP → backends autorisés)", backend)
}

func matchIPEntry(entry string, ip net.IP) bool {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		_, n, err := net.ParseCIDR(entry)
		return err == nil && n.Contains(ip)
	}
	e := net.ParseIP(entry)
	return e != nil && e.Equal(ip)
}

func backendHost(backend string) string {
	backend = strings.TrimSpace(backend)
	if !strings.Contains(backend, "://") {
		backend = "tcp://" + backend
	}
	u, err := url.Parse(backend)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
