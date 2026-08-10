// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ssrf fournit des garde-fous contre les URL sortantes dangereuses.
package ssrf

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// AllowPrivateEnv retourne true si la variable d'environnement vaut 1/true/yes.
func AllowPrivateEnv(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}

// ValidateHTTPURL refuse schémas non http(s), loopback, link-local, metadata ;
// RFC1918/ULA sauf si allowPrivate.
func ValidateHTTPURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URL invalide")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("schéma non autorisé (http/https uniquement)")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("hôte manquant")
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "metadata.google.internal" ||
		strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("hôte interdit (SSRF)")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ipAllowed(ip, allowPrivate) {
			return fmt.Errorf("adresse IP interdite (SSRF)")
		}
		return nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("résolution DNS: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("aucune adresse pour l'hôte")
	}
	for _, ip := range addrs {
		if !ipAllowed(ip, allowPrivate) {
			return fmt.Errorf("adresse résolue interdite (SSRF): %s", ip)
		}
	}
	return nil
}

func ipAllowed(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("169.254.169.253")) {
		return false
	}
	if !allowPrivate && ip.IsPrivate() {
		return false
	}
	return true
}
