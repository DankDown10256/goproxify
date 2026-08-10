// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package waf implémente un Web Application Firewall natif Go inspiré de l'OWASP CRS-4.
// Pas de dépendance ModSecurity/CGO — détection par expressions régulières compilées.
package waf

import (
	"regexp"
)

// Rule représente une règle WAF.
type Rule struct {
	ID       int
	Category string
	Severity Severity
	Pattern  *regexp.Regexp
	Targets  []Target // où chercher (URI, body, headers, args...)
	Message  string
}

// Severity classe la sévérité d'une correspondance.
type Severity int

const (
	SevCritical Severity = iota + 1
	SevHigh
	SevMedium
	SevLow
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Target désigne où appliquer la règle.
type Target int

const (
	TargetURI     Target = iota + 1
	TargetArgs             // query string values
	TargetBody             // request body
	TargetHeaders          // tous les headers
	TargetCookies          // valeurs des cookies
)

// DefaultRules retourne l'ensemble des règles OWASP CRS-4 simplifiées.
func DefaultRules() []Rule {
	return []Rule{
		// --- SQLi (CRS 942xxx) ---
		{
			ID: 942100, Category: "sqli", Severity: SevCritical,
			Pattern: mustCompile(`(?i)(union[\s\+]+(?:all\s+)?select|select[\s\+]+.*from|insert[\s\+]+into|update[\s\+]+\w+[\s\+]+set|delete[\s\+]+from|drop[\s\+]+(?:table|database)|truncate[\s\+]+table|exec(?:ute)?[\s\(]+|xp_\w+|sp_\w+)`),
			Targets: []Target{TargetArgs, TargetBody, TargetURI},
			Message: "SQL Injection détectée",
		},
		{
			ID: 942110, Category: "sqli", Severity: SevHigh,
			Pattern: mustCompile(`(?i)('[\s]*(?:or|and)[\s]*'?[\w\s]*'?[\s]*=[\s]*'?[\w\s]*'?|'[\s]*--[\s]|;[\s]*--[\s]|\/\*[\s\S]*?\*\/)`),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "SQL Injection (opérateurs logiques) détectée",
		},
		{
			ID: 942120, Category: "sqli", Severity: SevHigh,
			Pattern: mustCompile(`(?i)\b(?:benchmark|sleep|waitfor[\s]+delay|pg_sleep|dbms_pipe\.receive_message)\b`),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "Blind SQL Injection (time-based) détectée",
		},

		// --- XSS (CRS 941xxx) ---
		{
			ID: 941100, Category: "xss", Severity: SevCritical,
			Pattern: mustCompile(`(?i)<[\s]*script[\s>]|javascript[\s]*:|on(?:load|error|click|mouse\w+|focus|blur|key\w+|submit|change|input|reset|select)[\s]*=`),
			Targets: []Target{TargetArgs, TargetBody, TargetURI, TargetHeaders},
			Message: "XSS détecté",
		},
		{
			ID: 941110, Category: "xss", Severity: SevHigh,
			Pattern: mustCompile(`(?i)<[\s]*(?:img|iframe|embed|object|svg|video|audio|source|link|meta)[\s>]`),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "XSS (balises HTML dangereuses) détecté",
		},
		{
			ID: 941120, Category: "xss", Severity: SevMedium,
			Pattern: mustCompile(`(?i)(?:document\.(?:cookie|write|location)|window\.location|eval[\s]*\(|(?:set|get)Attribute[\s]*\()`),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "XSS (DOM manipulation) détecté",
		},

		// --- Path Traversal (CRS 930xxx) ---
		{
			ID: 930100, Category: "lfi", Severity: SevCritical,
			Pattern: mustCompile(`(?:\.\.[\\/]){2,}|(?:%2e%2e[\\/]){2,}|(?:%2e%2e%2f){2,}|(?:\.\./){2,}|(?:\.\.\\){2,}`),
			Targets: []Target{TargetURI, TargetArgs},
			Message: "Path Traversal détecté",
		},
		{
			ID: 930110, Category: "lfi", Severity: SevHigh,
			Pattern: mustCompile(`(?i)(?:/etc/(?:passwd|shadow|hosts|group)|/proc/self|/var/log|/tmp/|\\windows\\system32|\\boot\.ini|c:\\windows)`),
			Targets: []Target{TargetURI, TargetArgs, TargetBody},
			Message: "LFI (fichiers sensibles) détecté",
		},

		// --- RCE / Command Injection (CRS 932xxx) ---
		{
			ID: 932100, Category: "rce", Severity: SevCritical,
			Pattern: mustCompile("(?i)(?:;|\\||`|&&|\\$\\(|\\$\\{|>[\\s]*/dev/)[\\s]*(?:bash|sh|cmd|powershell|python|perl|ruby|php|wget|curl|nc|ncat|netcat|chmod|chown|sudo|su|rm[\\s]+-rf)"),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "Command Injection détectée",
		},
		{
			ID: 932110, Category: "rce", Severity: SevHigh,
			Pattern: mustCompile(`(?i)(?:\$\{IFS\}|\$\{@\}|\$\([[:space:]]*\)|(?:bash|sh)[\s]+-[ci][\s]+)`),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "RCE (shell bypass) détecté",
		},

		// --- PHP/Server-Side Injection ---
		{
			ID: 933100, Category: "php", Severity: SevCritical,
			Pattern: mustCompile(`(?i)(?:<\?php|<\?=|eval[\s]*\(|base64_decode[\s]*\(|system[\s]*\(|passthru[\s]*\(|popen[\s]*\(|proc_open[\s]*\(|shell_exec[\s]*\()`),
			Targets: []Target{TargetArgs, TargetBody, TargetURI},
			Message: "PHP Injection détectée",
		},

		// --- SSRF (CRS 934xxx) ---
		{
			ID: 934100, Category: "ssrf", Severity: SevHigh,
			Pattern: mustCompile(`(?i)(?:(?:file|gopher|dict|ldap|ftp)://|@[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}|(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1)(?::\d+)?)`),
			Targets: []Target{TargetArgs, TargetBody},
			Message: "SSRF potentiel détecté",
		},

		// --- Protocol Violations (CRS 920xxx) ---
		{
			ID: 920100, Category: "protocol", Severity: SevMedium,
			Pattern: mustCompile(`(?i)(?:\r\n|\r|\n)(?:content-type|content-length|transfer-encoding|host):`),
			Targets: []Target{TargetHeaders},
			Message: "HTTP Header Injection détecté",
		},

		// --- Scanner Detection (CRS 913xxx) ---
		{
			ID: 913100, Category: "scanner", Severity: SevMedium,
			Pattern: mustCompile(`(?i)(?:nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|feroxbuster|nuclei|burpsuite|acunetix|nessus|openvas|wfuzz|hydra|medusa|metasploit|havij|pangolin|sqlninja)`),
			Targets: []Target{TargetHeaders},
			Message: "Scanner de sécurité détecté",
		},
	}
}

func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
