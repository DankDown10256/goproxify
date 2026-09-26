// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package errorpages

import (
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/i18n"
)

// Vars contient les variables injectées dans un template adaptable.
type Vars struct {
	Status    int
	Title     string
	Message   string
	Host      string
	RequestID string
	LogURL    string
}

// VarsFor construit les variables pour un code HTTP (catalogue natif + requête).
// acceptLanguage is the raw Accept-Language header (may be empty → English).
func VarsFor(status int, host, reqID, acceptLanguage string) Vars {
	e := infoFor(status, i18n.FromAcceptLanguage(acceptLanguage))
	return Vars{
		Status:    status,
		Title:     e.title,
		Message:   e.message,
		Host:      host,
		RequestID: reqID,
		LogURL:    buildLogURL(reqID),
	}
}

// ApplyTemplate remplace les placeholders {{…}} dans le corps HTML.
// Placeholders : status, title, message, host, request_id, log_url.
// Les valeurs texte sont échappées HTML (sauf le corps qui est déjà du HTML auteur).
func ApplyTemplate(body string, v Vars) string {
	repl := map[string]string{
		"status":     strconv.Itoa(v.Status),
		"title":      html.EscapeString(v.Title),
		"message":    html.EscapeString(v.Message),
		"host":       html.EscapeString(v.Host),
		"request_id": html.EscapeString(v.RequestID),
		"log_url":    html.EscapeString(v.LogURL),
	}
	out := body
	for key, val := range repl {
		out = strings.ReplaceAll(out, "{{"+key+"}}", val)
		out = strings.ReplaceAll(out, "{{ "+key+" }}", val)
	}
	return out
}

// ResolveCustom cherche un binding custom pour status.
// Retourne (html, redirectURL, ok).
// Ordre : templates[code|Nxx] → pages[code|Nxx] (URL ou HTML legacy).
// acceptLanguage drives {{title}}/{{message}} from the native catalog when placeholders are used.
func ResolveCustom(cfg interface {
	GetTemplates() map[string]string
	GetPages() map[string]string
}, status int, host, reqID, acceptLanguage string, store *Store) (body string, redirect string, ok bool) {
	if cfg == nil {
		return "", "", false
	}
	keys := []string{fmt.Sprintf("%d", status), fmt.Sprintf("%dxx", status/100)}
	tpls := cfg.GetTemplates()
	for _, k := range keys {
		if id, found := tpls[k]; found && id != "" {
			raw, found := store.GetHTML(id)
			if !found || raw == "" {
				continue
			}
			return ApplyTemplate(raw, VarsFor(status, host, reqID, acceptLanguage)), "", true
		}
	}
	pages := cfg.GetPages()
	for _, k := range keys {
		if val, found := pages[k]; found && val != "" {
			if redir, ok := safeAbsoluteRedirect(val); ok {
				return "", redir, true
			}
			// Legacy HTML inline — aussi passé par ApplyTemplate si placeholders présents.
			return ApplyTemplate(val, VarsFor(status, host, reqID, acceptLanguage)), "", true
		}
	}
	return "", "", false
}

// safeAbsoluteRedirect n'accepte que http(s) absolus sans credentials ni CRLF.
func safeAbsoluteRedirect(val string) (string, bool) {
	val = strings.TrimSpace(val)
	if val == "" || strings.ContainsAny(val, "\r\n") {
		return "", false
	}
	if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
		return "", false
	}
	u, err := url.Parse(val)
	if err != nil || u.Host == "" || u.User != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	return u.String(), true
}
