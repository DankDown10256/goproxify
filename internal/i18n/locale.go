// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package i18n provides locale resolution and message catalogs (EN source of truth).
package i18n

import (
	"strconv"
	"strings"
)

// Supported locales.
const (
	LocaleEN = "en"
	LocaleFR = "fr"
	LocaleES = "es"
	LocaleDE = "de"
)

// Default is English (product primary locale).
const Default = LocaleEN

// Parse normalizes a locale tag to a supported locale; unknown values become Default.
func Parse(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	switch {
	case s == LocaleFR || strings.HasPrefix(s, "fr-") || strings.HasPrefix(s, "fr_"):
		return LocaleFR
	case s == LocaleES || strings.HasPrefix(s, "es-") || strings.HasPrefix(s, "es_"):
		return LocaleES
	case s == LocaleDE || strings.HasPrefix(s, "de-") || strings.HasPrefix(s, "de_"):
		return LocaleDE
	case s == LocaleEN || strings.HasPrefix(s, "en-") || strings.HasPrefix(s, "en_") || s == "":
		return LocaleEN
	default:
		return Default
	}
}

// FromAcceptLanguage picks a supported locale from an Accept-Language header.
// Uses the highest q-value among supported tags; falls back to Default.
func FromAcceptLanguage(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return Default
	}

	bestLoc := ""
	bestQ := -1.0

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag := part
		q := 1.0
		if i := strings.IndexByte(part, ';'); i >= 0 {
			tag = strings.TrimSpace(part[:i])
			params := part[i+1:]
			for _, p := range strings.Split(params, ";") {
				p = strings.TrimSpace(p)
				if len(p) >= 2 && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=' {
					if v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64); err == nil {
						q = v
					}
				}
			}
		}
		loc := localeFromTag(tag)
		if loc == "" {
			continue
		}
		if q > bestQ {
			bestQ = q
			bestLoc = loc
		}
	}
	if bestLoc == "" {
		return Default
	}
	return bestLoc
}

func localeFromTag(tag string) string {
	tag = strings.TrimSpace(strings.ToLower(tag))
	if tag == "*" {
		return LocaleEN
	}
	base := tag
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		base = tag[:i]
	}
	switch base {
	case LocaleFR:
		return LocaleFR
	case LocaleES:
		return LocaleES
	case LocaleDE:
		return LocaleDE
	case LocaleEN:
		return LocaleEN
	default:
		return ""
	}
}
