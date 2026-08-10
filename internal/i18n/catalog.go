// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package i18n

import "fmt"

// catalogs holds locale → key → message (EN is the source of truth).
var catalogs = map[string]map[string]string{
	LocaleEN: messagesEN,
	LocaleFR: messagesFR,
	LocaleES: messagesES,
	LocaleDE: messagesDE,
}

// T returns the localized message for key.
// Missing non-EN entries fall back to English; unknown keys return the key itself.
func T(locale, key string, args ...any) string {
	loc := Parse(locale)
	msg := lookup(loc, key)
	if msg == "" && loc != LocaleEN {
		msg = lookup(LocaleEN, key)
	}
	if msg == "" {
		return key
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

func lookup(locale, key string) string {
	if m, ok := catalogs[locale]; ok {
		return m[key]
	}
	return ""
}
