// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/vincamok/goproxify/internal/i18n"
)

// Locale resolves the request locale: X-Locale override, then Accept-Language, then en.
func Locale(r *http.Request) string {
	if r == nil {
		return i18n.Default
	}
	if v := r.Header.Get("X-Locale"); v != "" {
		return i18n.Parse(v)
	}
	return i18n.FromAcceptLanguage(r.Header.Get("Accept-Language"))
}

// writeErr writes a localized API error message for the given catalog key.
func writeErr(w http.ResponseWriter, r *http.Request, status int, key string) {
	http.Error(w, i18n.T(Locale(r), key), status)
}
