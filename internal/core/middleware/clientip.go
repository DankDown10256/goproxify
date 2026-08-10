// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"

	corelog "github.com/vincamok/goproxify/internal/core/logger"
)

// clientIP retourne l'IP client réelle (CF-Connecting-IP / XFF / X-Real-IP / RemoteAddr).
func clientIP(r *http.Request) string {
	return corelog.RealIP(r)
}
