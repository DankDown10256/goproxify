// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
)

// clientIP retourne l'IP client réelle (CF-Connecting-IP / XFF / X-Real-IP / RemoteAddr).
func clientIP(r *http.Request) string {
	return edgelog.RealIP(r)
}
