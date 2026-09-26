// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
)

// legacyCoreAPI garde fonctionnels les scripts écrits avant le renommage Core → Edge :
// paramètre de requête `core` (→ `edge`) et route /api/v1/backups/core (→ /backups/edge).
func legacyCoreAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Has("core") && !q.Has("edge") {
			q.Set("edge", q.Get("core"))
			q.Del("core")
			r.URL.RawQuery = q.Encode()
		}
		if strings.HasSuffix(r.URL.Path, "/backups/core") {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "core") + "edge"
		}
		next.ServeHTTP(w, r)
	})
}
