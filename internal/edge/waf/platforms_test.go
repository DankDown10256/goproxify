// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

var payloads = []string{
	"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "' OR 1=1--", "1 UNION SELECT 1,2,3",
	"admin' --", "../../etc/passwd", "; cat /etc/passwd", "<svg onload=alert(1)>", "1' AND SLEEP(5)--",
}

func status(t *testing.T, cfg *router.WAFConfig, payload string) int {
	t.Helper()
	e := NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := e.Middleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/?q="+url.QueryEscape(payload), nil))
	return rec.Code
}

func TestUnionOfIDsAndPlatformsAndUnknownNames(t *testing.T) {
	ids, unknown := ResolveExclusions([]int{1, 942100}, []string{"WordPress", "auto", "wordprss", "gitea"})
	has := map[int]bool{}
	for _, id := range ids {
		has[id] = true
	}
	for _, want := range []int{1, 941100, 942100, 930100} {
		if !has[want] {
			t.Errorf("règle %d absente de %v", want, ids)
		}
	}
	if len(unknown) != 2 || unknown[0] != "auto" || unknown[1] != "wordprss" {
		t.Errorf("noms inconnus : %v (« auto » n'existe plus : un nom inconnu, signalé et sans effet)", unknown)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("les règles doivent être triées et sans doublon : %v", ids)
		}
	}
}
