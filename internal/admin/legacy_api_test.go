// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacyCoreAPI(t *testing.T) {
	var gotPath, gotEdge, gotCore string
	h := legacyCoreAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotEdge, gotCore = r.URL.Path, r.URL.Query().Get("edge"), r.URL.Query().Get("core")
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/proxies?core=abc", nil))
	if gotEdge != "abc" || gotCore != "" {
		t.Fatalf("edge=%q core=%q", gotEdge, gotCore)
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/proxies?core=old&edge=new", nil))
	if gotEdge != "new" {
		t.Fatalf("edge explicite prioritaire : %q", gotEdge)
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/backups/core", nil))
	if gotPath != "/api/v1/backups/edge" {
		t.Fatalf("path=%q", gotPath)
	}
}
