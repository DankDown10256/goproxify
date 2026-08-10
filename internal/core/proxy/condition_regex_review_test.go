// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestReviewP1_ConditionRegexPrecompiled(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	route := &router.Route{
		ID:   "cond",
		Host: "app.test",
		Type: router.RouteHTTP,
		Backends: []router.Backend{
			{URL: "http://127.0.0.1:1"}, // ne doit pas être atteint
		},
		Conditions: []router.Condition{{
			Type:    "header",
			Name:    "X-Env",
			Value:   "^prod$",
			Regex:   true,
			Backend: backend.URL,
		}},
	}
	h := NewHandler(route, NewBackendHealth(slog.Default()), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())
	if len(h.conditionRes) != 1 || h.conditionRes[0] == nil {
		t.Fatal("regex de condition doit être précompilée")
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Header.Set("X-Env", "prod")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}
