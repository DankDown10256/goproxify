// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestExpandVars(t *testing.T) {
	vars := map[string]string{"country": "FR", "lang": "fr"}
	cases := []struct{ in, want string }{
		{"no vars", "no vars"},
		{"hello ${country}", "hello FR"},
		{"${lang}-${country}", "fr-FR"},
		{"${unknown}", "${unknown}"},
		{"${country}${lang}", "FRfr"},
	}
	for _, tc := range cases {
		got := ExpandVars(tc.in, vars)
		if got != tc.want {
			t.Errorf("ExpandVars(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveVar_Header(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Country", "DE")
	v := router.RequestVar{
		Name: "country", Source: "header", Key: "X-Country",
		Cases: []router.RequestVarCase{
			{Pattern: "FR", Value: "french"},
			{Pattern: "DE", Value: "german"},
		},
		Default: "other",
	}
	got := resolveVar(req, v)
	if got != "german" {
		t.Errorf("got %q, want %q", got, "german")
	}
}

func TestResolveVar_Default(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	v := router.RequestVar{
		Name: "env", Source: "header", Key: "X-Env",
		Cases:   []router.RequestVarCase{{Pattern: "prod", Value: "production"}},
		Default: "development",
	}
	got := resolveVar(req, v)
	if got != "development" {
		t.Errorf("got %q, want %q", got, "development")
	}
}

func TestResolveVar_Regex(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9")
	v := router.RequestVar{
		Name: "lang", Source: "header", Key: "Accept-Language",
		Cases: []router.RequestVarCase{
			{Pattern: `^(fr)`, Value: "french", Regex: true},
			{Pattern: `^(en)`, Value: "english", Regex: true},
		},
		Default: "other",
	}
	got := resolveVar(req, v)
	if got != "french" {
		t.Errorf("got %q, want %q", got, "french")
	}
}

func TestResolveRequestVars_Middleware(t *testing.T) {
	vars := []router.RequestVar{
		{Name: "role", Source: "header", Key: "X-Role", Default: "guest"},
	}
	var capturedVars map[string]string
	h := ResolveRequestVars(vars)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedVars = GetRequestVars(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Role", "admin")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if capturedVars["role"] != "admin" {
		t.Errorf("got %q, want %q", capturedVars["role"], "admin")
	}
}
