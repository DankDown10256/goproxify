// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestWantsForwardedHeaderDefaultAll(t *testing.T) {
	if !wantsForwardedHeader(nil, "X-Forwarded-For") {
		t.Fatal("nil route should default to all headers")
	}
	r := &router.Route{}
	if !wantsForwardedHeader(r, "X-Real-IP") {
		t.Fatal("absent headers_manipulation should default to all")
	}
	r.HeadersManipulation = &router.HeadersManipulationConfig{}
	if !wantsForwardedHeader(r, "X-Forwarded-Proto") {
		t.Fatal("nil ForwardedHeaders should default to all")
	}
}

func TestWantsForwardedHeaderExplicit(t *testing.T) {
	r := &router.Route{
		HeadersManipulation: &router.HeadersManipulationConfig{
			ForwardedHeaders: []string{"X-Real-IP", "x-forwarded-for"},
		},
	}
	if !wantsForwardedHeader(r, "X-Real-IP") {
		t.Fatal("expected X-Real-IP")
	}
	if !wantsForwardedHeader(r, "X-Forwarded-For") {
		t.Fatal("expected case-insensitive X-Forwarded-For")
	}
	if wantsForwardedHeader(r, "X-Forwarded-Proto") {
		t.Fatal("X-Forwarded-Proto should be off")
	}
}

func TestWantsForwardedHeaderNone(t *testing.T) {
	r := &router.Route{
		HeadersManipulation: &router.HeadersManipulationConfig{
			ForwardedHeaders: []string{},
		},
	}
	if wantsForwardedHeader(r, "X-Real-IP") {
		t.Fatal("empty list should inject none")
	}
}

func TestApplyForwardedHeadersSelective(t *testing.T) {
	r := &router.Route{
		HeadersManipulation: &router.HeadersManipulationConfig{
			ForwardedHeaders: []string{"X-Forwarded-Host"},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://backend/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "spoofed")
	req.Header.Set("X-Real-IP", "spoofed")
	applyForwardedHeaders(req, r, "app.example.fr")
	if got := req.Header.Get("X-Forwarded-Host"); got != "app.example.fr" {
		t.Fatalf("X-Forwarded-Host: got %q", got)
	}
	if req.Header.Get("X-Forwarded-For") != "" {
		t.Fatal("X-Forwarded-For should be removed when unchecked")
	}
	if req.Header.Get("X-Real-IP") != "" {
		t.Fatal("X-Real-IP should be removed when unchecked")
	}
}

func TestApplyRequestHeaderManipulation(t *testing.T) {
	r := &router.Route{
		HeadersManipulation: &router.HeadersManipulationConfig{
			RequestHideHeader: []string{"Cookie", " Authorization "},
			RequestSetHeader:  map[string]string{"X-App": "goproxify", "Authorization": "Bearer x"},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://backend/", nil)
	req.Header.Set("Cookie", "a=1")
	req.Header.Set("Authorization", "old")
	req.Header.Set("X-Keep", "1")
	applyRequestHeaderManipulation(req, r)
	if req.Header.Get("Cookie") != "" {
		t.Fatal("Cookie should be hidden")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer x" {
		t.Fatalf("Authorization: got %q", got)
	}
	if got := req.Header.Get("X-App"); got != "goproxify" {
		t.Fatalf("X-App: got %q", got)
	}
	if req.Header.Get("X-Keep") != "1" {
		t.Fatal("X-Keep should remain")
	}
}

func TestApplyHTTPVersion(t *testing.T) {
	t11 := &http.Transport{}
	applyHTTPVersion(t11, "1.1")
	if t11.ForceAttemptHTTP2 {
		t.Fatal("1.1 should not ForceAttemptHTTP2")
	}
	if t11.TLSNextProto == nil {
		t.Fatal("1.1 should set TLSNextProto empty map")
	}
	t2 := &http.Transport{}
	applyHTTPVersion(t2, "2")
	if !t2.ForceAttemptHTTP2 {
		t.Fatal("2 should ForceAttemptHTTP2")
	}
}
