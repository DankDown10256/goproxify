// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestApplyProxyRedirects(t *testing.T) {
	cases := []struct {
		name  string
		value string
		rules []router.ProxyRedirect
		want  string
	}{
		{
			name:  "prefix match",
			value: "http://backend:8080/dashboard",
			rules: []router.ProxyRedirect{{From: "http://backend:8080", To: "https://app.example.fr"}},
			want:  "https://app.example.fr/dashboard",
		},
		{
			name:  "no match returns original",
			value: "http://other:9090/path",
			rules: []router.ProxyRedirect{{From: "http://backend:8080", To: "https://app.example.fr"}},
			want:  "http://other:9090/path",
		},
		{
			name:  "regex with capture",
			value: "http://backend:8080/api/v1/users",
			rules: []router.ProxyRedirect{
				{From: `^http://backend:8080(/.*)?$`, To: "https://app.example.fr$1", Regex: true},
			},
			want: "https://app.example.fr/api/v1/users",
		},
		{
			name:  "first matching rule wins",
			value: "http://backend:8080/path",
			rules: []router.ProxyRedirect{
				{From: "http://backend:8080", To: "https://first.example.fr"},
				{From: "http://backend:8080", To: "https://second.example.fr"},
			},
			want: "https://first.example.fr/path",
		},
		{
			name:  "empty rules returns original",
			value: "http://backend:8080/path",
			rules: nil,
			want:  "http://backend:8080/path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applyProxyRedirects(c.value, c.rules)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
