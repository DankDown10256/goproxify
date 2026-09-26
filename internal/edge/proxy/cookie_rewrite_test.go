// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestRewriteCookieAttr_Domain(t *testing.T) {
	cases := []struct {
		raw   string
		rules []router.CookieRewrite
		want  string
	}{
		{
			raw:   "session=abc; Domain=backend.internal; Path=/; HttpOnly",
			rules: []router.CookieRewrite{{From: "backend.internal", To: "app.example.fr"}},
			want:  "session=abc; Domain=app.example.fr; Path=/; HttpOnly",
		},
		{
			raw:   "session=abc; Path=/; HttpOnly",
			rules: []router.CookieRewrite{{From: "backend.internal", To: "app.example.fr"}},
			want:  "session=abc; Path=/; HttpOnly", // no Domain attr — unchanged
		},
		{
			raw:   "token=xyz; Domain=other.com; Secure",
			rules: []router.CookieRewrite{{From: "backend.internal", To: "app.example.fr"}},
			want:  "token=xyz; Domain=other.com; Secure", // no match
		},
		{
			// last attribute (no trailing ;)
			raw:   "session=abc; Path=/; Domain=backend.internal",
			rules: []router.CookieRewrite{{From: "backend.internal", To: "app.example.fr"}},
			want:  "session=abc; Path=/; Domain=app.example.fr",
		},
		{
			// regex rule
			raw:   "session=abc; Domain=api.backend.internal; Path=/",
			rules: []router.CookieRewrite{{From: `^(.*)\.backend\.internal$`, To: "$1.example.fr", Regex: true}},
			want:  "session=abc; Domain=api.example.fr; Path=/",
		},
	}
	for _, c := range cases {
		got := rewriteCookieAttr(c.raw, "Domain", c.rules)
		if got != c.want {
			t.Errorf("rewriteCookieAttr(%q):\n got  %q\n want %q", c.raw, got, c.want)
		}
	}
}

func TestRewriteSetCookieHeaders(t *testing.T) {
	resp := &http.Response{Header: http.Header{
		"Set-Cookie": []string{
			"a=1; Domain=backend.internal; Path=/old",
			"b=2; Domain=backend.internal; Path=/other",
			"c=3; Path=/old",
		},
	}}
	domainRules := []router.CookieRewrite{{From: "backend.internal", To: "app.example.fr"}}
	pathRules := []router.CookieRewrite{{From: "/old", To: "/new"}}
	rewriteSetCookieHeaders(resp, domainRules, pathRules)
	want := []string{
		"a=1; Domain=app.example.fr; Path=/new",
		"b=2; Domain=app.example.fr; Path=/other",
		"c=3; Path=/new",
	}
	got := resp.Header["Set-Cookie"]
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Errorf("cookie[%d]: got %q, want %q", i, got[i], w)
		}
	}
}
