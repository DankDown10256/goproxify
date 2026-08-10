// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"strings"
	"testing"
)

func TestApplyPageTemplateVars(t *testing.T) {
	out := ApplyPageTemplate(
		`<h1>{{brand}}</h1><p>{{user_email}}</p><b>{{ core_name }}</b><div>{{content}}</div><i>{{csrf}}</i>`,
		PageVars{Brand: "GPX", UserEmail: "a@b.c", CoreName: "core1", CSRF: "tok", Content: "<em>ok</em>"},
	)
	for _, want := range []string{"GPX", "a@b.c", "core1", "<em>ok</em>", "tok"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	esc := ApplyPageTemplate(`{{brand}}`, PageVars{Brand: `<img>`})
	if esc != "&lt;img&gt;" {
		t.Fatalf("escape: %q", esc)
	}
}

func TestTemplateStoreReplaceAllAndFallback(t *testing.T) {
	s := NewTemplateStore()
	s.ReplaceAll([]PageTemplate{
		{Key: PageLogin, Body: `<login>{{brand}}</login>`},
		{Key: "unknown", Body: "x"},
		{Key: PageCatalog, Body: ""},
	})
	if _, ok := s.Get(PageLogin); !ok {
		t.Fatal("login")
	}
	if _, ok := s.Get("unknown"); ok {
		t.Fatal("unknown key rejected")
	}
	if _, ok := s.Get(PageCatalog); ok {
		t.Fatal("empty body ignored")
	}
	html, custom := s.ResolvePage(PageVault, PageVars{Brand: "B"}, false)
	if custom {
		t.Fatal("vault should fallback")
	}
	if !strings.Contains(html, `data-page="vault"`) || !strings.Contains(html, "B") {
		t.Fatalf("%s", html)
	}
	s.ReplaceAll(nil)
	if len(s.Snapshot()) != 0 {
		t.Fatal("cleared")
	}
}

func TestRenderIndexCustomLogin(t *testing.T) {
	s := NewTemplateStore()
	if _, spa := s.RenderIndex(PageVars{Brand: "X"}); !spa {
		t.Fatal("default SPA")
	}
	s.ReplaceAll([]PageTemplate{{Key: PageLogin, Body: `<h1>Custom {{brand}}</h1>`}})
	html, spa := s.RenderIndex(PageVars{Brand: "Access"})
	if spa || !strings.Contains(html, "Custom Access") {
		t.Fatalf("spa=%v html=%s", spa, html)
	}
	s.ReplaceAll([]PageTemplate{
		{Key: PageLayout, Body: `<wrap>{{content}}</wrap>`},
		{Key: PageLogin, Body: `IN`},
	})
	html, spa = s.RenderIndex(PageVars{})
	if spa || html != `<wrap>IN</wrap>` {
		t.Fatalf("%q", html)
	}
}
