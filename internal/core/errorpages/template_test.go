// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package errorpages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyTemplatePlaceholders(t *testing.T) {
	body := `<h1>{{status}} {{title}}</h1><p>{{message}}</p><span>{{host}} {{request_id}}</span>`
	got := ApplyTemplate(body, VarsFor(502, "api.example", "req1", "fr"))
	for _, want := range []string{"502", "Passerelle incorrecte", "api.example", "req1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("attendu %q dans %q", want, got)
		}
	}
	if strings.Contains(got, "{{status}}") {
		t.Fatal("placeholder non remplacé")
	}
}

func TestStoreReplaceAllAndAssets(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	id := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	err := s.ReplaceAll([]Template{{
		ID:   id,
		Name: "brand",
		Body: "<html>{{status}}</html>",
		Assets: []Asset{{
			Filename:    "logo.png",
			ContentType: "image/png",
			Content:     []byte{0x89, 0x50, 0x4e, 0x47},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	html, ok := s.GetHTML(id)
	if !ok || html != "<html>{{status}}</html>" {
		t.Fatalf("html=%q ok=%v", html, ok)
	}
	b, ct, ok := s.GetAsset(id, "logo.png")
	if !ok || ct != "image/png" || len(b) != 4 {
		t.Fatalf("asset ok=%v ct=%s len=%d", ok, ct, len(b))
	}
	if _, err := os.Stat(filepath.Join(dir, id, "index.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, id, "logo.png")); err != nil {
		t.Fatal(err)
	}

	if err := s.ReplaceAll(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetHTML(id); ok {
		t.Fatal("template devrait être purgé")
	}
}

func TestStoreGetHTMLDiskFallback(t *testing.T) {
	dir := t.TempDir()
	id := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	tplDir := filepath.Join(dir, id)
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := "<html>from-disk</html>"
	if err := os.WriteFile(filepath.Join(tplDir, "index.html"), []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	got, ok := s.GetHTML(id)
	if !ok || got != want {
		t.Fatalf("got=%q ok=%v", got, ok)
	}
}

func TestResolveCustomTemplate(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	id := "11111111-2222-3333-4444-555555555555"
	_ = s.ReplaceAll([]Template{{ID: id, Body: "ERR {{status}} {{title}}"}})
	cfg := &mockEP{tpl: map[string]string{"5xx": id}}
	body, redir, ok := ResolveCustom(cfg, 502, "h", "r", "fr", s)
	if !ok || redir != "" || body != "ERR 502 Passerelle incorrecte" {
		t.Fatalf("body=%q redir=%q ok=%v", body, redir, ok)
	}
}

func TestResolveCustomRedirect(t *testing.T) {
	cfg := &mockEP{pages: map[string]string{"404": "https://example.com/404"}}
	_, redir, ok := ResolveCustom(cfg, 404, "", "", "", NewStore(t.TempDir()))
	if !ok || redir != "https://example.com/404" {
		t.Fatalf("redir=%q ok=%v", redir, ok)
	}
}

func TestResolveCustomRedirectRejectsBad(t *testing.T) {
	cfg := &mockEP{pages: map[string]string{"404": "javascript:alert(1)"}}
	body, redir, ok := ResolveCustom(cfg, 404, "", "", "", NewStore(t.TempDir()))
	// Traité comme HTML legacy, pas redirect
	if redir != "" {
		t.Fatalf("redir inattendu %q body=%q ok=%v", redir, body, ok)
	}
	cfg2 := &mockEP{pages: map[string]string{"404": "https://user:pass@evil.com/"}}
	_, redir, ok = ResolveCustom(cfg2, 404, "", "", "", NewStore(t.TempDir()))
	if ok && redir != "" {
		t.Fatalf("credentials doivent être rejetées: %q", redir)
	}
}

type mockEP struct {
	tpl   map[string]string
	pages map[string]string
}

func (m *mockEP) GetTemplates() map[string]string { return m.tpl }
func (m *mockEP) GetPages() map[string]string     { return m.pages }
