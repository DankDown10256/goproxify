// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package appinv

import (
	"net/http"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestFromHeaders(t *testing.T) {
	got := FromHeaders(hdr(
		"Server", "Apache/2.4.58 (Debian) PHP/8.2.12 OpenSSL/3.0.11",
		"X-Powered-By", "PHP/8.2.12",
		"X-AspNet-Version", "4.0.30319",
	))
	by := map[string]Finding{}
	for _, f := range got {
		by[f.Product+"|"+f.Evidence] = f
	}
	for _, tc := range []struct{ key, cpe, ver string }{
		{"apache http server|Server: Apache/2.4.58", "apache:http_server", "2.4.58"},
		{"php|Server: PHP/8.2.12", "php:php", "8.2.12"},
		{"openssl|Server: OpenSSL/3.0.11", "openssl:openssl", "3.0.11"},
		{"php|X-Powered-By: PHP/8.2.12", "php:php", "8.2.12"},
		{"asp.net|X-AspNet-Version: 4.0.30319", "", "4.0.30319"},
	} {
		f, ok := by[tc.key]
		if !ok || f.CPE != tc.cpe || f.Version != tc.ver || f.Source != SourceHeaders {
			t.Errorf("%s : %+v (ok=%v)", tc.key, f, ok)
		}
	}
	if len(got) != 5 {
		t.Errorf("%d résultats : %+v", len(got), got)
	}
}

func TestFromHeadersGivesNothingForUnknownOrVersionless(t *testing.T) {
	if got := FromHeaders(hdr("Server", "cloudflare")); len(got) != 0 {
		t.Errorf("un nom inconnu et sans version n'est pas consigné : %+v", got)
	}
	got0 := FromHeaders(hdr("Server", "Microsoft-HTTPAPI/2.0"))
	if len(got0) != 1 || got0[0].Product != "" || got0[0].Evidence != "Server: Microsoft-HTTPAPI/2.0" || got0[0].Coverage() != CoverageUnknown || got0[0].Name() != "microsoft-httpapi" {
		t.Errorf("un logiciel versionné inconnu est consigné sans produit : %+v", got0)
	}
	got := FromHeaders(hdr("Server", "nginx"))
	if len(got) != 1 || got[0].Product != "nginx" || got[0].Version != "" {
		t.Errorf("nginx sans version : %+v", got)
	}
	if got := FromHeaders(hdr("Server", "Microsoft-IIS/10.0")); len(got) != 1 || got[0].Version != "10.0" || !got[0].Partial {
		t.Errorf("IIS : %+v", got)
	}
	if got := FromHeaders(hdr("Server", "OpenSSL/1.1.1k")); len(got) != 1 || got[0].Version != "1.1.1k" {
		t.Errorf("OpenSSL garde sa lettre : %+v", got)
	}
	if got := FromHeaders(hdr("Server", "nginx/1.25.3-fake")); len(got) != 1 || got[0].Version != "1.25.3" {
		t.Errorf("suffixe ignoré : %+v", got)
	}
}

func TestXGenerator(t *testing.T) {
	got := FromHeaders(hdr("X-Generator", "Drupal 10 (https://www.drupal.org)"))
	if len(got) != 1 || got[0].Product != "drupal" || got[0].CPE != "drupal:drupal" || got[0].Version != "" {
		t.Errorf("une version à un seul chiffre n'est pas précise : %+v", got)
	}
	got = FromHeaders(hdr("X-Generator", "Drupal 10.2.3 (https://www.drupal.org)"))
	if len(got) != 1 || got[0].Version != "10.2.3" {
		t.Errorf("Drupal : %+v", got)
	}
}

func TestHeaderSignature(t *testing.T) {
	if HeaderSignature(hdr("Content-Type", "text/html")) != "" {
		t.Error("aucun en-tête qui compte : signature vide")
	}
	a := HeaderSignature(hdr("Server", "nginx/1.25.3"))
	if a == "" || a == HeaderSignature(hdr("Server", "nginx/1.25.4")) {
		t.Error("la signature suit la valeur")
	}
}

func TestFromHTML(t *testing.T) {
	doc := `<!doctype html><html><head><title>x</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<meta name="generator" content="WordPress 6.4.2" />
<META CONTENT='Hugo 0.121.2' NAME='generator'>
<meta name="generator" content="Joomla! - Open Source Content Management">
<meta name="generator" content="Mon CMS maison 1.0">
</head></html>`
	got := FromHTML([]byte(doc))
	by := map[string]Finding{}
	for _, f := range got {
		by[f.Product] = f
	}
	if f := by["wordpress"]; f.CPE != "wordpress:wordpress" || f.Version != "6.4.2" || f.Source != SourceHTML || !strings.Contains(f.Evidence, "WordPress 6.4.2") {
		t.Errorf("WordPress : %+v", f)
	}
	if f := by["hugo"]; f.CPE != "gohugo:hugo" || f.Version != "0.121.2" {
		t.Errorf("Hugo, attributs dans l'autre ordre : %+v", f)
	}
	if f, ok := by["joomla"]; !ok || f.CPE != "" || f.Version != "" {
		t.Errorf("Joomla est reconnu sans version ni CPE : %+v", f)
	}
	if len(got) != 3 {
		t.Errorf("un générateur inconnu n'est pas inventé : %+v", got)
	}
}
