// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package appinv

import (
	"net/http"
	"regexp"
	"strings"
)

// Sources de l'empreinte des réponses du backend (ADR 0017, étape 2).
const (
	SourceHeaders = "headers"
	SourceHTML    = "html"
)

// serverProducts : les produits qu'un en-tête Server ou X-Powered-By nomme avant la barre oblique (« nginx/1.25.3 »), vers le produit et
// son identifiant CPE. Un nom absent d'ici n'est pas reconnu : rien n'est deviné.
var serverProducts = map[string]known{
	"nginx":             {"nginx", "nginx:nginx"},
	"apache":            {"apache http server", "apache:http_server"},
	"php":               {"php", "php:php"},
	"openresty":         {"openresty", "openresty:openresty"},
	"lighttpd":          {"lighttpd", "lighttpd:lighttpd"},
	"microsoft-iis":     {"iis", "microsoft:internet_information_services"},
	"caddy":             {"caddy", "caddyserver:caddy"},
	"gunicorn":          {"gunicorn", "gunicorn:gunicorn"},
	"uvicorn":           {"uvicorn", "uvicorn:uvicorn"},
	"werkzeug":          {"werkzeug", "palletsprojects:werkzeug"},
	"openssl":           {"openssl", "openssl:openssl"},
	"phusion_passenger": {"passenger", "phusion:passenger"},
	"express":           {"express", "expressjs:express"},
	"envoy":             {"envoy", "envoyproxy:envoy"},
	"traefik":           {"traefik", "traefik:traefik"},
	"squid":             {"squid", "squid-cache:squid"},
	"mod_wsgi":          {"mod_wsgi", "modwsgi:mod_wsgi"},
	"jetty":             {"jetty", "eclipse:jetty"},
	"litespeed":         {"litespeed", ""},
	"tomcat":            {"apache tomcat", "apache:tomcat"},
}

// generators : les noms que porte un générateur de site (<meta name="generator">, X-Generator), vers le produit et son CPE.
var generators = map[string]known{
	"wordpress":   {"wordpress", "wordpress:wordpress"},
	"drupal":      {"drupal", "drupal:drupal"},
	"ghost":       {"ghost", "ghost:ghost"},
	"mediawiki":   {"mediawiki", "mediawiki:mediawiki"},
	"hugo":        {"hugo", "gohugo:hugo"},
	"jekyll":      {"jekyll", "jekyllrb:jekyll"},
	"typo3":       {"typo3", "typo3:typo3"},
	"prestashop":  {"prestashop", "prestashop:prestashop"},
	"woocommerce": {"woocommerce", "woocommerce:woocommerce"},
	"discourse":   {"discourse", "discourse:discourse"},
	"dokuwiki":    {"dokuwiki", "dokuwiki:dokuwiki"},
	"moodle":      {"moodle", "moodle:moodle"},
	"joomla":      {"joomla", ""},
	"wix.com":     {"wix", ""},
}

var (
	tokenVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)+)`)
	opensslVer   = regexp.MustCompile(`^(\d+(?:\.\d+)+[a-z]?)`)
	generatorRe  = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9.!_-]*(?:\s+[A-Za-z][A-Za-z0-9.!_-]*)?)\s+v?(\d+(?:\.\d+)*)`)
	metaTagRe    = regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	metaNameRe   = regexp.MustCompile(`(?is)\bname\s*=\s*["']generator["']`)
	metaContent  = regexp.MustCompile(`(?is)\bcontent\s*=\s*["']([^"']+)["']`)
	parenRe      = regexp.MustCompile(`\([^)]*\)`)
)

func finding(k known, version, source, evidence string) Finding {
	f := Finding{Product: k.product, CPE: k.cpe, Source: source, Evidence: evidence}
	if version != "" && strings.Count(version, ".") >= 1 {
		f.Version = version
		f.Partial = strings.Count(version, ".") == 1
	}
	return f
}

// productTokens lit « nginx/1.25.3 », « Apache/2.4.58 (Debian) PHP/8.2.12 OpenSSL/3.0.11 » : un jeton « nom/version » par produit.
func productTokens(value, header string, out *[]Finding) {
	value = parenRe.ReplaceAllString(value, " ")
	for _, tok := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		name, ver, _ := strings.Cut(tok, "/")
		k, ok := serverProducts[strings.ToLower(name)]
		if !ok {
			// Un logiciel versionné que la table ne connaît pas est consigné sans produit : le rapport de couverture le montre.
			if tokenVersion.MatchString(strings.ToLower(ver)) {
				*out = append(*out, Finding{Source: SourceHeaders, Evidence: header + ": " + tok})
			}
			continue
		}
		var version string
		re := tokenVersion
		if k.product == "openssl" {
			re = opensslVer
		}
		if m := re.FindStringSubmatch(strings.ToLower(ver)); m != nil {
			version = m[1]
		}
		*out = append(*out, finding(k, version, SourceHeaders, header+": "+tok))
	}
}

// generatorFinding reconnaît un générateur de site d'après sa valeur (« WordPress 6.4.2 », « Drupal 10 (https://www.drupal.org) »).
func generatorFinding(value, source, evidence string) (Finding, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Finding{}, false
	}
	name, version := value, ""
	if m := generatorRe.FindStringSubmatch(value); m != nil {
		name, version = m[1], m[2]
	}
	low := strings.ToLower(name)
	k, ok := generators[low]
	if !ok {
		// « Joomla! - Open Source Content Management » : le nom est le premier mot.
		first := strings.ToLower(strings.TrimRight(strings.Fields(name)[0], "!,:-"))
		if k, ok = generators[first]; !ok {
			return Finding{}, false
		}
	}
	return finding(k, version, source, evidence), true
}

// FromHeaders reconnaît les applications que nomment les en-têtes d'une réponse du backend. Lire ces en-têtes avant hide_server est
// la raison d'être de l'empreinte passive : le client ne les voit plus, la passerelle si.
func FromHeaders(h http.Header) []Finding {
	var out []Finding
	for _, v := range h.Values("Server") {
		productTokens(v, "Server", &out)
	}
	for _, v := range h.Values("X-Powered-By") {
		productTokens(v, "X-Powered-By", &out)
	}
	if v := strings.TrimSpace(h.Get("X-AspNet-Version")); v != "" {
		out = append(out, finding(known{"asp.net", ""}, strings.TrimPrefix(v, "v"), SourceHeaders, "X-AspNet-Version: "+v))
	}
	for _, v := range h.Values("X-Generator") {
		if f, ok := generatorFinding(v, SourceHeaders, "X-Generator: "+v); ok {
			out = append(out, f)
		}
	}
	return out
}

// watched : les en-têtes dont HeaderSignature détecte le changement.
var watched = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}

// HeaderSignature résume les en-têtes qui comptent pour l'empreinte : vide quand la réponse n'en porte aucun. Deux réponses de signature
// égale donnent le même résultat, la passerelle n'analyse donc qu'un changement.
func HeaderSignature(h http.Header) string {
	var sb strings.Builder
	for _, k := range watched {
		for _, v := range h.Values(k) {
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// FromHTML reconnaît le générateur annoncé par <meta name="generator" content="WordPress 6.4.2"> dans le début d'un document HTML.
func FromHTML(doc []byte) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, tag := range metaTagRe.FindAll(doc, 64) {
		if !metaNameRe.Match(tag) {
			continue
		}
		m := metaContent.FindSubmatch(tag)
		if m == nil {
			continue
		}
		value := string(m[1])
		if f, ok := generatorFinding(value, SourceHTML, `<meta name="generator"> `+value); ok && !seen[f.Product] {
			seen[f.Product] = true
			out = append(out, f)
		}
	}
	return out
}
