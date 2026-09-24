// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package errorpages génère les pages d'erreur HTML par défaut du core Goproxify.
// Chaque page est autonome (CSS inline, aucune dépendance externe) et affiche
// une section technique masquée révélable par clic.
package errorpages

import (
	"fmt"
	"html/template"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/i18n"
)

// CoreVersion est initialisé au démarrage (cmd/goproxify/main.go).
var CoreVersion = "dev"

// AdminBaseURL est l'origine publique de l'interface Admin (ex. https://203.0.113.10:9443).
// Renseignée via GPX_ADMIN_PUBLIC_URL ou poussée par l'Admin (admin_public_url).
// Vide = pas de lien cliquable (évite de résoudre contre l'hôte proxyfié).
var (
	adminBaseMu  sync.RWMutex
	adminBaseURL string
)

// SetAdminBaseURL enregistre l'origine publique de l'Admin (trim du slash final).
func SetAdminBaseURL(u string) {
	adminBaseMu.Lock()
	adminBaseURL = strings.TrimRight(strings.TrimSpace(u), "/")
	adminBaseMu.Unlock()
}

// GetAdminBaseURL retourne l'origine Admin connue (peut être vide).
func GetAdminBaseURL() string {
	adminBaseMu.RLock()
	defer adminBaseMu.RUnlock()
	return adminBaseURL
}

type errInfo struct{ title, message string }

func infoFor(code int, loc string) errInfo {
	codeKey := strconv.Itoa(code)
	title := i18n.T(loc, "err.title."+codeKey)
	msg := i18n.T(loc, "err.message."+codeKey)
	// Unknown status: T returns the key itself when missing — detect and use fallback.
	if title == "err.title."+codeKey {
		title = i18n.T(loc, "err.title.fallback", code)
	}
	if msg == "err.message."+codeKey {
		msg = i18n.T(loc, "err.message.fallback")
	}
	return errInfo{title: title, message: msg}
}

func esc(s string) string { return string(template.HTMLEscapeString(s)) }

// Render génère une page HTML autonome pour le code HTTP donné.
// acceptLanguage is the raw Accept-Language header (may be empty → English).
// host : hôte de la requête, reqID : valeur X-Request-ID (peut être vide).
func Render(code int, host, reqID, acceptLanguage string) string {
	loc := i18n.FromAcceptLanguage(acceptLanguage)
	e := infoFor(code, loc)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	details := `<div class="dl">`
	if host != "" {
		details += `<span class="dk">` + esc(i18n.T(loc, "err.label.host")) + `</span><span class="dv">` + esc(host) + `</span>`
	}
	details += `<span class="dk">` + esc(i18n.T(loc, "err.label.time")) + `</span><span class="dv">` + ts + `</span>`
	if reqID != "" {
		details += `<span class="dk">` + esc(i18n.T(loc, "err.label.request")) + `</span><span class="dv">` + esc(reqID) + `</span>`
		if logURL := buildLogURL(reqID); logURL != "" {
			details += `<span class="dk">` + esc(i18n.T(loc, "err.label.log_id")) + `</span><span class="dv"><a href="` + esc(logURL) + `" style="color:inherit;text-decoration:underline">` + esc(reqID) + `</a></span>`
		} else {
			details += `<span class="dk">` + esc(i18n.T(loc, "err.label.log_id")) + `</span><span class="dv">` + esc(reqID) + `</span>`
		}
	}
	details += `</div>`

	badge := i18n.T(loc, "err.badge", code)
	detailsTitle := i18n.T(loc, "err.details_title")

	// Note : les %% dans le CSS sont des signes % littéraux échappés pour fmt.Sprintf.
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%d %s — Goproxify</title>
<style>
:root{--bg:#f7f8fa;--text:#1a1d23;--text2:#6b7280;--border:#e5e7eb;--card:#fff;--sh:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);--dim:rgba(0,0,0,.04)}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--text:#e6e8ef;--text2:#8b92a5;--border:#1e2330;--card:#151b27;--sh:0 2px 6px rgba(0,0,0,.45);--dim:rgba(255,255,255,.03)}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;box-shadow:var(--sh);max-width:460px;width:100%%;padding:48px 40px 36px;position:relative;overflow:hidden}
.wm{position:absolute;right:-10px;bottom:-48px;font-size:180px;font-weight:900;color:var(--dim);line-height:1;pointer-events:none;user-select:none;letter-spacing:-6px}
.badge{display:inline-flex;align-items:center;gap:6px;background:var(--dim);border:1px solid var(--border);border-radius:999px;padding:3px 12px;font-size:11.5px;color:var(--text2);margin-bottom:22px}
.dot{width:6px;height:6px;border-radius:50%%;background:currentColor;opacity:.7;flex:none}
h1{font-size:24px;font-weight:700;margin-bottom:10px;line-height:1.3}
p{font-size:14px;color:var(--text2);line-height:1.7}
.foot{margin-top:36px;padding-top:18px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.brand{font-size:11.5px;color:var(--text2);display:flex;align-items:center;gap:7px;opacity:.65}
.dbtn{background:none;border:none;cursor:pointer;color:var(--text2);opacity:.3;padding:4px 7px;border-radius:4px;font-size:13px;letter-spacing:.15em;transition:opacity .15s;font-family:inherit}
.dbtn:hover{opacity:.75}
.details{display:none;margin-top:14px;background:var(--dim);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-size:10.5px;font-family:ui-monospace,"SF Mono",Menlo,monospace;color:var(--text2);line-height:2.1}
.details.open{display:block}
.dl{display:grid;grid-template-columns:auto 1fr;gap:0 16px}
.dk{opacity:.5;white-space:nowrap}
.dv{color:var(--text);word-break:break-all}
</style>
</head>
<body>
<div class="card">
  <div class="wm">%d</div>
  <div class="badge"><span class="dot"></span>%s</div>
  <h1>%s</h1>
  <p>%s</p>
  <div class="foot">
    <span class="brand">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
      Goproxify
    </span>
    <button class="dbtn" onclick="document.getElementById('d').classList.toggle('open')" title="%s">···</button>
  </div>
  <div class="details" id="d">%s</div>
</div>
</body>
</html>`,
		esc(loc),
		code, esc(e.title),
		code,
		esc(badge),
		esc(e.title),
		esc(e.message),
		esc(detailsTitle),
		details,
	)
}

// buildLogURL construit un deep-link absolu vers la page Logs de l'Admin.
// Retourne "" si l'URL Admin n'est pas connue (évite un lien relatif sur l'hôte proxyfié).
func buildLogURL(reqID string) string {
	base := GetAdminBaseURL()
	if base == "" || reqID == "" {
		return ""
	}
	q := url.Values{}
	q.Set("gpx_page", "logs")
	q.Set("component", "core")
	q.Set("search", reqID)
	q.Set("kind", "access")
	return base + "/?" + q.Encode()
}
