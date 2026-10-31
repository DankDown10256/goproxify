// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Pair est un label (ou une annotation Kubernetes). Une valeur secrète n'est jamais écrite en clair : elle porte un
// marqueur {{env:NOM}} que la sortie remplace par une variable d'environnement ou par un texte à remplacer.
type Pair struct {
	Key   string
	Value string
}

const tokenOpen = "{{env:"

func token(name string) string { return tokenOpen + name + "}}" }

// envTokens extrait les noms de variables d'une valeur, dans l'ordre.
func envTokens(v string) []string {
	var out []string
	for {
		i := strings.Index(v, tokenOpen)
		if i < 0 {
			return out
		}
		rest := v[i+len(tokenOpen):]
		j := strings.Index(rest, "}}")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		v = rest[j+2:]
	}
}

// Generated est l'équivalent en labels d'une route.
type Generated struct {
	Labels []Pair
	// Unsupported liste les réglages de la route qu'aucun label ne porte, ou qu'il porte en partie.
	Unsupported []string
}

// Env liste les variables à renseigner (secrets), sans doublon, dans l'ordre d'apparition.
func (g *Generated) Env() []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range g.Labels {
		for _, name := range envTokens(p.Value) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// handledKeys sont les clés JSON de la route que FromRoute traite (en entier ou en partie) ou ignore volontairement.
// Toute autre clé non vide est un réglage sans label.
var handledKeys = map[string]bool{
	"id": true, "updated_at": true, "agent_name": true, "delegate_api_endpoint": true, "origin": true,
	"host": true, "aliases": true, "type": true, "backends": true,
	"tls_enabled": true, "tls_passthrough": true,
	"preserve_host": true, "websocket": true, "request_id": true, "http_version": true,
	"strip_prefix": true, "path_rewrite": true,
	"connect_timeout": true, "response_timeout": true, "send_timeout": true, "max_body_size": true,
	"lb": true, "sticky_cookie": true, "retry": true, "circuit_breaker": true, "limit_conn": true,
	"backpressure": true, "slow_start_sec": true,
	"headers_manipulation": true, "transform": true,
	"jwt": true, "mtls": true, "cache": true, "logging": true,
	"rate_limit": true, "ip_filter": true, "geo_ip": true, "cors": true, "waf": true, "bot": true,
	"snippet_ids": true, "auth_provider_id": true, "plugins": true, "ephor_whitelist": true,
}

type builder struct {
	g    *Generated
	note map[string]bool
}

func (b *builder) add(key, value string) {
	b.g.Labels = append(b.g.Labels, Pair{Key: "goproxify." + key, Value: value})
}

func (b *builder) unsupported(what string) {
	if !b.note[what] {
		b.note[what] = true
		b.g.Unsupported = append(b.g.Unsupported, what)
	}
}

// FromRoute produit les labels qui font enregistrer cette route par un Agent (Docker, Portainer) ou par la découverte
// Kubernetes. Un réglage sans label, ou que le label ne porte qu'en partie, est listé dans Unsupported.
func FromRoute(r *router.Route) *Generated {
	b := &builder{g: &Generated{}, note: map[string]bool{}}
	if r == nil {
		return b.g
	}

	b.add("enable", "true")
	hosts := append([]string{r.Host}, r.Aliases...)
	b.add("host", strings.Join(hosts, ","))
	if t := strings.ToLower(string(r.Type)); t == "tcp" || t == "udp" {
		b.add("type", t)
		b.unsupported("flux " + strings.ToUpper(t) + " : l'enregistrement par labels ne crée que des routes HTTP")
	}
	if len(r.Backends) > 0 {
		b.add("backend", r.Backends[0].URL)
	}
	if len(r.Backends) > 1 {
		b.unsupported("backends multiples : un conteneur porte un seul backend, mettez les mêmes labels sur chaque conteneur du pool")
	}
	if r.TLSEnabled {
		b.add("tls", "true")
	}
	if r.TLSPassthrough {
		b.add("passthrough", "true")
	}

	b.behavior(r)
	b.timeouts(r)
	b.resilience(r)
	b.headers(r)
	b.security(r)
	b.auth(r)
	b.extras(r)
	b.unknownKeys(r)
	return b.g
}

func (b *builder) behavior(r *router.Route) {
	flag := func(key string, v *bool) {
		if v == nil {
			return
		}
		if *v {
			b.add(key, "true")
		} else {
			b.unsupported(key + " désactivé : un label ne sait que l'activer")
		}
	}
	flag("preserve_host", r.PreserveHost)
	flag("websocket", r.Websocket)
	flag("request_id", r.RequestID)
	if v := strings.TrimSpace(r.HttpVersion); v != "" && v != "auto" {
		b.add("http_version", v)
	}
	if r.StripPrefix != "" {
		b.add("strip_prefix", r.StripPrefix)
	}
	if r.PathRewrite != "" {
		b.add("path_rewrite", r.PathRewrite)
	}
}

func (b *builder) timeouts(r *router.Route) {
	if r.ConnectTimeout > 0 {
		b.add("timeout.connect", r.ConnectTimeout.String())
	}
	if r.ResponseTimeout > 0 {
		b.add("timeout.response", r.ResponseTimeout.String())
	}
	if r.SendTimeout > 0 {
		b.add("timeout.send", r.SendTimeout.String())
	}
	switch {
	case r.MaxBodySize > 0:
		b.add("max_body_size", formatSize(r.MaxBodySize))
	case r.MaxBodySize < 0:
		b.unsupported("max_body_size illimité : un label ne sait que poser une limite")
	}
}

func formatSize(n int64) string {
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}} {
		if n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

func (b *builder) resilience(r *router.Route) {
	if r.LB != "" && r.LB != router.LBAdaptive {
		b.add("lb", string(r.LB))
	}
	if r.StickyCookie != "" {
		b.add("sticky_cookie", r.StickyCookie)
	}
	if rc := r.Retry; rc != nil && rc.Attempts > 0 {
		v := strconv.Itoa(rc.Attempts)
		if rc.InitialWait > 0 {
			v += ":" + rc.InitialWait.String()
		}
		b.add("retry", v)
		if rc.MaxWait > 0 {
			b.unsupported("retry.max_wait")
		}
	}
	if cb := r.CircuitBreaker; cb != nil && cb.Threshold > 0 {
		v := strconv.Itoa(cb.Threshold)
		if cb.Timeout > 0 {
			v += ":" + cb.Timeout.String()
		}
		b.add("circuit_breaker", v)
	}
	if lc := r.LimitConn; lc != nil && lc.MaxPerIP > 0 {
		b.add("limit_conn", strconv.Itoa(lc.MaxPerIP))
	}
	if bp := r.Backpressure; bp != nil && bp.MaxInflight > 0 {
		v := strconv.Itoa(bp.MaxInflight)
		if bp.Queue > 0 || bp.QueueTimeoutMs > 0 {
			v += ":" + strconv.Itoa(bp.Queue)
		}
		if bp.QueueTimeoutMs > 0 {
			v += ":" + (time.Duration(bp.QueueTimeoutMs) * time.Millisecond).String()
		}
		b.add("backpressure", v)
	}
	if r.SlowStartSec > 0 {
		b.add("slow_start", strconv.Itoa(r.SlowStartSec))
	}
}

// sensitiveName : un en-tête ou une clé de configuration dont la valeur ne doit jamais apparaître dans un bloc à copier.
func sensitiveName(name string) bool {
	n := strings.ToLower(name)
	for _, w := range []string{"authorization", "secret", "password", "passwd", "token", "api-key", "api_key", "apikey", "x-api", "credential", "private"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

func envName(parts ...string) string {
	var sb strings.Builder
	sb.WriteString("GPX")
	for _, p := range parts {
		sb.WriteByte('_')
		for _, c := range strings.ToUpper(p) {
			if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				sb.WriteRune(c)
			} else {
				sb.WriteByte('_')
			}
		}
	}
	return sb.String()
}

func (b *builder) headers(r *router.Route) {
	if hm := r.HeadersManipulation; hm != nil {
		if len(hm.RequestSetHeader) > 0 {
			names := make([]string, 0, len(hm.RequestSetHeader))
			for k := range hm.RequestSetHeader {
				names = append(names, k)
			}
			sort.Strings(names)
			var parts []string
			for _, k := range names {
				v := hm.RequestSetHeader[k]
				switch {
				case strings.Contains(v, ","):
					b.unsupported("en-tête " + k + " : une valeur contenant une virgule ne passe pas dans goproxify.headers.add")
				case sensitiveName(k):
					parts = append(parts, k+":"+token(envName("HDR", k)))
				default:
					parts = append(parts, k+":"+v)
				}
			}
			if len(parts) > 0 {
				b.add("headers.add", strings.Join(parts, ","))
			}
		}
		if len(hm.ForwardedHeaders) > 0 || len(hm.RequestHideHeader) > 0 || len(hm.ResponseAddHeader) > 0 {
			b.unsupported("headers_manipulation (en-têtes transmis, masqués ou ajoutés à la réponse)")
		}
	}
	if t := r.Transform; t != nil {
		if len(t.RemoveResponseHeaders) > 0 {
			b.add("headers.remove", strings.Join(t.RemoveResponseHeaders, ","))
		}
		if t.RewriteFrom != "" || t.RewriteTo != "" || len(t.AddRequestHeaders) > 0 || len(t.RemoveRequestHeaders) > 0 || len(t.AddResponseHeaders) > 0 {
			b.unsupported("transform (réécriture et en-têtes de requête / de réponse ajoutés)")
		}
	}
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func (b *builder) security(r *router.Route) {
	if rl := r.RateLimit; rl != nil && rl.RequestsPerSecond > 0 {
		v := formatFloat(rl.RequestsPerSecond) + "/s"
		if rl.Burst > 0 {
			v += ":" + strconv.Itoa(rl.Burst)
		}
		b.add("rate_limit", v)
		if (rl.KeyBy != "" && rl.KeyBy != "ip") || rl.Quota > 0 || rl.Shared {
			b.unsupported("rate_limit (clé, quota, partage entre passerelles)")
		}
	}
	if f := r.IPFilter; f != nil && len(f.CIDRs) > 0 {
		mode := f.Mode
		if mode == "" {
			mode = "allow"
		}
		b.add("ip_filter", mode+":"+strings.Join(f.CIDRs, ","))
	}
	if g := r.GeoIP; g != nil && len(g.Countries) > 0 {
		mode := g.Mode
		if mode == "" {
			mode = "allow"
		}
		b.add("geo_ip", mode+":"+strings.Join(g.Countries, ","))
	}
	if c := r.CORS; c != nil && len(c.AllowedOrigins) > 0 {
		var origins []string
		for _, o := range c.AllowedOrigins {
			if o == "*" {
				b.unsupported("cors avec l'origine « * » : un label exige une liste explicite")
				continue
			}
			origins = append(origins, o)
		}
		if len(origins) > 0 {
			b.add("cors", strings.Join(origins, ","))
		}
	}
	b.waf(r)
	b.bot(r)
	if ids := r.EphorWhitelist; len(ids) > 0 {
		b.add("ephor.whitelist", strings.Join(ids, ","))
	}
}

func (b *builder) waf(r *router.Route) {
	w := r.WAF
	if w == nil || !w.Enabled {
		return
	}
	mode := w.Mode
	if mode != "detect" {
		mode = "block"
	}
	b.add("waf", mode)
	if w.AnomalyThreshold > 0 {
		b.add("waf.anomaly_threshold", strconv.Itoa(w.AnomalyThreshold))
	}
	if w.MaxBodyMB > 0 {
		b.add("waf.max_body_mb", strconv.Itoa(w.MaxBodyMB))
	}
	if len(w.ExcludeIDs) > 0 {
		ids := make([]string, len(w.ExcludeIDs))
		for i, id := range w.ExcludeIDs {
			ids[i] = strconv.Itoa(id)
		}
		b.add("waf.exclude_ids", strings.Join(ids, ","))
	}
	if w.BehaviorEnabled {
		b.add("waf.behavior", "true")
		if w.BehaviorWindowSec > 0 {
			b.add("waf.behavior.window", strconv.Itoa(w.BehaviorWindowSec))
		}
		if w.BehaviorThreshold > 0 {
			b.add("waf.behavior.threshold", strconv.Itoa(w.BehaviorThreshold))
		}
	}
	if len(w.TrustedProxies) > 0 {
		b.add("waf.trusted_proxies", strings.Join(w.TrustedProxies, ","))
	}
	if len(w.CustomRules) > 0 || len(w.Exclusions) > 0 || w.CustomRulesPath != "" {
		b.unsupported("waf (règles personnalisées, exclusions par chemin)")
	}
}

func (b *builder) bot(r *router.Route) {
	bt := r.Bot
	if bt == nil || !bt.Enabled {
		return
	}
	b.add("bot", "true")
	if bt.Mode != "" {
		b.add("bot.mode", bt.Mode)
	}
	if len(bt.UABlacklist) > 0 || (bt.JSChallenge && bt.Mode != "challenge") || bt.ChallengeSecret != "" || bt.ChallengeProvider != "" ||
		bt.ChallengeDifficulty > 0 || bt.ChallengeTTL != "" || bt.ChallengeSiteKey != "" ||
		bt.ChallengeProviderSecret != "" || len(bt.ChallengeExemptPaths) > 0 {
		b.unsupported("bot (liste d'agents, paramètres du challenge)")
	}
}

func (b *builder) auth(r *router.Route) {
	if j := r.JWT; j != nil && j.Enabled {
		if j.JWKSURL == "" {
			b.unsupported("jwt sans URL JWKS : un label ne sait valider que par JWKS")
		} else {
			b.add("jwt", j.JWKSURL)
			if j.Issuer != "" {
				b.add("jwt.issuer", j.Issuer)
			}
			if j.Audience != "" {
				b.add("jwt.audience", j.Audience)
			}
			if j.HeaderName != "" || j.ClaimsHeader != "" {
				b.unsupported("jwt (nom de l'en-tête, en-tête des claims)")
			}
		}
	}
	if m := r.MTLS; m != nil && m.Enabled {
		if m.CACertFile == "" {
			b.unsupported("mtls sans fichier CA : un label désigne un fichier CA lisible par la passerelle")
		} else {
			b.add("mtls", m.CACertFile)
			if m.CACertPEM != "" || len(m.AllowedSANs) > 0 || m.SubjectHeader != "" || !m.RequireClientCert {
				b.unsupported("mtls (certificat inline, SAN autorisés, en-tête du sujet, certificat facultatif)")
			}
		}
	}
	if r.AuthProviderID != "" {
		b.add("auth_provider", r.AuthProviderID)
	}
}

func (b *builder) extras(r *router.Route) {
	if len(r.SnippetIDs) > 0 {
		b.add("snippets", strings.Join(r.SnippetIDs, ","))
	}
	if c := r.Cache; c != nil && c.Enabled {
		switch {
		case len(c.ValidRules) == 0:
			b.add("cache", "true")
		case len(c.ValidRules) == 1 && c.ValidRules[0].TTL != "" && len(c.ValidRules[0].StatusCodes) == 0:
			b.add("cache", c.ValidRules[0].TTL)
		default:
			b.add("cache", "true")
			b.unsupported("cache (TTL par code de statut)")
		}
		if c.Dir != "" || len(c.BypassHeaders) > 0 || len(c.BypassCookies) > 0 || c.IgnoreCookies || len(c.VaryCookies) > 0 ||
			len(c.Methods) > 0 || c.StaleWhileRevalidate != "" || c.StaleIfError != "" || c.DisableCoalescing {
			b.unsupported("cache (contournements, cookies, méthodes, stale-*)")
		}
	}
	if l := r.Logging; l != nil {
		switch {
		case !l.AccessLog || l.Format == "off":
			b.unsupported("journal d'accès désactivé : un label ne sait que l'activer")
		default:
			if l.Format == "" && l.Level == "" {
				b.add("logs", "true")
			}
			if l.Format != "" {
				b.add("logs.format", l.Format)
			}
			if l.Level != "" {
				b.add("logs.level", l.Level)
			}
		}
	}
	if len(r.Plugins) > 0 {
		names := make([]string, len(r.Plugins))
		for i, p := range r.Plugins {
			names[i] = p.Name
		}
		b.add("plugins", strings.Join(names, ","))
		for _, p := range r.Plugins {
			keys := make([]string, 0, len(p.Config))
			for k := range p.Config {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				key := "plugin." + p.Name + "." + k
				switch v := p.Config[k].(type) {
				case string:
					if sensitiveName(k) {
						b.add(key, token(envName("PLUGIN", p.Name, k)))
					} else {
						b.add(key, v)
					}
				case bool:
					b.add(key, strconv.FormatBool(v))
				case float64:
					b.add(key, formatFloat(v))
				case int:
					b.add(key, strconv.Itoa(v))
				default:
					b.unsupported(fmt.Sprintf("plugin %s : la clé %q n'est pas une valeur simple", p.Name, k))
				}
			}
		}
	}
}

// unknownKeys relève ce que la route porte et qu'aucun label ne couvre.
func (b *builder) unknownKeys(r *router.Route) {
	raw, err := json.Marshal(r)
	if err != nil {
		return
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	var keys []string
	for k, v := range m {
		if !handledKeys[k] && !emptyJSON(v) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.unsupported(k)
	}
}

func emptyJSON(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// EnvTokens extrait les noms de variables secrètes d'une valeur de label.
func EnvTokens(v string) []string { return envTokens(v) }
