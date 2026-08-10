// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DetectedCondition est une règle de routage par chemin extraite d'un bloc location nginx.
// Utilisé pour les importeurs simples (Traefik, Caddy…).
type DetectedCondition struct {
	Path    string `json:"path"`    // préfixe de chemin (ex: "/sse")
	Backend string `json:"backend"` // URL du backend pour ce chemin
}

// DetectedLocation est un bloc location nginx complet : backend + config par chemin.
type DetectedLocation struct {
	Path     string   `json:"path"`               // préfixe de chemin (ex: "/api")
	PathType string   `json:"path_type,omitempty"` // prefix | exact | regex
	Backends []string `json:"backends,omitempty"`
	// Overrides (zéro = hérite de la route)
	ConnectTimeout  int               `json:"connect_timeout,omitempty"`
	ResponseTimeout int               `json:"response_timeout,omitempty"`
	SendTimeout     int               `json:"send_timeout,omitempty"`
	MaxBodySize     int64             `json:"max_body_size,omitempty"`
	HSTS            bool              `json:"hsts,omitempty"`
	HSTSMaxAge      int               `json:"hsts_max_age,omitempty"`
	XFrameOptions   string            `json:"x_frame_options,omitempty"`
	CustomHeaders   map[string]string `json:"custom_headers,omitempty"`
}

// DetectedProxy est un proxy extrait d'une configuration tierce.
type DetectedProxy struct {
	Host          string              `json:"host"`
	Backends      []string            `json:"backends"`
	Conditions    []DetectedCondition `json:"conditions,omitempty"` // routage backend simple
	Locations     []DetectedLocation  `json:"locations,omitempty"`  // config complète par chemin
	TLS           bool                `json:"tls"`
	Source        string              `json:"source"`
	Raw           string              `json:"raw,omitempty"`
	// Headers niveau route
	HSTS          bool              `json:"hsts,omitempty"`
	HSTSMaxAge    int               `json:"hsts_max_age,omitempty"`
	XFrameOptions string            `json:"x_frame_options,omitempty"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
	// Timeouts, buffer et limite body (natifs)
	ConnectTimeout  int   `json:"connect_timeout,omitempty"`  // secondes
	ResponseTimeout int   `json:"response_timeout,omitempty"` // secondes
	SendTimeout     int   `json:"send_timeout,omitempty"`     // secondes
	BufferSize      int   `json:"buffer_size,omitempty"`      // octets
	MaxBodySize     int64 `json:"max_body_size,omitempty"`    // octets
}

// ParseConfig détecte le format et extrait les proxies.
func ParseConfig(format, content string) ([]DetectedProxy, error) {
	switch format {
	case "nginx":
		return parseNginx(content)
	case "traefik-yaml":
		return parseTraefikYAML(content)
	case "traefik-toml":
		return parseTraefikTOML(content)
	case "caddy":
		return parseCaddy(content)
	case "haproxy":
		return parseHAProxy(content)
	case "goproxify":
		return parseGoproxify(content)
	default:
		// Essaie JSON générique (tableau de proxies)
		return parseGenericJSON(content)
	}
}

// ── nginx ─────────────────────────────────────────────────────────────────────

var (
	reServerBlock   = regexp.MustCompile(`(?s)server\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}`)
	reServerName    = regexp.MustCompile(`server_name\s+([^;]+);`)
	reProxyPass     = regexp.MustCompile(`proxy_pass\s+([^;]+);`)
	reListenSSL     = regexp.MustCompile(`listen\s+[^\n]*ssl`)
	reUpstreamBlock = regexp.MustCompile(`(?s)upstream\s+(\S+)\s*\{([^{}]*)\}`)
	reUpstreamSrv   = regexp.MustCompile(`(?m)^\s*server\s+(\S+?)(?:\s+[^;]*)?\s*;`)
	reLocationBlock      = regexp.MustCompile(`(?s)location\s+([^{]+?)\s*\{([^{}]*)\}`)
	reLocationRoot       = regexp.MustCompile(`(?s)location\s+/\s*\{([^{}]*)\}`)
	reAddHeader          = regexp.MustCompile(`(?i)add_header\s+(\S+)\s+"([^"]*)"`)
	reAddHeaderRaw       = regexp.MustCompile(`(?i)add_header\s+(\S+)\s+(\S+)`)
	reHSTSMaxAge         = regexp.MustCompile(`max-age=(\d+)`)
	reConnectTimeout     = regexp.MustCompile(`(?m)proxy_connect_timeout\s+(\d+)`)
	reReadTimeout        = regexp.MustCompile(`(?m)proxy_read_timeout\s+(\d+)`)
	reSendTimeout        = regexp.MustCompile(`(?m)proxy_send_timeout\s+(\d+)`)
	reBufferSize         = regexp.MustCompile(`(?m)proxy_buffer_size\s+(\d+)([kKmM]?)`)
	reClientMaxBody      = regexp.MustCompile(`(?m)client_max_body_size\s+(\d+)([kKmM]?)`)
)

// nginxUpstreams extrait les upstreams nginx : nom → liste de serveurs (IP:port).
func nginxUpstreams(content string) map[string][]string {
	m := map[string][]string{}
	for _, um := range reUpstreamBlock.FindAllStringSubmatch(content, -1) {
		name := um[1]
		block := um[2]
		var servers []string
		for _, sm := range reUpstreamSrv.FindAllStringSubmatch(block, -1) {
			servers = append(servers, sm[1])
		}
		if len(servers) > 0 {
			m[name] = servers
		}
	}
	return m
}

// resolveBackend résout un proxy_pass vers les backends réels (upstream ou URL directe).
func resolveBackend(rawURL string, upstreams map[string][]string) []string {
	u := strings.TrimSpace(rawURL)
	// Extrait le schéma et le host
	scheme := "http"
	host := u
	if strings.HasPrefix(u, "https://") {
		scheme = "https"
		host = strings.TrimPrefix(u, "https://")
	} else if strings.HasPrefix(u, "http://") {
		host = strings.TrimPrefix(u, "http://")
	}
	// Retire le chemin éventuel
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if servers, ok := upstreams[host]; ok {
		var out []string
		for _, s := range servers {
			out = append(out, scheme+"://"+s)
		}
		return out
	}
	return []string{u}
}

// parseNginxSize convertit une valeur nginx avec suffixe (k/m) en octets.
func parseNginxSize(val, suffix string) int64 {
	var v int64
	fmt.Sscanf(val, "%d", &v)
	switch strings.ToLower(suffix) {
	case "k":
		v *= 1024
	case "m":
		v *= 1024 * 1024
	}
	return v
}

// extractNginxTimeouts lit les directives de timeout/buffer depuis un bloc location.
func extractNginxTimeouts(loc string) (connect, read, send int, bufSize int, maxBody int64) {
	parseInt := func(re *regexp.Regexp) int {
		if m := re.FindStringSubmatch(loc); m != nil {
			v := 0
			fmt.Sscanf(m[1], "%d", &v)
			return v
		}
		return 0
	}
	connect = parseInt(reConnectTimeout)
	read = parseInt(reReadTimeout)
	send = parseInt(reSendTimeout)
	if m := reBufferSize.FindStringSubmatch(loc); m != nil {
		bufSize = int(parseNginxSize(m[1], m[2]))
	}
	if m := reClientMaxBody.FindStringSubmatch(loc); m != nil {
		maxBody = parseNginxSize(m[1], m[2])
	}
	return
}

// extractNginxHeadersBlock mappe les add_header d'un corps de bloc (déjà extrait) sur les champs.
func extractNginxHeadersBlock(loc string) (hsts bool, hstsMx int, xframe string, custom map[string]string) {
	parseHeader := func(name, value string) {
		switch strings.ToLower(name) {
		case "strict-transport-security":
			hsts = true
			if m := reHSTSMaxAge.FindStringSubmatch(value); m != nil {
				fmt.Sscanf(m[1], "%d", &hstsMx)
			}
		case "x-frame-options":
			xframe = value
		default:
			if custom == nil {
				custom = map[string]string{}
			}
			custom[name] = value
		}
	}
	seen := map[string]bool{}
	for _, m := range reAddHeader.FindAllStringSubmatch(loc, -1) {
		seen[strings.ToLower(m[1])] = true
		parseHeader(m[1], m[2])
	}
	for _, m := range reAddHeaderRaw.FindAllStringSubmatch(loc, -1) {
		if !seen[strings.ToLower(m[1])] {
			parseHeader(m[1], m[2])
		}
	}
	return
}

// extractNginxHeaders lit les add_header d'un bloc location / et les mappe sur les champs DetectedProxy.
func extractNginxHeaders(block string) (hsts bool, hstsMx int, xframe string, custom map[string]string) {
	locM := reLocationRoot.FindStringSubmatch(block)
	if locM == nil {
		return
	}
	loc := locM[1]

	parseHeader := func(name, value string) {
		switch strings.ToLower(name) {
		case "strict-transport-security":
			hsts = true
			if m := reHSTSMaxAge.FindStringSubmatch(value); m != nil {
				fmt.Sscanf(m[1], "%d", &hstsMx)
			}
		case "x-frame-options":
			xframe = value
		default:
			if custom == nil {
				custom = map[string]string{}
			}
			custom[name] = value
		}
	}

	// add_header Name "value" [always]
	for _, m := range reAddHeader.FindAllStringSubmatch(loc, -1) {
		parseHeader(m[1], m[2])
	}
	// add_header Name value (sans guillemets) — seulement si pas déjà capturé ci-dessus
	seen := map[string]bool{}
	for _, m := range reAddHeader.FindAllStringSubmatch(loc, -1) {
		seen[strings.ToLower(m[1])] = true
	}
	for _, m := range reAddHeaderRaw.FindAllStringSubmatch(loc, -1) {
		if !seen[strings.ToLower(m[1])] {
			parseHeader(m[1], m[2])
		}
	}
	return
}

// isInternalLocation retourne true si le chemin est un bloc interne nginx (pas à router).
func isInternalLocation(path string) bool {
	// Blocs acme-challenge, error pages internes (/_nfep...), = /path exact
	return strings.HasPrefix(path, "/.well-known/acme-challenge") ||
		strings.HasPrefix(path, "/_") ||
		strings.HasPrefix(path, "= /")
}

func parseNginx(content string) ([]DetectedProxy, error) {
	upstreams := nginxUpstreams(content)
	var out []DetectedProxy
	for _, m := range reServerBlock.FindAllStringSubmatch(content, -1) {
		block := m[1]
		namesM := reServerName.FindStringSubmatch(block)
		if namesM == nil {
			continue
		}
		names := strings.Fields(namesM[1])
		if len(names) == 0 {
			continue
		}
		host := names[0]
		if host == "_" || host == "localhost" {
			continue
		}

		// Parse chaque bloc location individuellement
		var primaryBackends []string
		var locations []DetectedLocation

		for _, lm := range reLocationBlock.FindAllStringSubmatch(block, -1) {
			locPath := strings.TrimSpace(lm[1])
			locBody := lm[2]

			if isInternalLocation(locPath) {
				continue
			}

			pm := reProxyPass.FindStringSubmatch(locBody)
			if pm == nil {
				continue
			}
			resolved := resolveBackend(strings.TrimSpace(pm[1]), upstreams)

			if locPath == "/" {
				primaryBackends = append(primaryBackends, resolved...)
			} else {
				// Extraire la config spécifique à ce bloc location
				lConn, lRead, lSend, _, lMaxBody := extractNginxTimeouts(locBody)
				lHSTS, lHSTSMx, lXFrame, lCustom := extractNginxHeadersBlock(locBody)
				pathType := "prefix"
				if strings.HasPrefix(locPath, "= ") {
					pathType = "exact"
					locPath = strings.TrimPrefix(locPath, "= ")
				} else if strings.HasPrefix(locPath, "~") {
					pathType = "regex"
					locPath = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(locPath, "~*"), "~"))
				}
				locations = append(locations, DetectedLocation{
					Path: locPath, PathType: pathType,
					Backends:        resolved,
					ConnectTimeout:  lConn, ResponseTimeout: lRead, SendTimeout: lSend,
					MaxBodySize:     lMaxBody,
					HSTS: lHSTS, HSTSMaxAge: lHSTSMx, XFrameOptions: lXFrame, CustomHeaders: lCustom,
				})
			}
		}

		if len(primaryBackends) == 0 && len(locations) == 0 {
			continue
		}

		tls := reListenSSL.MatchString(block)
		hsts, hstsMx, xframe, custom := extractNginxHeaders(block)
		connect, read, send, bufSize, maxBody := extractNginxTimeouts(block)
		out = append(out, DetectedProxy{
			Host: host, Backends: primaryBackends, Locations: locations,
			TLS: tls, Source: "nginx", Raw: strings.TrimSpace(block),
			HSTS: hsts, HSTSMaxAge: hstsMx, XFrameOptions: xframe, CustomHeaders: custom,
			ConnectTimeout: connect, ResponseTimeout: read, SendTimeout: send, BufferSize: bufSize,
			MaxBodySize: maxBody,
		})
	}
	return out, nil
}

// ── Traefik YAML ──────────────────────────────────────────────────────────────

type traefikYAML struct {
	HTTP struct {
		Routers  map[string]struct {
			Rule    string `yaml:"rule"`
			Service string `yaml:"service"`
			TLS     *struct{} `yaml:"tls"`
		} `yaml:"routers"`
		Services map[string]struct {
			LoadBalancer struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
			} `yaml:"loadBalancer"`
		} `yaml:"services"`
	} `yaml:"http"`
}

var reTraefikHost = regexp.MustCompile("Host\\(`([^`]+)`\\)")

func parseTraefikYAML(content string) ([]DetectedProxy, error) {
	var cfg traefikYAML
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}
	var out []DetectedProxy
	for _, r := range cfg.HTTP.Routers {
		m := reTraefikHost.FindStringSubmatch(r.Rule)
		if m == nil {
			continue
		}
		host := m[1]
		var backends []string
		if svc, ok := cfg.HTTP.Services[r.Service]; ok {
			for _, s := range svc.LoadBalancer.Servers {
				backends = append(backends, s.URL)
			}
		}
		out = append(out, DetectedProxy{
			Host: host, Backends: backends, TLS: r.TLS != nil, Source: "traefik-yaml",
		})
	}
	return out, nil
}

// ── Traefik TOML ──────────────────────────────────────────────────────────────

func parseTraefikTOML(content string) ([]DetectedProxy, error) {
	// Extraction par regex (évite la dépendance go-toml à l'exécution)
	var out []DetectedProxy
	reRouter := regexp.MustCompile(`(?s)\[http\.routers\.([^\]]+)\][^\[]*rule\s*=\s*"([^"]+)"`)
	reService := regexp.MustCompile(`service\s*=\s*"([^"]+)"`)
	reTLS := regexp.MustCompile(`\[http\.routers\.[^\]]+\.tls\]`)
	reServerURL := regexp.MustCompile(`url\s*=\s*"([^"]+)"`)

	for _, m := range reRouter.FindAllStringSubmatch(content, -1) {
		ruleStr := m[2]
		hostM := reTraefikHost.FindStringSubmatch(ruleStr)
		if hostM == nil {
			continue
		}
		host := hostM[1]
		svcM := reService.FindStringSubmatch(m[0])
		var backends []string
		if svcM != nil {
			svcBlock := regexp.MustCompile(`(?s)\[http\.services\.` + regexp.QuoteMeta(svcM[1]) + `[^\[]*`).FindString(content)
			for _, su := range reServerURL.FindAllStringSubmatch(svcBlock, -1) {
				backends = append(backends, su[1])
			}
		}
		tls := reTLS.MatchString(content)
		out = append(out, DetectedProxy{Host: host, Backends: backends, TLS: tls, Source: "traefik-toml"})
	}
	return out, nil
}

// ── Caddy ─────────────────────────────────────────────────────────────────────

var (
	reCaddyBlock    = regexp.MustCompile(`(?m)^(\S[^\{]*)\{([^}]*)\}`)
	reCaddyRevProxy = regexp.MustCompile(`reverse_proxy\s+(\S+)`)
)

func parseCaddy(content string) ([]DetectedProxy, error) {
	var out []DetectedProxy
	for _, m := range reCaddyBlock.FindAllStringSubmatch(content, -1) {
		host := strings.TrimSpace(m[1])
		block := m[2]
		if host == "" || strings.HasPrefix(host, "#") || strings.HasPrefix(host, "(") {
			continue
		}
		// strip port if any
		host = strings.Split(host, ":")[0]
		tls := strings.Contains(block, "tls ") || strings.HasPrefix(host, "https://")
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		var backends []string
		for _, pm := range reCaddyRevProxy.FindAllStringSubmatch(block, -1) {
			backends = append(backends, pm[1])
		}
		if len(backends) == 0 {
			continue
		}
		out = append(out, DetectedProxy{Host: host, Backends: backends, TLS: tls, Source: "caddy"})
	}
	return out, nil
}

// ── HAProxy ───────────────────────────────────────────────────────────────────

func parseHAProxy(content string) ([]DetectedProxy, error) {
	var out []DetectedProxy
	// Map frontend → backend
	frontends := map[string]string{}
	backends := map[string][]string{}

	var currentSection, currentName string
	reBind := regexp.MustCompile(`bind\s+\*?:(\d+)`)
	reDefault := regexp.MustCompile(`default_backend\s+(\S+)`)
	reServer := regexp.MustCompile(`server\s+\S+\s+(\S+)`)
	reACLHost := regexp.MustCompile(`acl\s+\S+\s+hdr\(host\)\s+-i\s+(\S+)`)
	reACLName := regexp.MustCompile(`acl\s+(\S+)\s+`)
	reUseBackend := regexp.MustCompile(`use_backend\s+(\S+)\s+if\s+(\S+)`)

	frontendHosts := map[string]string{} // frontend name → detected host
	frontendACLs := map[string]map[string]string{} // frontend → aclName → host

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "frontend ") {
			currentSection = "frontend"
			currentName = strings.Fields(line)[1]
			frontendACLs[currentName] = map[string]string{}
			continue
		}
		if strings.HasPrefix(line, "backend ") {
			currentSection = "backend"
			currentName = strings.Fields(line)[1]
			continue
		}
		switch currentSection {
		case "frontend":
			if m := reBind.FindStringSubmatch(line); m != nil {
				_ = m[1]
			}
			if m := reACLHost.FindStringSubmatch(line); m != nil {
				if am := reACLName.FindStringSubmatch(line); am != nil {
					frontendACLs[currentName][am[1]] = m[1]
				}
			}
			if m := reDefault.FindStringSubmatch(line); m != nil {
				frontends[currentName] = m[1]
			}
			if m := reUseBackend.FindStringSubmatch(line); m != nil {
				backendName := m[1]
				aclName := m[2]
				if host, ok := frontendACLs[currentName][aclName]; ok {
					frontendHosts[backendName] = host
				}
			}
		case "backend":
			if m := reServer.FindStringSubmatch(line); m != nil {
				backends[currentName] = append(backends[currentName], m[1])
			}
		}
	}

	seen := map[string]bool{}
	for fe, be := range frontends {
		host := frontendHosts[be]
		if host == "" {
			host = fe
		}
		if seen[be] {
			continue
		}
		seen[be] = true
		svrs := backends[be]
		var bkds []string
		for _, s := range svrs {
			bkds = append(bkds, "http://"+s)
		}
		out = append(out, DetectedProxy{Host: host, Backends: bkds, Source: "haproxy"})
	}
	return out, nil
}

// ── Goproxify natif ───────────────────────────────────────────────────────────

func parseGoproxify(content string) ([]DetectedProxy, error) {
	// Peut être un tableau de routes ou un Backup complet
	var routes []struct {
		Host     string `json:"host"`
		Backends []struct {
			URL string `json:"url"`
		} `json:"backends"`
		TLSEnabled bool `json:"tls_enabled"`
	}
	if err := json.Unmarshal([]byte(content), &routes); err == nil {
		var out []DetectedProxy
		for _, r := range routes {
			var bkds []string
			for _, b := range r.Backends {
				bkds = append(bkds, b.URL)
			}
			out = append(out, DetectedProxy{Host: r.Host, Backends: bkds, TLS: r.TLSEnabled, Source: "goproxify"})
		}
		return out, nil
	}
	// Essaie en tant que Backup complet
	var b Backup
	if err := json.Unmarshal([]byte(content), &b); err == nil && len(b.Proxies) > 0 {
		var out []DetectedProxy
		for _, p := range b.Proxies {
			var bkds []string
			for _, bk := range p.Config.Backends {
				bkds = append(bkds, bk.URL)
			}
			out = append(out, DetectedProxy{
				Host: p.Config.Host, Backends: bkds, TLS: p.Config.TLSEnabled, Source: "goproxify",
			})
		}
		return out, nil
	}
	return nil, nil
}

// ── JSON générique ────────────────────────────────────────────────────────────

func parseGenericJSON(content string) ([]DetectedProxy, error) {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(content), &rows); err != nil {
		// Tente un objet unique
		var row map[string]any
		if err2 := json.Unmarshal([]byte(content), &row); err2 != nil {
			return nil, err
		}
		rows = []map[string]any{row}
	}
	var out []DetectedProxy
	for _, r := range rows {
		host := strVal(r, "host", "domain", "server_name", "hostname")
		if host == "" {
			continue
		}
		var backends []string
		if v, ok := r["backend"]; ok {
			backends = append(backends, anyToStr(v))
		}
		if v, ok := r["backends"]; ok {
			if arr, ok := v.([]any); ok {
				for _, b := range arr {
					backends = append(backends, anyToStr(b))
				}
			}
		}
		tls, _ := r["tls"].(bool)
		out = append(out, DetectedProxy{Host: host, Backends: backends, TLS: tls, Source: "json"})
	}
	return out, nil
}

func strVal(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func anyToStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if u, ok := t["url"].(string); ok {
			return u
		}
	}
	return ""
}
