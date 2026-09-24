// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"strconv"
	"strings"

	gplabels "github.com/vincamok/goproxify/internal/labels"
)

// Labels Docker reconnus par Goproxify.
const (
	LabelEnable          = "goproxify.enable"       // "true" active la découverte
	LabelType            = "goproxify.type"          // http | tcp | udp (défaut: http)
	LabelHost            = "goproxify.host"          // ex: app.example.fr
	LabelPort            = "goproxify.port"          // port de l'application
	LabelBackendURL      = "goproxify.backend"       // URL complète ex: http://app:8080
	LabelTLS             = "goproxify.tls"           // "true" active la terminaison TLS
	LabelHTTPS           = "goproxify.https"         // "true" = backend en HTTPS
	LabelPassthrough     = "goproxify.passthrough"   // "true" = SSL passthrough
	LabelRateLimit       = "goproxify.rate_limit"    // "100/s" ou "100/s:50"
	LabelRateLimitRPS    = "goproxify.rate_limit.rps"   // alias générateur UI
	LabelRateLimitBurst  = "goproxify.rate_limit.burst" // optionnel
	LabelIPFilter        = "goproxify.ip_filter"     // "allow:10.0.0.0/8,192.168.0.0/16"
	LabelCORS            = "goproxify.cors"          // origins séparés par virgule (pas "true"/*)
	LabelGeoIP           = "goproxify.geo_ip"        // "allow:FR,DE"
	LabelSnippets        = "goproxify.snippets"      // IDs snippets Admin, CSV
	LabelAuthProvider    = "goproxify.auth_provider" // ID fournisseur auth Admin
	LabelWAF                    = "goproxify.waf"                     // true|block|detect
	LabelWAFAnomalyThreshold    = "goproxify.waf.anomaly_threshold"    // ex: "10" (score cumulatif)
	LabelWAFMaxBodyMB           = "goproxify.waf.max_body_mb"          // ex: "10"
	LabelWAFExcludeIDs          = "goproxify.waf.exclude_ids"          // CSV d'IDs ex: "942100,941100"
	LabelWAFBehavior            = "goproxify.waf.behavior"             // "true" active l'analyse comportementale
	LabelWAFBehaviorWindow      = "goproxify.waf.behavior.window"      // ex: "60" (secondes)
	LabelWAFBehaviorThreshold   = "goproxify.waf.behavior.threshold"   // ex: "8"
	LabelWAFTrustedProxies      = "goproxify.waf.trusted_proxies"      // CSV de CIDRs ex: "10.0.0.0/8"
	LabelSentinelWhitelist        = "goproxify.sentinel.whitelist"          // CSV IPs/CIDRs exemptés du moteur Sentinel
	LabelSentinelWhitelistNetwork = "goproxify.sentinel.whitelist.network"  // "true" : exempte automatiquement le réseau Docker du container
	LabelSentinelWhitelistSelf    = "goproxify.sentinel.whitelist.self"     // "true" : exempte l'IP du container lui-même
	LabelBot                    = "goproxify.bot"                      // "true"
	LabelBotMode                = "goproxify.bot.mode"                 // block|monitor|log|challenge
	LabelLogs            = "goproxify.logs"          // "true" active le log forwarding
	LabelUpdateAuto      = "goproxify.update.auto"   // "true" mise à jour auto
	LabelUpdatePrune     = "goproxify.update.prune"  // "true" supprime les anciennes images
	LabelUpdateSchedule  = "goproxify.update.schedule"        // cron ex: "0 3 * * *"
	LabelUpdateRollback  = "goproxify.update.rollback_timeout" // "60s"
	LabelHealthRestart   = "goproxify.healthcheck.restart_max" // max restarts avant recreate
	LabelHealthRecreate  = "goproxify.healthcheck.recreate_timeout" // délai avant rollback
	LabelIP              = "goproxify.ip"                     // IP du conteneur (surcharge l'auto-détection)
	LabelCanary          = "goproxify.canary"                 // "true" = backend canary
	LabelCanaryWeight    = "goproxify.canary.weight"          // % du trafic (défaut: 10)
	LabelShadow          = "goproxify.shadow"                 // "true" = backend shadow mirror

	// Comportement HTTP
	LabelPreserveHost = "goproxify.preserve_host" // "true" transmet le Host original au backend
	LabelWebsocket    = "goproxify.websocket"      // "true" active le support WebSocket
	LabelHTTPVersion  = "goproxify.http_version"   // "1.1" | "2" (version HTTP vers backend)
	LabelRequestID    = "goproxify.request_id"     // "true" injecte X-Request-ID

	// Réécriture d'URL
	LabelStripPrefix  = "goproxify.strip_prefix"  // préfixe à retirer avant de transmettre
	LabelPathRewrite  = "goproxify.path_rewrite"  // réécriture de chemin ex: /api → /v2/api

	// Timeouts & limites
	LabelConnectTimeout  = "goproxify.timeout.connect"   // ex: "5s"
	LabelResponseTimeout = "goproxify.timeout.response"  // ex: "30s"
	LabelSendTimeout     = "goproxify.timeout.send"      // ex: "10s"
	LabelMaxBodySize     = "goproxify.max_body_size"      // en octets ou suffixe ex: "10m"

	// Load balancing & résilience
	LabelLB            = "goproxify.lb"              // round_robin | weighted | adaptive
	LabelStickyCookie  = "goproxify.sticky_cookie"   // nom du cookie de session sticky
	LabelRetry         = "goproxify.retry"            // "3" ou "3:500ms"
	LabelCircuitBreaker = "goproxify.circuit_breaker" // "5:30s" (seuil erreurs:délai ouverture)
	LabelLimitConn     = "goproxify.limit_conn"       // "50" connexions simultanées max
	LabelBackpressure  = "goproxify.backpressure"     // "200" | "200:100" | "200:100:2s" (max requêtes simultanées[:file[:attente max]])
	LabelSlowStart     = "goproxify.slow_start"       // "30" (secondes) ou "30s" : montée en charge d'un nouveau backend

	// En-têtes
	LabelAddHeaders    = "goproxify.headers.add"    // "X-Foo:bar,X-Baz:qux"
	LabelRemoveHeaders = "goproxify.headers.remove" // "X-Powered-By,Server"

	// Authentification
	LabelJWT  = "goproxify.jwt"  // URL JWKS du fournisseur (https://idp/.well-known/jwks.json)
	LabelJWTIssuer   = "goproxify.jwt.issuer"   // issuer attendu (optionnel)
	LabelJWTAudience = "goproxify.jwt.audience" // audience attendue (optionnel)
	LabelMTLS = "goproxify.mtls" // chemin du fichier CA (PEM) lisible par le Core ; certificat client exigé

	// Cache
	LabelCache = "goproxify.cache" // "60s" ou "true" pour les valeurs par défaut

	// Logs
	LabelLogFormat = "goproxify.logs.format" // combined | json | minimal
	LabelLogLevel  = "goproxify.logs.level"  // debug | info | warn | error
)

// Rôles de discovery pour Canary / Shadow.
const (
	RoleNormal = "normal"
	RoleCanary = "canary"
	RoleShadow = "shadow"
)

// ProxySpec est la config d'un proxy déduit des labels Docker.
type ProxySpec struct {
	ContainerID   string
	ContainerName string
	Image         string
	NetworkID     string
	IPAddress     string // IP du conteneur dans son réseau Docker

	Type        string // http | tcp | udp
	Host        string
	Aliases     []string // hostnames secondaires (même route)
	Paths       []string // préfixes publics (locations + strip)
	Port        int
	BackendURL  string
	TLS         bool
	Passthrough bool

	RateLimit string
	IPFilter  string
	CORS      string
	GeoIP     string

	SnippetIDs     string // CSV d'IDs snippets Admin
	AuthProviderID string
	WAF                 string // true|block|detect
	WAFAnomalyThreshold int    // 0 = premier match
	WAFMaxBodyMB        int
	WAFExcludeIDs       string // CSV d'IDs
	WAFBehavior         bool
	WAFBehaviorWindow   int // secondes
	WAFBehaviorThreshold int
	WAFTrustedProxies   string // CSV CIDRs
	SentinelWhitelist        string // CSV IPs/CIDRs exemptés du moteur Sentinel
	SentinelWhitelistNetwork bool   // true = résoudre le CIDR du réseau Docker et l'ajouter
	SentinelWhitelistSelf    bool   // true = ajouter l'IP du container lui-même
	Bot                 string // "true"
	BotMode             string // block|monitor|log|challenge

	LogForwarding bool
	LogFormat     string // combined | json | minimal
	LogLevel      string // debug | info | warn | error
	UpdateAuto    bool
	UpdatePrune   bool

	HealthRestartMax       int
	HealthRecreateTimeout  string

	// Comportement HTTP
	PreserveHost bool
	Websocket    bool
	HTTPVersion  string // "1.1" | "2"
	RequestID    bool

	// Réécriture d'URL
	StripPrefix string
	PathRewrite string

	// Timeouts & limites
	ConnectTimeout  string
	ResponseTimeout string
	SendTimeout     string
	MaxBodySize     string

	// Load balancing & résilience
	LB            string // round_robin | weighted | adaptive
	StickyCookie  string
	Retry         string // "3" ou "3:500ms"
	CircuitBreaker string // "5:30s"
	LimitConn     int
	Backpressure  string // "200:100:2s"
	SlowStart     string // "30" ou "30s"

	// En-têtes
	AddHeaders    string // "X-Foo:bar,X-Baz:qux"
	RemoveHeaders string // "X-Powered-By,Server"

	// Authentification avancée
	JWT  string
	MTLS string
	JWTIssuer   string
	JWTAudience string

	// Cache
	Cache string

	// Role : normal | canary | shadow (dérivé des labels canary/shadow).
	Role         string
	CanaryWeight int // % trafic canary, défaut 10
}

// ParseLabels construit un ProxySpec depuis les labels d'un conteneur.
// Retourne nil si le label goproxify.enable n'est pas "true".
// goproxify.host accepte plusieurs hostnames séparés par des virgules
// (premier = host, suivants = aliases). Un chemin optionnel (/admin) est
// exposé comme location avec strip-prefix.
// exposedPorts : ports internes exposés par le conteneur (ex: {"3000/tcp":{}}).
// containerIP  : IP du conteneur dans son réseau Docker (peut être vide).
func ParseLabels(containerID, containerName, image, networkID string, labels map[string]string, exposedPorts map[string]struct{}, containerIP string) *ProxySpec {
	specs := ParseLabelsMulti(containerID, containerName, image, networkID, labels, exposedPorts, containerIP)
	if len(specs) == 0 {
		return nil
	}
	return specs[0]
}

// ParseLabelsMulti retourne un ProxySpec pour le conteneur.
// goproxify.host CSV : premier hostname = Host, suivants = Aliases ;
// un chemin (/admin) devient une location avec strip-prefix.
func ParseLabelsMulti(containerID, containerName, image, networkID string, labels map[string]string, exposedPorts map[string]struct{}, containerIP string) []*ProxySpec {
	if !boolLabel(labels, LabelEnable) {
		return nil
	}

	// Résolution du port : label > premier port exposé > 80
	port := intLabel(labels, LabelPort, 0)
	if port == 0 {
		port = firstExposedPort(exposedPorts)
	}
	if port == 0 {
		port = 80
	}

	// Résolution de l'IP : label > IP Docker > nom du conteneur
	ip := labels[LabelIP]
	if ip == "" {
		ip = containerIP
	}
	if ip == "" {
		ip = strings.TrimPrefix(containerName, "/")
	}

	backendURL := labels[LabelBackendURL]
	if backendURL == "" {
		scheme := "http"
		if boolLabel(labels, LabelHTTPS) {
			scheme = "https"
		}
		backendURL = scheme + "://" + ip + ":" + strconv.Itoa(port)
	}

	role, canaryWeight := parseTrafficRole(labels)

	refs := gplabels.ParseHostCSV(labels[LabelHost])
	if len(refs) == 0 {
		return nil
	}
	host, aliases := gplabels.UniqueHosts(refs)
	paths := gplabels.UniquePaths(refs)
	if host == "" {
		return nil
	}
	if aliases == nil {
		aliases = []string{}
	}
	if paths == nil {
		paths = []string{}
	}

	return []*ProxySpec{{
		ContainerID:   containerID,
		ContainerName: containerName,
		Image:         image,
		NetworkID:     networkID,
		IPAddress:     containerIP,

		Type:        stringLabel(labels, LabelType, "http"),
		Host:        host,
		Aliases:     aliases,
		Paths:       paths,
		Port:        port,
		BackendURL:  backendURL,
		TLS:         boolLabel(labels, LabelTLS),
		Passthrough: boolLabel(labels, LabelPassthrough),

		RateLimit: resolveRateLimitLabel(labels),
		IPFilter:  labels[LabelIPFilter],
		CORS:      labels[LabelCORS],
		GeoIP:     labels[LabelGeoIP],

		SnippetIDs:     labels[LabelSnippets],
		AuthProviderID: labels[LabelAuthProvider],
		WAF:                  labels[LabelWAF],
		WAFAnomalyThreshold:  intLabel(labels, LabelWAFAnomalyThreshold, 0),
		WAFMaxBodyMB:         intLabel(labels, LabelWAFMaxBodyMB, 0),
		WAFExcludeIDs:        labels[LabelWAFExcludeIDs],
		WAFBehavior:          boolLabel(labels, LabelWAFBehavior),
		WAFBehaviorWindow:    intLabel(labels, LabelWAFBehaviorWindow, 0),
		WAFBehaviorThreshold: intLabel(labels, LabelWAFBehaviorThreshold, 0),
		WAFTrustedProxies:    labels[LabelWAFTrustedProxies],
		SentinelWhitelist:        labels[LabelSentinelWhitelist],
		SentinelWhitelistNetwork: boolLabel(labels, LabelSentinelWhitelistNetwork),
		SentinelWhitelistSelf:    boolLabel(labels, LabelSentinelWhitelistSelf),
		Bot:                  labels[LabelBot],
		BotMode:              stringLabel(labels, LabelBotMode, ""),

		LogForwarding: boolLabel(labels, LabelLogs),
		LogFormat:     stringLabel(labels, LabelLogFormat, ""),
		LogLevel:      stringLabel(labels, LabelLogLevel, ""),
		UpdateAuto:    boolLabel(labels, LabelUpdateAuto),
		UpdatePrune:   boolLabel(labels, LabelUpdatePrune),

		HealthRestartMax:      intLabel(labels, LabelHealthRestart, 3),
		HealthRecreateTimeout: stringLabel(labels, LabelHealthRecreate, "30s"),

		PreserveHost: boolLabel(labels, LabelPreserveHost),
		Websocket:    boolLabel(labels, LabelWebsocket),
		HTTPVersion:  stringLabel(labels, LabelHTTPVersion, ""),
		RequestID:    boolLabel(labels, LabelRequestID),

		StripPrefix: stringLabel(labels, LabelStripPrefix, ""),
		PathRewrite: stringLabel(labels, LabelPathRewrite, ""),

		ConnectTimeout:  stringLabel(labels, LabelConnectTimeout, ""),
		ResponseTimeout: stringLabel(labels, LabelResponseTimeout, ""),
		SendTimeout:     stringLabel(labels, LabelSendTimeout, ""),
		MaxBodySize:     stringLabel(labels, LabelMaxBodySize, ""),

		LB:             stringLabel(labels, LabelLB, ""),
		StickyCookie:   stringLabel(labels, LabelStickyCookie, ""),
		Retry:          stringLabel(labels, LabelRetry, ""),
		CircuitBreaker: stringLabel(labels, LabelCircuitBreaker, ""),
		LimitConn:      intLabel(labels, LabelLimitConn, 0),
		Backpressure:   stringLabel(labels, LabelBackpressure, ""),
		SlowStart:      stringLabel(labels, LabelSlowStart, ""),

		AddHeaders:    stringLabel(labels, LabelAddHeaders, ""),
		RemoveHeaders: stringLabel(labels, LabelRemoveHeaders, ""),

		JWT:  stringLabel(labels, LabelJWT, ""),
		MTLS: stringLabel(labels, LabelMTLS, ""),
		JWTIssuer:   stringLabel(labels, LabelJWTIssuer, ""),
		JWTAudience: stringLabel(labels, LabelJWTAudience, ""),

		Cache: stringLabel(labels, LabelCache, ""),

		Role:         role,
		CanaryWeight: canaryWeight,
	}}
}

// resolveRateLimitLabel préfère goproxify.rate_limit, sinon .rps (+ .burst).
func resolveRateLimitLabel(labels map[string]string) string {
	if v := strings.TrimSpace(labels[LabelRateLimit]); v != "" {
		return v
	}
	rps := strings.TrimSpace(labels[LabelRateLimitRPS])
	if rps == "" {
		return ""
	}
	if burst := strings.TrimSpace(labels[LabelRateLimitBurst]); burst != "" {
		return rps + "/s:" + burst
	}
	return rps + "/s"
}

// parseTrafficRole dérive role + poids canary depuis les labels.
// Si canary et shadow sont tous deux true, canary gagne.
func parseTrafficRole(labels map[string]string) (role string, canaryWeight int) {
	canary := boolLabel(labels, LabelCanary)
	shadow := boolLabel(labels, LabelShadow)
	weight := intLabel(labels, LabelCanaryWeight, 10)
	if weight < 0 {
		weight = 0
	}
	if weight > 100 {
		weight = 100
	}
	switch {
	case canary:
		return RoleCanary, weight
	case shadow:
		return RoleShadow, weight
	default:
		return RoleNormal, weight
	}
}

// firstExposedPort retourne le premier port TCP exposé depuis ExposedPorts Docker.
// Le format est "3000/tcp" ou "80/udp".
func firstExposedPort(ports map[string]struct{}) int {
	for k := range ports {
		if strings.HasSuffix(k, "/tcp") {
			n, err := strconv.Atoi(strings.TrimSuffix(k, "/tcp"))
			if err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

func boolLabel(labels map[string]string, key string) bool {
	return strings.EqualFold(labels[key], "true")
}

func stringLabel(labels map[string]string, key, def string) string {
	if v := labels[key]; v != "" {
		return v
	}
	return def
}

func intLabel(labels map[string]string, key string, def int) int {
	if v := labels[key]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
