// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"strconv"
	"strings"
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
	LabelIPFilter        = "goproxify.ip_filter"     // "allow:10.0.0.0/8,203.0.113.10/16"
	LabelCORS            = "goproxify.cors"          // origins séparés par virgule (pas "true"/*)
	LabelGeoIP           = "goproxify.geo_ip"        // "allow:FR,DE"
	LabelSnippets        = "goproxify.snippets"      // IDs snippets Admin, CSV
	LabelAuthProvider    = "goproxify.auth_provider" // ID fournisseur auth Admin
	LabelWAF             = "goproxify.waf"           // true|block|detect
	LabelBot             = "goproxify.bot"           // "true"
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
	WAF            string // true|block|detect
	Bot            string // "true"

	LogForwarding bool
	UpdateAuto    bool
	UpdatePrune   bool

	HealthRestartMax       int
	HealthRecreateTimeout  string

	// Role : normal | canary | shadow (dérivé des labels canary/shadow).
	Role         string
	CanaryWeight int // % trafic canary, défaut 10
}

// ParseLabels construit un ou plusieurs ProxySpec depuis les labels d'un conteneur.
// Retourne nil si le label goproxify.enable n'est pas "true".
// goproxify.host accepte plusieurs hostnames séparés par des virgules.
// exposedPorts : ports internes exposés par le conteneur (ex: {"3000/tcp":{}}).
// containerIP  : IP du conteneur dans son réseau Docker (peut être vide).
func ParseLabels(containerID, containerName, image, networkID string, labels map[string]string, exposedPorts map[string]struct{}, containerIP string) *ProxySpec {
	specs := ParseLabelsMulti(containerID, containerName, image, networkID, labels, exposedPorts, containerIP)
	if len(specs) == 0 {
		return nil
	}
	return specs[0]
}

// ParseLabelsMulti retourne un ProxySpec par hostname déclaré dans goproxify.host.
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

	hosts := strings.Split(labels[LabelHost], ",")
	specs := make([]*ProxySpec, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		specs = append(specs, &ProxySpec{
			ContainerID:   containerID,
			ContainerName: containerName,
			Image:         image,
			NetworkID:     networkID,
			IPAddress:     containerIP,

			Type:        stringLabel(labels, LabelType, "http"),
			Host:        h,
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
			WAF:            labels[LabelWAF],
			Bot:            labels[LabelBot],

			LogForwarding: boolLabel(labels, LabelLogs),
			UpdateAuto:    boolLabel(labels, LabelUpdateAuto),
			UpdatePrune:   boolLabel(labels, LabelUpdatePrune),

			HealthRestartMax:      intLabel(labels, LabelHealthRestart, 3),
			HealthRecreateTimeout: stringLabel(labels, LabelHealthRecreate, "30s"),

			Role:         role,
			CanaryWeight: canaryWeight,
		})
	}
	return specs
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
