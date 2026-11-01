// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"time"
)

// RouteOrigin identifie la route découverte (ID de route et passerelle qui l'annonçait) dont un proxy est issu.
type RouteOrigin struct {
	ID   string `json:"id"`
	Edge string `json:"edge,omitempty"`
}

// Route décrit un proxy HTTP ou TCP/UDP vers un ou plusieurs backends.
type Route struct {
	ID       string    `json:"id"`
	Host     string    `json:"host"`              // ex: "app.example.fr" — vide pour TCP/UDP
	Aliases  []string  `json:"aliases,omitempty"` // domaines secondaires pointant vers la même route
	Type     RouteType `json:"type"`              // http | tcp | udp
	Backends []Backend `json:"backends"`

	// AgentName est le nœud Agent qui a découvert / injecté cette route (docker:/k8s:).
	AgentName string `json:"agent_name,omitempty"`

	// Origin dit quelle route découverte a donné ce proxy (conversion « conteneur → proxy ») : l'Admin signale le proxy
	// dont le conteneur d'origine a disparu. N'a aucun effet sur le routage.
	Origin *RouteOrigin `json:"origin,omitempty"`

	// DelegateAPIEndpoint est l'endpoint interne (http://host:8000) de la passerelle déléguée.
	// Renseigné par Admin lors du push des délégations. Utilisé pour le relay passerelle→Passerelle.
	DelegateAPIEndpoint string `json:"delegate_api_endpoint,omitempty"`

	// TLS
	TLSEnabled     bool   `json:"tls_enabled"`
	TLSPassthrough bool   `json:"tls_passthrough"`           // SNI passthrough sans déchiffrement
	CertName       string `json:"cert_name"`                 // clé dans CertStore
	TLSSkipVerify  bool   `json:"tls_skip_verify,omitempty"` // ignorer le certificat backend auto-signé
	// nil (absent) = conserver le Host original (défaut, comme nginx) ; false = envoyer le host du backend
	PreserveHost *bool `json:"preserve_host,omitempty"`
	// nil/true = autoriser WebSocket ; false = rejeter Upgrade: websocket
	Websocket *bool `json:"websocket,omitempty"`
	// auto (défaut) | 1.1 | 2 — version HTTP vers le backend
	HttpVersion string `json:"http_version,omitempty"`
	// nil/true = générer/propager X-Request-ID ; false = ne pas exposer au client ni au backend
	RequestID *bool `json:"request_id,omitempty"`

	// TCP/UDP
	ListenPort int `json:"listen_port,omitempty"` // port d'écoute local (L4)
	// IdleTimeoutSec : une connexion TCP (L4) sans octet dans aucun sens depuis cette durée est fermée. 0 = jamais
	// (défaut : les pools de connexions d'une base de données restent inactifs des heures). Pour une route UDP, c'est
	// la durée d'inactivité d'une session (défaut 60 s). 86 400 au plus.
	IdleTimeoutSec int `json:"idle_timeout_sec,omitempty"`

	// Plugins WebAssembly attachés à la route, exécutés dans l'ordre (ADR 0008).
	Plugins []PluginRef `json:"plugins,omitempty"`

	// Sécurité
	RateLimit           *RateLimitConfig           `json:"rate_limit,omitempty"`
	LimitConn           *LimitConnConfig           `json:"limit_conn,omitempty"`
	Backpressure        *BackpressureConfig        `json:"backpressure,omitempty"`
	IPFilter            *IPFilterConfig            `json:"ip_filter,omitempty"`
	GeoIP               *GeoIPConfig               `json:"geo_ip,omitempty"`
	Headers             *HeadersConfig             `json:"headers,omitempty"`
	HeadersManipulation *HeadersManipulationConfig `json:"headers_manipulation,omitempty"`
	CORS                *CORSConfig                `json:"cors,omitempty"`
	WAF                 *WAFConfig                 `json:"waf,omitempty"`
	Bot                 *BotConfig                 `json:"bot,omitempty"`
	JWT                 *JWTConfig                 `json:"jwt,omitempty"`
	MTLS                *MTLSConfig                `json:"mtls,omitempty"`
	SSO                 *SSOConfig                 `json:"sso,omitempty"`
	// Surface apprend la surface du proxy (ADR 0016) : ce que son trafic légitime utilise.
	Surface *SurfaceConfig `json:"surface,omitempty"`

	// Cache proxy sur disque (vide = désactivé)
	CachePath string `json:"cache_path,omitempty"`
	// Cache avancé : TTL par code, bypass, no-store (équivalent nginx proxy_cache_valid / proxy_cache_bypass).
	Cache *CacheConfig `json:"cache,omitempty"`

	// Compression négocie la compression des réponses (zstd, br, gzip) selon Accept-Encoding.
	Compression *CompressionConfig `json:"compression,omitempty"`

	// ProxyProtocol : "v1" ou "v2" = la passerelle écrit l'en-tête PROXY (IP du client) au début
	// de chaque connexion vers le backend (le backend doit l'attendre). Vide = désactivé.
	// Sur une route HTTP, chaque requête ouvre sa propre connexion (pas de réutilisation :
	// l'en-tête décrit un seul client).
	ProxyProtocol string `json:"proxy_protocol,omitempty"`

	// Timeouts vers le backend (0 = valeurs par défaut Go)
	ConnectTimeout  time.Duration `json:"connect_timeout,omitempty"`  // TCP dial (nginx: proxy_connect_timeout)
	ResponseTimeout time.Duration `json:"response_timeout,omitempty"` // attente headers réponse (nginx: proxy_read_timeout)
	SendTimeout     time.Duration `json:"send_timeout,omitempty"`     // envoi requête backend (nginx: proxy_send_timeout)
	BufferSize      int           `json:"buffer_size,omitempty"`      // taille buffer réponse en octets (nginx: proxy_buffer_size)
	MaxBodySize     int64         `json:"max_body_size,omitempty"`    // taille max corps requête client en octets (nginx: client_max_body_size ; 0 = défaut 100 Mo, -1 = illimité)

	// Résilience
	LB             LBAlgorithm  `json:"lb"` // round_robin | weighted | adaptive
	CircuitBreaker *CBConfig    `json:"circuit_breaker,omitempty"`
	Retry          *RetryConfig `json:"retry,omitempty"`
	StickyCookie   string       `json:"sticky_cookie,omitempty"`
	// SlowStartSec : durée (s) de montée en charge d'un backend nouvellement sain ou nouvellement ajouté (0 = désactivé).
	SlowStartSec int                `json:"slow_start_sec,omitempty"`
	HealthCheck  *HealthCheckConfig `json:"health_check,omitempty"`

	// Pipeline de transformation de requête/réponse (headers, réécriture URL).
	Transform *RequestTransform `json:"transform,omitempty"`

	// Trafic avancé
	Canary *CanaryConfig `json:"canary,omitempty"`
	Shadow *ShadowConfig `json:"shadow,omitempty"`
	// Split répartit le trafic entre plusieurs backends nommés selon des poids (A/B, déploiement progressif).
	Split *SplitConfig `json:"split,omitempty"`
	// Maintenance coupe la route avec une page 503, sans la supprimer.
	Maintenance *MaintenanceConfig `json:"maintenance,omitempty"`
	// SignedURL n'accepte que les URLs signées (HMAC + expiration), comme nginx secure_link.
	SignedURL *SignedURLConfig `json:"signed_url,omitempty"`
	// GraphQL borne la profondeur et la taille des requêtes GraphQL.
	GraphQL *GraphQLConfig `json:"graphql,omitempty"`
	// Static sert un dossier local de la passerelle au lieu de proxifier (aucun backend requis).
	Static *StaticConfig `json:"static,omitempty"`

	// RequestSchema valide le corps JSON des requêtes contre un JSON Schema.
	RequestSchema *RequestSchemaConfig `json:"request_schema,omitempty"`
	// OpenAPI valide chemins, méthodes, paramètres et corps JSON des requêtes contre une spécification OpenAPI 3.0/3.1.
	OpenAPI *OpenAPIConfig `json:"openapi,omitempty"`
	// GRPCTranscode expose un backend gRPC en REST/JSON (annotations google.api.http), la passerelle traduisant requêtes et réponses.
	GRPCTranscode *GRPCTranscodeConfig `json:"grpc_transcode,omitempty"`

	// Hedge double une requête GET/HEAD lente vers un autre backend ; la première réponse gagne.
	Hedge *HedgeConfig `json:"hedge,omitempty"`
	// GRPCWeb traduit gRPC-Web (navigateurs) en gRPC vers le backend, qui doit parler HTTP/2.
	GRPCWeb bool `json:"grpc_web,omitempty"`
	// Bandwidth plafonne le débit de chaque réponse (octets par seconde, par connexion).
	Bandwidth *BandwidthConfig `json:"bandwidth,omitempty"`
	// RedactJSON masque des champs des réponses JSON avant de les envoyer au client.
	RedactJSON *RedactConfig `json:"redact_json,omitempty"`
	// HTMLInject insère un fragment (script, balise) dans les pages HTML du backend.
	HTMLInject *HTMLInjectConfig `json:"html_inject,omitempty"`
	Conditions []Condition       `json:"conditions,omitempty"`
	Locations  []Location        `json:"locations,omitempty"`
	// StripPrefix is applied at proxy time (usually copied from the matched Location).
	StripPrefix string `json:"strip_prefix,omitempty"`
	// StripPrefixFold: StripPrefix s'applique sans tenir compte de la casse (posé par MergeLocation).
	StripPrefixFold bool `json:"-"`
	// PathRewrite is a replacement template applied after a regex Location match.
	// Use $1, $2 … to reference capture groups from the matched Location regex.
	PathRewrite string `json:"path_rewrite,omitempty"`
	// PathRewritePattern holds the source regex pattern when PathRewrite is set.
	// It is populated by MergeLocation and not persisted to JSON.
	PathRewritePattern string `json:"-"`

	// ProxyRedirects réécrit le header Location/Refresh des réponses de redirection
	// venant du backend (équivalent nginx proxy_redirect).
	// Chaque règle remplace la première correspondance ; les règles sont évaluées en ordre.
	ProxyRedirects []ProxyRedirect `json:"proxy_redirects,omitempty"`

	// RequestVars définit des variables dérivées de la requête (équivalent nginx map {}).
	// Utilisables dans request_set_header via le template ${var_name}.
	RequestVars []RequestVar `json:"request_vars,omitempty"`

	// SubFilters réécrit le corps des réponses texte du backend
	// (équivalent nginx sub_filter). Appliqué uniquement sur Content-Type text/* et application/json.
	SubFilters []SubFilter `json:"sub_filters,omitempty"`

	// CookieDomain remplace l'attribut Domain= dans les Set-Cookie du backend
	// (équivalent nginx proxy_cookie_domain <backend_domain> <replace>).
	// Slice de paires {From, To} ; vide = pas de réécriture.
	CookieDomains []CookieRewrite `json:"cookie_domains,omitempty"`
	// CookiePaths remplace l'attribut Path= dans les Set-Cookie du backend
	// (équivalent nginx proxy_cookie_path <backend_path> <replace>).
	CookiePaths []CookieRewrite `json:"cookie_paths,omitempty"`

	// EphorWhitelist : IPs/CIDRs exemptés du moteur de détection automatique pour cette route.
	// Ces entrées sont fusionnées dans la whitelist globale du moteur Ephor.
	EphorWhitelist []string `json:"ephor_whitelist,omitempty"`

	// Observabilité par route
	Logging *RouteLoggingConfig `json:"logging,omitempty"`

	// Pages d'erreur personnalisées
	ErrorPages *ErrorPagesConfig `json:"error_pages,omitempty"`

	// Références vers des ressources passerelle partagées
	// SnippetUnresolved liste les snippets référencés mais introuvables ou illisibles (calculé par
	// ResolveSnippets, jamais sérialisé) : la route refuse alors le trafic au lieu de perdre leur protection.
	SnippetUnresolved string   `json:"-"`
	SnippetIDs        []string `json:"snippet_ids,omitempty"`      // snippets à fusionner dans la config
	AuthProviderID    string   `json:"auth_provider_id,omitempty"` // fournisseur SSO/OIDC de la passerelle

	UpdatedAt time.Time `json:"updated_at"`
}

// RouteLoggingConfig configure le logging par route.
type RouteLoggingConfig struct {
	AccessLog bool   `json:"access_log"`       // activer le log d'accès (défaut: true)
	Format    string `json:"format,omitempty"` // combined | json | minimal | off
	Level     string `json:"level,omitempty"`  // debug | info | warn | error (erreurs proxy)
}

// ErrorPagesConfig configure les pages d'erreur personnalisées par code HTTP.
type ErrorPagesConfig struct {
	// Pages : legacy — clé "404"/"5xx" → HTML inline ou URL de redirection (http/https).
	Pages map[string]string `json:"pages,omitempty"`
	// Templates : clé "404"/"5xx" → UUID d'un template de la bibliothèque Admin.
	Templates map[string]string `json:"templates,omitempty"`
}

// GetPages expose Pages pour la résolution runtime.
func (c *ErrorPagesConfig) GetPages() map[string]string {
	if c == nil {
		return nil
	}
	return c.Pages
}

// GetTemplates expose Templates pour la résolution runtime.
func (c *ErrorPagesConfig) GetTemplates() map[string]string {
	if c == nil {
		return nil
	}
	return c.Templates
}

type RouteType string

const (
	RouteHTTP RouteType = "http"
	RouteTCP  RouteType = "tcp"
	RouteUDP  RouteType = "udp"
)

type Backend struct {
	URL               string `json:"url"`                    // ex: "http://10.0.0.5:3000" ou "10.0.0.5:5432" (L4)
	Weight            int    `json:"weight"`                 // 0 = égal aux autres
	ContainerID       string `json:"container_id,omitempty"` // discovery Docker — pour merge/retrait
	Image             string `json:"image,omitempty"`        // image du conteneur : inventaire des applications (ADR 0017)
	AgentName         string `json:"agent_name,omitempty"`
	OwnerEdgeEndpoint string `json:"owner_edge_endpoint,omitempty"` // si distant : gateway vers cette passerelle
	OwnerEdgeName     string `json:"owner_edge_name,omitempty"`
}

type LBAlgorithm string

const (
	LBRoundRobin LBAlgorithm = "round_robin"
	LBWeighted   LBAlgorithm = "weighted"
	LBAdaptive   LBAlgorithm = "adaptive"
)

type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"rps"`
	Burst             int     `json:"burst"`
	// KeyBy détermine la clé de rate-limit : "ip" (défaut), "jwt_sub", "jwt_email",
	// ou "jwt_claim:<nom>" pour un claim JWT arbitraire.
	// "header:<nom>" (clé d'API) et "cookie:<nom>" sont aussi acceptés.
	KeyBy string `json:"key_by,omitempty"`
	// Quota : nombre max de requêtes par clé et par QuotaPeriod ("minute" | "hour" | "day"),
	// en plus du débit instantané. 0 = pas de quota.
	Quota       int    `json:"quota,omitempty"`
	QuotaPeriod string `json:"quota_period,omitempty"`
	// Shared : les passerelles d'un groupe HA échangent leurs comptes de quota (au plus ~2 s de retard) pour appliquer un quota commun,
	// et le débit qu'elles admettent par clé (~0,5 s) : chacune retire la part de ses pairs de son débit instantané (rps).
	Shared bool `json:"shared,omitempty"`
}

// LimitConnConfig limite le nombre de connexions simultanées par IP
// (équivalent nginx limit_conn).
type LimitConnConfig struct {
	MaxPerIP int `json:"max_per_ip"` // 0 = désactivé
}

// BackpressureConfig plafonne les requêtes simultanées vers les backends d'une route
// et met les excédentaires en file bornée ; au-delà, 503 + Retry-After.
type BackpressureConfig struct {
	MaxInflight    int `json:"max_inflight"`               // 0 = désactivé
	Queue          int `json:"queue,omitempty"`            // requêtes en attente max (0 = rejet immédiat)
	QueueTimeoutMs int `json:"queue_timeout_ms,omitempty"` // attente max en file (défaut 1000)
}

// PluginRef attache un plugin WASM installé sur la passerelle à une route, avec sa configuration.
type PluginRef struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config,omitempty"`
}

type IPFilterConfig struct {
	Mode  string   `json:"mode"` // allow | deny
	CIDRs []string `json:"cidrs"`
}

// CacheConfig configure le cache proxy HTTP avancé par route.
// Équivalent nginx proxy_cache_valid / proxy_cache_bypass.
type CacheConfig struct {
	Enabled bool `json:"enabled"`
	// Dir est le répertoire de stockage (vide = valeur de CachePath si présent, sinon /tmp/goproxify-cache/<route-id>).
	Dir string `json:"dir,omitempty"`
	// ValidRules définit le TTL par code de statut (équivalent proxy_cache_valid 200 10m).
	// Chaque règle s'applique si le code de la réponse est dans StatusCodes (vide = tous).
	ValidRules []CacheValidRule `json:"valid_rules,omitempty"`
	// BypassHeaders : si l'un de ces headers de requête est non-vide, le cache est ignoré (bypass + no-store).
	BypassHeaders []string `json:"bypass_headers,omitempty"`
	// BypassCookies : si l'un de ces cookies est présent, le cache est ignoré.
	BypassCookies []string `json:"bypass_cookies,omitempty"`
	// IgnoreCookies : met en cache même si la requête porte des cookies (ils ne
	// participent pas à la clé). Sans cette option ni VaryCookies, toute requête
	// avec cookie ou Authorization contourne le cache.
	IgnoreCookies bool `json:"ignore_cookies,omitempty"`
	// VaryCookies : cookies dont la valeur fait partie de la clé de cache (autorise le cache avec cookies).
	VaryCookies []string `json:"vary_cookies,omitempty"`
	// Methods : méthodes mises en cache (défaut : ["GET", "HEAD"]).
	Methods []string `json:"methods,omitempty"`
	// StaleWhileRevalidate : durée pendant laquelle une entrée expirée est servie
	// pendant qu'elle est revalidée en arrière-plan (ex. "30s"). La directive
	// stale-while-revalidate du backend a priorité.
	StaleWhileRevalidate string `json:"stale_while_revalidate,omitempty"`
	// StaleIfError : durée pendant laquelle une entrée expirée remplace une
	// réponse 5xx du backend (ex. "1h"). La directive stale-if-error du backend a priorité.
	StaleIfError string `json:"stale_if_error,omitempty"`
	// DisableCoalescing : désactive le regroupement des requêtes simultanées sur
	// un même MISS (une seule va au backend par défaut).
	DisableCoalescing bool `json:"disable_coalescing,omitempty"`
}

// CompressionConfig configure la compression des réponses vers le client.
type CompressionConfig struct {
	Enabled bool `json:"enabled"`
	// Algorithms par ordre de préférence serveur parmi zstd | br | gzip (défaut : zstd, br, gzip).
	Algorithms []string `json:"algorithms,omitempty"`
	// MinLength : taille minimale (octets) sous laquelle on ne compresse pas quand Content-Length est connu (défaut 1024).
	MinLength int `json:"min_length,omitempty"`
	// Level 1 (rapide) à 9 (max), traduit par algorithme ; 0 = défaut de chaque algorithme.
	Level int `json:"level,omitempty"`
	// Types : Content-Type compressés, "text/*" accepté (défaut : texte, JSON, JS, XML, SVG, polices).
	Types []string `json:"types,omitempty"`
}

// CacheValidRule associe un TTL à un ensemble de codes HTTP.
// Équivalent nginx `proxy_cache_valid 200 302 10m`.
type CacheValidRule struct {
	// StatusCodes : codes HTTP concernés. Vide = tous (équivalent "any").
	StatusCodes []int  `json:"status_codes,omitempty"`
	TTL         string `json:"ttl"` // ex: "10m", "1h", "30s"
}

// RequestVar définit une variable dérivée de la requête (équivalent nginx map {}).
// La variable est résolue à chaque requête et peut être injectée via request_set_header.
type RequestVar struct {
	Name    string           `json:"name"`              // nom de la variable (sans $)
	Source  string           `json:"source"`            // header | cookie | query | method | remote_ip | path
	Key     string           `json:"key,omitempty"`     // nom du header/cookie/query param (si source=header/cookie/query)
	Default string           `json:"default,omitempty"` // valeur si aucun cas ne correspond
	Cases   []RequestVarCase `json:"cases,omitempty"`
}

// RequestVarCase mappe un pattern à une valeur de variable.
type RequestVarCase struct {
	Pattern string `json:"pattern"`         // valeur ou regex à matcher
	Value   string `json:"value"`           // valeur retournée si pattern correspond
	Regex   bool   `json:"regex,omitempty"` // interpréter Pattern comme regex
}

// SubFilter décrit une règle de remplacement dans le corps des réponses texte.
// Si Regex est vrai, From est une expression régulière (avec captures $1…).
type SubFilter struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Regex bool   `json:"regex,omitempty"`
}

// CookieRewrite décrit une règle de remplacement d'attribut dans Set-Cookie.
// Si Regex est vrai, From est une expression régulière (avec captures $1…).
type CookieRewrite struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Regex bool   `json:"regex,omitempty"`
}

// ProxyRedirect décrit une règle de réécriture du header Location dans les
// réponses 3xx du backend. Équivalent nginx `proxy_redirect <from> <to>`.
// Si Regex est vrai, From est une expression régulière (avec captures $1…).
type ProxyRedirect struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Regex bool   `json:"regex,omitempty"`
}

type HeadersConfig struct {
	HSTS          bool              `json:"hsts"`
	HSTSMaxAge    int               `json:"hsts_max_age"`
	XFrameOptions string            `json:"x_frame_options"`
	HideServer    bool              `json:"hide_server"`
	Custom        map[string]string `json:"custom,omitempty"`
}

// HeadersManipulationConfig contrôle les en-têtes injectés vers le backend
// (équivalent nginx proxy_set_header X-Forwarded-* / X-Real-IP).
// ForwardedHeaders nil = injecter les 4 par défaut ; slice vide = n'en injecter aucun.
type HeadersManipulationConfig struct {
	// nil = les 4 headers par défaut ; slice vide = aucun.
	ForwardedHeaders  []string          `json:"forwarded_headers"`
	RequestSetHeader  map[string]string `json:"request_set_header,omitempty"`  // proxy_set_header Name value
	RequestHideHeader []string          `json:"request_hide_header,omitempty"` // proxy_hide_header / Del
	ResponseAddHeader []string          `json:"response_add_header,omitempty"` // legacy UI ; préférer headers.custom
}

// SurfaceConfig règle l'apprentissage de la surface d'un proxy. Mode : off (défaut) | learn. En learn la passerelle observe
// le trafic légitime et en tire un profil ; elle ne bloque rien.
type SurfaceConfig struct {
	Mode string `json:"mode,omitempty"`
	// Type : api (surface fermée : une liste de chemins a un sens) | site (contenu ouvert, milliers de chemins : le profil ne propose ni
	// politique de chemins ni ajouts, et sa convergence ne dépend pas des chemins). Vide : traité comme une API.
	Type string `json:"type,omitempty"`
}

type CORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers"`
	MaxAge         int      `json:"max_age"`
}

// GeoIPConfig configure le filtrage géographique par pays.
type GeoIPConfig struct {
	DBPath    string   `json:"db_path"`
	Mode      string   `json:"mode"`      // allow | deny
	Countries []string `json:"countries"` // codes ISO-3166-1 alpha-2
}

// RequestTransform décrit le pipeline de transformation de requête/réponse.
// Les opérations sont appliquées dans l'ordre : réécriture URL → headers requête → headers réponse.
type RequestTransform struct {
	// Réécriture de préfixe d'URL : /api/v1/foo → /v1/foo si RewriteFrom="/api/v1".
	RewriteFrom string `json:"rewrite_from,omitempty"`
	RewriteTo   string `json:"rewrite_to,omitempty"`
	// Headers ajoutés/supprimés sur la requête vers le backend.
	AddRequestHeaders    map[string]string `json:"add_request_headers,omitempty"`
	RemoveRequestHeaders []string          `json:"remove_request_headers,omitempty"`
	// Headers ajoutés/supprimés sur la réponse vers le client.
	AddResponseHeaders    map[string]string `json:"add_response_headers,omitempty"`
	RemoveResponseHeaders []string          `json:"remove_response_headers,omitempty"`
}

type CBConfig struct {
	Threshold int           `json:"threshold"` // nb d'échecs consécutifs
	Timeout   time.Duration `json:"timeout"`   // durée open → half-open
}

// HealthCheckConfig configure les sondes actives de santé des backends.
type HealthCheckConfig struct {
	Path               string        `json:"path,omitempty"`                // chemin sondé (défaut /health)
	Interval           time.Duration `json:"interval,omitempty"`            // fréquence (défaut 30s)
	Timeout            time.Duration `json:"timeout,omitempty"`             // timeout probe (défaut 5s)
	HealthyThreshold   int           `json:"healthy_threshold,omitempty"`   // succès consécutifs pour passer up (défaut 1)
	UnhealthyThreshold int           `json:"unhealthy_threshold,omitempty"` // échecs consécutifs pour passer down (défaut 1)
}

type RetryConfig struct {
	Attempts    int           `json:"attempts"`
	InitialWait time.Duration `json:"initial_wait"`
	MaxWait     time.Duration `json:"max_wait"`
}

// WAFExclusion exclut des règles du WAF sous certains chemins seulement. Un chemin est un préfixe sur frontière de segment :
// "/wp-admin/" couvre /wp-admin/post.php ; "/api/search" couvre /api/search et /api/search/x, pas /api/searchx. Les règles sont
// celles de rule_ids et, si platform est renseignée, celles que cette plateforme déclenche d'habitude à tort.
type WAFExclusion struct {
	Paths    []string `json:"paths"`
	RuleIDs  []int    `json:"rule_ids,omitempty"`
	Platform string   `json:"platform,omitempty"`
	// Note : pourquoi l'exclusion existe (pour celui qui relira la configuration).
	Note string `json:"note,omitempty"`
}

// WAFConfig configure le WAF par route.
type WAFConfig struct {
	Enabled          bool         `json:"enabled"`
	Mode             string       `json:"mode"` // detect | block
	ExcludeIDs       []int        `json:"exclude_ids"`
	MaxBodyMB        int          `json:"max_body_mb"`
	AnomalyThreshold int          `json:"anomaly_threshold"` // 0 = premier match, >0 = score cumulatif
	CustomRules      []CustomRule `json:"custom_rules,omitempty"`

	// Analyse comportementale — stateful, par IP, sur une fenêtre glissante.
	BehaviorEnabled   bool `json:"behavior_enabled"`
	BehaviorWindowSec int  `json:"behavior_window_s"`  // durée fenêtre (défaut 60s)
	BehaviorThreshold int  `json:"behavior_threshold"` // score avant action (défaut 8)

	// TrustedProxies : CIDRs des proxies de confiance dont les headers X-Forwarded-For
	// sont acceptés pour déterminer l'IP réelle du client.
	// Vide = pas de confiance (on utilise RemoteAddr directement).
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// Exclusions : des règles exclues sur certains chemins seulement. Partout ailleurs, ces règles restent actives : c'est l'exclusion
	// à préférer à exclude_ids, qui vaut pour tout le proxy. Une exclusion peut nommer une plateforme (`platform`) : ce sont alors ses
	// règles habituelles qui sont retirées sous ses chemins.
	Exclusions []WAFExclusion `json:"exclusions,omitempty"`

	// CustomRulesPath : chemin vers un fichier JSON de règles custom sur la passerelle.
	// Surveillé en temps réel — toute modification recharge les règles sans redémarrage.
	// Format : tableau de CustomRule (même schéma que custom_rules dans la config).
	// Exemple : /etc/goproxify/waf-custom-rules.json
	CustomRulesPath string `json:"custom_rules_path,omitempty"`

	// WAFWhitelistIPs : IPs/CIDRs exemptes du WAF pour cette route.
	// La protection d'Ephor reste active.
	WAFWhitelistIPs []string `json:"waf_whitelist_ips,omitempty"`
}

// CustomRule est une règle WAF définie par l'utilisateur.
type CustomRule struct {
	ID       int      `json:"id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"` // critical | high | medium | low
	Pattern  string   `json:"pattern"`  // regex Go
	Targets  []string `json:"targets"`  // uri | args | body | headers | cookies
	Message  string   `json:"message"`
	Score    int      `json:"score,omitempty"` // score anomalie (0 = déduit de la sévérité)
}

// BotConfig configure la protection bot.
type BotConfig struct {
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode,omitempty"` // block | monitor | log | challenge
	UABlacklist     []string `json:"ua_blacklist,omitempty"`
	JSChallenge     bool     `json:"js_challenge"`
	ChallengeSecret string   `json:"challenge_secret,omitempty"`
	// ChallengeProvider : pow (défaut, preuve de travail SHA-256 résolue par le navigateur) | turnstile | hcaptcha.
	ChallengeProvider string `json:"challenge_provider,omitempty"`
	// ChallengeDifficulty : bits de tête à zéro exigés de la preuve de travail (défaut 16, max 24 ; chaque bit double le travail).
	ChallengeDifficulty int `json:"challenge_difficulty,omitempty"`
	// ChallengeTTL : durée de validité de la preuve (défaut 24h, minimum 1m).
	ChallengeTTL string `json:"challenge_ttl,omitempty"`
	// ChallengeSiteKey / ChallengeProviderSecret : clés du fournisseur turnstile ou hcaptcha.
	ChallengeSiteKey        string `json:"challenge_site_key,omitempty"`
	ChallengeProviderSecret string `json:"challenge_provider_secret,omitempty"`
	// ChallengeExemptPaths : préfixes de chemin jamais défiés (API, webhooks, flux appelés par des machines).
	ChallengeExemptPaths []string `json:"challenge_exempt_paths,omitempty"`
}

// JWTConfig configure la validation JWT.
type JWTConfig struct {
	Enabled      bool   `json:"enabled"`
	JWKSURL      string `json:"jwks_url,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Audience     string `json:"audience,omitempty"`
	HeaderName   string `json:"header_name,omitempty"`
	ClaimsHeader string `json:"claims_header,omitempty"`
}

// MTLSConfig configure la validation mTLS des clients.
type MTLSConfig struct {
	Enabled           bool     `json:"enabled"`
	CACertFile        string   `json:"ca_cert_file,omitempty"`
	CACertPEM         string   `json:"ca_cert_pem,omitempty"`
	RequireClientCert bool     `json:"require_client_cert"`
	AllowedSANs       []string `json:"allowed_sans,omitempty"`
	SubjectHeader     string   `json:"subject_header,omitempty"`
}

// SSOConfig configure le provider SSO.
type SSOConfig struct {
	Enabled bool `json:"enabled"`
	// Provider : authentik | authelia | oauth2_proxy | basic | forward | pocket_id | oidc |
	//            keycloak | zitadel | google | microsoft | auth0 | okta | casdoor | dex |
	//            github | ldap | ldap_ad | saml
	Provider       string `json:"provider"`
	ForwardAuthURL string `json:"forward_auth_url,omitempty"`
	// ForwardAuthTimeoutMs : délai max du service d'authentification (défaut 5000).
	ForwardAuthTimeoutMs int `json:"forward_auth_timeout_ms,omitempty"`
	// ForwardAuthSignInURL : un 401 du service redirige le navigateur ici (?rd=<URL d'origine>), ex. /oauth2/start d'oauth2-proxy.
	ForwardAuthSignInURL string             `json:"forward_auth_signin_url,omitempty"`
	HeadersToForward     []string           `json:"headers_to_forward,omitempty"`
	BasicUsers           []BasicUser        `json:"basic_users,omitempty"`
	Realm                string             `json:"realm,omitempty"`
	OIDC                 *OIDCConfig        `json:"oidc,omitempty"`
	GitHub               *GitHubOAuthConfig `json:"github,omitempty"`
	LDAP                 *LDAPConfig        `json:"ldap,omitempty"`
	SAML                 *SAMLConfig        `json:"saml,omitempty"`
}

// GitHubOAuthConfig configure l'authentification via GitHub OAuth2.
type GitHubOAuthConfig struct {
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	AllowedOrgs   []string `json:"allowed_orgs,omitempty"`  // restreindre à ces orgs GitHub
	AllowedTeams  []string `json:"allowed_teams,omitempty"` // format "org/team"
	SessionSecret string   `json:"session_secret"`
	SessionMaxAge int      `json:"session_max_age,omitempty"` // secondes, défaut 86400
}

// LDAPConfig configure l'authentification LDAP / Active Directory.
type LDAPConfig struct {
	URL           string   `json:"url"`     // ex: ldap://dc.corp.local:389 ou ldaps://...
	BindDN        string   `json:"bind_dn"` // DN de lecture (service account)
	BindPassword  string   `json:"bind_password"`
	BaseDN        string   `json:"base_dn"`                  // ex: DC=corp,DC=local
	UserFilter    string   `json:"user_filter"`              // ex: (sAMAccountName=%s) ou (uid=%s)
	GroupFilter   string   `json:"group_filter,omitempty"`   // filtre groupes (optionnel)
	AllowedGroups []string `json:"allowed_groups,omitempty"` // DNs ou CNs de groupes autorisés
	UsernameAttr  string   `json:"username_attr,omitempty"`  // défaut: sAMAccountName / uid
	EmailAttr     string   `json:"email_attr,omitempty"`     // défaut: mail
	TLSSkipVerify bool     `json:"tls_skip_verify,omitempty"`
	SessionSecret string   `json:"session_secret"`
	SessionMaxAge int      `json:"session_max_age,omitempty"`
}

// SAMLConfig configure l'authentification SAML 2.0 (Service Provider).
type SAMLConfig struct {
	// SP (nous)
	EntityID     string `json:"entity_id"`               // ex: https://app.example.com/saml/metadata
	ACSPath      string `json:"acs_path"`                // ex: /saml/acs (assertion consumer service)
	MetadataPath string `json:"metadata_path,omitempty"` // ex: /saml/metadata
	CertPEM      string `json:"cert_pem"`                // certificat X.509 du SP (PEM)
	KeyPEM       string `json:"key_pem"`                 // clé privée du SP (PEM) — jamais en DB
	// IdP (partenaire)
	IDPMetadataURL string `json:"idp_metadata_url,omitempty"` // URL XML métadonnées IdP
	IDPMetadataXML string `json:"idp_metadata_xml,omitempty"` // ou XML inline
	// Mapping attributs
	UsernameAttr  string   `json:"username_attr,omitempty"` // défaut: uid / NameID
	EmailAttr     string   `json:"email_attr,omitempty"`
	GroupsAttr    string   `json:"groups_attr,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	SessionSecret string   `json:"session_secret"`
	SessionMaxAge int      `json:"session_max_age,omitempty"`
}

// OIDCConfig configure l'authentification via OIDC (Pocket ID, Keycloak, etc.)
// avec Authorization Code Flow + PKCE.
type OIDCConfig struct {
	IssuerURL     string   `json:"issuer_url"` // ex: https://id.example.com
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`              // ex: https://app.example.com/_gpx/oidc/callback
	Scopes        []string `json:"scopes,omitempty"`          // défaut: [openid, email, profile]
	UsernameClaim string   `json:"username_claim,omitempty"`  // défaut: "preferred_username"
	SessionSecret string   `json:"session_secret"`            // clé HMAC pour les cookies de session
	SessionMaxAge int      `json:"session_max_age,omitempty"` // secondes, défaut 86400
}

// BasicUser est un couple utilisateur / mot de passe pour le mode Basic Auth.
// Password : bcrypt ($2a$/$2b$/$2y$) recommandé ; plaintext encore accepté (legacy).
type BasicUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// CanaryConfig envoie un pourcentage du trafic vers un backend canary.
// Si Header/CookieName est renseigné, le basculement est déterministe (header ou cookie présent).
type CanaryConfig struct {
	Backend     string `json:"backend"`                // URL du backend canary
	Weight      int    `json:"weight"`                 // % du trafic [0-100] (mode aléatoire)
	Header      string `json:"header,omitempty"`       // header de déclenchement (ex: X-Canary)
	HeaderValue string `json:"header_value,omitempty"` // valeur attendue (vide = présence suffit)
	CookieName  string `json:"cookie_name,omitempty"`  // cookie de déclenchement
	ContainerID string `json:"container_id,omitempty"` // discovery Docker — cycle de vie
}

// ShadowConfig duplique chaque requête vers un backend miroir (sans impacter la réponse).
type ShadowConfig struct {
	Backend     string `json:"backend"`                // URL du backend miroir
	ContainerID string `json:"container_id,omitempty"` // discovery Docker — cycle de vie

	// Compare compare la réponse du miroir à celle du primaire (statut toujours, en-têtes et corps
	// en option) : métriques gpx_routing_shadow_diff_total et échantillon journalisé. Le corps est
	// comparé par taille et SHA-256 de ses 8 premiers Mo, sans être conservé.
	Compare        bool     `json:"compare,omitempty"`
	CompareHeaders []string `json:"compare_headers,omitempty"`
	CompareBody    bool     `json:"compare_body,omitempty"`
}

// Condition représente une règle de routage conditionnel sur les attributs de la requête.
// Pour le routage par chemin, utiliser Location (plus complet).
type Condition struct {
	Type    string `json:"type"`            // header | cookie | query | method
	Name    string `json:"name,omitempty"`  // nom du header/cookie/query
	Value   string `json:"value"`           // valeur attendue
	Regex   bool   `json:"regex,omitempty"` // interprète Value comme regexp
	Backend string `json:"backend"`         // URL de backend cible si condition vraie
}

// Location est une configuration par chemin (équivalent nginx `location`).
// Les champs non nuls remplacent la config de la route parente pour les
// requêtes dont le chemin correspond.
type Location struct {
	Path     string `json:"path"`                // chemin cible (ex: /api, /admin)
	PathType string `json:"path_type,omitempty"` // prefix (défaut) | exact | regex
	// CaseInsensitive force la correspondance sans casse (prefix/exact). nil = défaut sûr :
	// vrai si la location porte auth, ip_filter ou rate_limit, faux sinon.
	CaseInsensitive *bool `json:"case_insensitive,omitempty"`
	// StripPrefix retire Path du chemin avant de proxifier (nginx proxy_pass avec slash final).
	StripPrefix bool `json:"strip_prefix,omitempty"`
	// PathRewrite est un template de réécriture pour les locations regex (ex: /new/$1).
	PathRewrite string `json:"path_rewrite,omitempty"`

	// Backend override — vide = hérite des backends de la route
	Backends []Backend `json:"backends,omitempty"`

	// Overrides de config (nil = hérite de la route)
	RateLimit       *RateLimitConfig    `json:"rate_limit,omitempty"`
	IPFilter        *IPFilterConfig     `json:"ip_filter,omitempty"`
	Headers         *HeadersConfig      `json:"headers,omitempty"`
	CORS            *CORSConfig         `json:"cors,omitempty"`
	Auth            *SSOConfig          `json:"auth,omitempty"`
	MaxBodySize     int64               `json:"max_body_size,omitempty"`
	ConnectTimeout  time.Duration       `json:"connect_timeout,omitempty"`
	ResponseTimeout time.Duration       `json:"response_timeout,omitempty"`
	SendTimeout     time.Duration       `json:"send_timeout,omitempty"`
	Logging         *RouteLoggingConfig `json:"logging,omitempty"`
	ErrorPages      *ErrorPagesConfig   `json:"error_pages,omitempty"`
}

// SplitConfig répartit les requêtes entre Variants au prorata de leur Weight.
// Avec StickyCookie, un visiteur garde la variante qui lui a été attribuée (test A/B stable).
// Override nomme un header ou un cookie dont la valeur (nom de variante) force le choix.
type SplitConfig struct {
	Variants     []SplitVariant `json:"variants"`
	StickyCookie string         `json:"sticky_cookie,omitempty"`
	Override     string         `json:"override,omitempty"`
}

// SplitVariant est une destination nommée du Split.
type SplitVariant struct {
	Name    string `json:"name"`
	Backend string `json:"backend"`
	Weight  int    `json:"weight"`
}

// MaintenanceConfig met une route en maintenance : 503 + Retry-After, page HTML optionnelle.
// BypassCIDRs et BypassHeader laissent passer les équipes qui testent la route.
type MaintenanceConfig struct {
	Enabled       bool     `json:"enabled"`
	Message       string   `json:"message,omitempty"`
	HTML          string   `json:"html,omitempty"`
	RetryAfterSec int      `json:"retry_after_sec,omitempty"`
	BypassCIDRs   []string `json:"bypass_cidrs,omitempty"`
	BypassHeader  string   `json:"bypass_header,omitempty"` // "Nom: valeur" attendu
}

// SignedURLConfig décrit la vérification d'URLs signées :
// sig = base64url(HMAC-SHA256(secret, chemin + "\n" + expires)), expires en secondes Unix.
type SignedURLConfig struct {
	Enabled      bool     `json:"enabled"`
	Secret       string   `json:"secret"`
	ParamSig     string   `json:"param_sig,omitempty"`     // défaut "sig"
	ParamExpires string   `json:"param_expires,omitempty"` // défaut "expires"
	Paths        []string `json:"paths,omitempty"`         // préfixes protégés (vide = toute la route)
}

// GraphQLConfig borne les requêtes GraphQL (POST JSON ou GET ?query=).
type GraphQLConfig struct {
	Enabled            bool `json:"enabled"`
	MaxDepth           int  `json:"max_depth,omitempty"`   // profondeur max des sélections (0 = illimitée)
	MaxAliases         int  `json:"max_aliases,omitempty"` // nombre max d'alias (0 = illimité)
	BlockIntrospection bool `json:"block_introspection,omitempty"`
}

// BandwidthConfig plafonne le débit d'une réponse.
type BandwidthConfig struct {
	BytesPerSec int64 `json:"bytes_per_sec"`
}

// Positions d'insertion de HTMLInjectConfig.
const (
	HTMLInjectHeadEnd = "head_end" // avant le premier </head>
	HTMLInjectBodyEnd = "body_end" // avant le dernier </body> (défaut)
)

// HTMLInjectConfig insère Content dans les réponses text/html. Avec CSPNonce, {{nonce}} dans Content est remplacé
// par un nonce propre à la réponse, ajouté à la directive script-src du Content-Security-Policy du backend.
type HTMLInjectConfig struct {
	Position string `json:"position,omitempty"`
	Content  string `json:"content"`
	CSPNonce bool   `json:"csp_nonce,omitempty"`
}

// RedactConfig masque des champs JSON. Fields : noms de clés (à toute profondeur) ou chemins "a.b.c".
type RedactConfig struct {
	Fields []string `json:"fields"`
	Mask   string   `json:"mask,omitempty"` // défaut "***"
}

// HedgeConfig : si le backend n'a pas commencé à répondre après DelayMs, la même requête
// (GET/HEAD sans corps) part vers le backend suivant. MaxExtra : tentatives supplémentaires (défaut 1).
type HedgeConfig struct {
	DelayMs  int `json:"delay_ms"`
	MaxExtra int `json:"max_extra,omitempty"`
}

// StaticConfig fait servir un dossier de la passerelle par la route. SPAFallback renvoie l'index
// pour les chemins de page introuvables (routage côté navigateur). CacheMaxAge (s) s'applique aux
// fichiers autres que l'index, toujours revalidé.
type StaticConfig struct {
	Enabled     bool   `json:"enabled"`
	Root        string `json:"root"`
	Index       string `json:"index,omitempty"` // défaut "index.html"
	SPAFallback bool   `json:"spa_fallback,omitempty"`
	CacheMaxAge int    `json:"cache_max_age,omitempty"`
}

// RequestSchemaConfig valide le corps JSON des requêtes. Mode : "block" (défaut, 422) ou "detect"
// (la requête passe, seule la métrique compte). MaxBody : taille max lue en octets (défaut 1 Mo).
type RequestSchemaConfig struct {
	Enabled bool                `json:"enabled"`
	Mode    string              `json:"mode,omitempty"`
	MaxBody int64               `json:"max_body,omitempty"`
	Rules   []RequestSchemaRule `json:"rules"`
}

// RequestSchemaRule : la première règle dont la méthode (défaut POST, PUT, PATCH) et le préfixe de
// chemin correspondent s'applique. Schema est un JSON Schema autonome (aucun $ref externe).
type RequestSchemaRule struct {
	Methods    []string        `json:"methods,omitempty"`
	PathPrefix string          `json:"path_prefix,omitempty"`
	Schema     json.RawMessage `json:"schema"`
}

// OpenAPIConfig valide les requêtes contre une spécification OpenAPI 3.0 ou 3.1 (chemins, méthodes,
// paramètres de chemin, de requête, d'en-tête et de cookie, corps JSON). Spec est le document en YAML
// ou JSON (une chaîne, ou directement l'objet JSON) ; seules les références locales ("#/…") sont
// admises. Mode : "block" (défaut) refuse la requête non conforme, "detect" la laisse passer et ne
// fait que compter. UnknownPaths : "allow" (défaut, la spécification peut être partielle) ou "block"
// (404 pour un chemin absent de la spécification, 405 pour une méthode absente). StripPrefix est
// retiré du chemin avant la recherche (préfixe de l'URL de serveur). Skip exclut des familles de
// contrôles : "path", "query", "header", "cookie", "body".
type OpenAPIConfig struct {
	Enabled      bool            `json:"enabled"`
	Spec         json.RawMessage `json:"spec"`
	Mode         string          `json:"mode,omitempty"`
	UnknownPaths string          `json:"unknown_paths,omitempty"`
	StripPrefix  string          `json:"strip_prefix,omitempty"`
	MaxBody      int64           `json:"max_body,omitempty"`
	Skip         []string        `json:"skip,omitempty"`
	// BlockReasons : en mode detect, les types de violation que le contrôle refuse quand même (unknown_path, unknown_method,
	// invalid_param, invalid_body, unsupported_media, too_large). Les autres passent et sont comptées. Sans effet en mode block,
	// qui les refuse toutes. Posé règle par règle par l'apprentissage de surface (ADR 0016, étape 4).
	BlockReasons []string `json:"block_reasons,omitempty"`
}

// GRPCTranscodeConfig expose un backend gRPC (unaire) en REST/JSON. Les descripteurs viennent soit de
// fichiers .proto (Proto : nom → contenu, imports google/api/* et google/protobuf/* fournis), soit
// d'un FileDescriptorSet binaire encodé en base64 (DescriptorSet, produit par
// `protoc --include_imports --descriptor_set_out`) ; l'un des deux, pas les deux. Chaque méthode est
// publiée selon ses annotations google.api.http ; avec AutoMapping, une méthode sans annotation est
// aussi publiée en `POST /<paquet.Service>/<Méthode>` (corps = message), comme le transcodeur d'Envoy.
// Services restreint aux services nommés (nom complet). Les méthodes à flux sont ignorées.
// EmitDefaults écrit les champs à valeur par défaut, ProtoFieldNames garde les noms de champs du
// .proto (au lieu de lowerCamelCase). Le backend doit parler gRPC en HTTP/2 (h2c accepté en http://).
type GRPCTranscodeConfig struct {
	Enabled         bool              `json:"enabled"`
	Proto           map[string]string `json:"proto,omitempty"`
	DescriptorSet   string            `json:"descriptor_set,omitempty"`
	Services        []string          `json:"services,omitempty"`
	AutoMapping     bool              `json:"auto_mapping,omitempty"`
	EmitDefaults    bool              `json:"emit_defaults,omitempty"`
	ProtoFieldNames bool              `json:"proto_field_names,omitempty"`
	MaxRequestBody  int64             `json:"max_request_body,omitempty"`
	MaxResponseBody int64             `json:"max_response_body,omitempty"`
}
