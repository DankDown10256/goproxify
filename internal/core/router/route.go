// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"time"
)

// Route décrit un proxy HTTP ou TCP/UDP vers un ou plusieurs backends.
type Route struct {
	ID       string   `json:"id"`
	Host     string   `json:"host"`              // ex: "app.example.fr" — vide pour TCP/UDP
	Aliases  []string `json:"aliases,omitempty"` // domaines secondaires pointant vers la même route
	Type     RouteType `json:"type"`             // http | tcp | udp
	Backends []Backend `json:"backends"`

	// AgentName est le nœud Agent qui a découvert / injecté cette route (docker:/k8s:).
	AgentName string `json:"agent_name,omitempty"`

	// DelegateAPIEndpoint est l'endpoint interne (http://host:8000) du Core délégué.
	// Renseigné par Admin lors du push des délégations. Utilisé pour le relay Core→Core.
	DelegateAPIEndpoint string `json:"delegate_api_endpoint,omitempty"`

	// TLS
	TLSEnabled     bool   `json:"tls_enabled"`
	TLSPassthrough bool   `json:"tls_passthrough"` // SNI passthrough sans déchiffrement
	CertName       string `json:"cert_name"`       // clé dans CertStore
	TLSSkipVerify  bool   `json:"tls_skip_verify,omitempty"`  // ignorer le certificat backend auto-signé
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

	// Sécurité
	RateLimit           *RateLimitConfig           `json:"rate_limit,omitempty"`
	LimitConn           *LimitConnConfig           `json:"limit_conn,omitempty"`
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

	// Cache proxy sur disque (vide = désactivé)
	CachePath string `json:"cache_path,omitempty"`
	// Cache avancé : TTL par code, bypass, no-store (équivalent nginx proxy_cache_valid / proxy_cache_bypass).
	Cache *CacheConfig `json:"cache,omitempty"`

	// Timeouts vers le backend (0 = valeurs par défaut Go)
	ConnectTimeout  time.Duration `json:"connect_timeout,omitempty"`  // TCP dial (nginx: proxy_connect_timeout)
	ResponseTimeout time.Duration `json:"response_timeout,omitempty"` // attente headers réponse (nginx: proxy_read_timeout)
	SendTimeout     time.Duration `json:"send_timeout,omitempty"`     // envoi requête backend (nginx: proxy_send_timeout)
	BufferSize      int           `json:"buffer_size,omitempty"`      // taille buffer réponse en octets (nginx: proxy_buffer_size)
	MaxBodySize     int64         `json:"max_body_size,omitempty"`    // taille max corps requête client en octets (nginx: client_max_body_size, 0 = illimité)

	// Résilience
	LB            LBAlgorithm `json:"lb"`             // round_robin | weighted | adaptive
	CircuitBreaker *CBConfig  `json:"circuit_breaker,omitempty"`
	Retry         *RetryConfig `json:"retry,omitempty"`
	StickyCookie  string       `json:"sticky_cookie,omitempty"`

	// Trafic avancé
	Canary     *CanaryConfig    `json:"canary,omitempty"`
	Shadow     *ShadowConfig    `json:"shadow,omitempty"`
	Conditions []Condition      `json:"conditions,omitempty"`
	Locations  []Location       `json:"locations,omitempty"`
	// StripPrefix is applied at proxy time (usually copied from the matched Location).
	StripPrefix string `json:"strip_prefix,omitempty"`
	// PathRewrite is a replacement template applied after a regex Location match.
	// Use $1, $2 … to reference capture groups from the matched Location regex.
	PathRewrite        string `json:"path_rewrite,omitempty"`
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

	// SentinelWhitelist : IPs/CIDRs exemptés du moteur de détection automatique pour cette route.
	// Ces entrées sont fusionnées dans la whitelist globale du moteur Sentinel.
	SentinelWhitelist []string `json:"sentinel_whitelist,omitempty"`

	// Observabilité par route
	Logging    *RouteLoggingConfig `json:"logging,omitempty"`

	// Pages d'erreur personnalisées
	ErrorPages *ErrorPagesConfig `json:"error_pages,omitempty"`

	// Références vers des ressources Core partagées
	SnippetIDs     []string `json:"snippet_ids,omitempty"`      // snippets à fusionner dans la config
	AuthProviderID string   `json:"auth_provider_id,omitempty"` // fournisseur SSO/OIDC du Core

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
	URL                string `json:"url"`                              // ex: "http://10.0.0.5:3000" ou "10.0.0.5:5432" (L4)
	Weight             int    `json:"weight"`                           // 0 = égal aux autres
	ContainerID        string `json:"container_id,omitempty"`           // discovery Docker — pour merge/retrait
	AgentName          string `json:"agent_name,omitempty"`
	OwnerCoreEndpoint  string `json:"owner_core_endpoint,omitempty"`    // si distant : gateway vers ce Core
	OwnerCoreName      string `json:"owner_core_name,omitempty"`
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
}

// LimitConnConfig limite le nombre de connexions simultanées par IP
// (équivalent nginx limit_conn).
type LimitConnConfig struct {
	MaxPerIP int `json:"max_per_ip"` // 0 = désactivé
}

type IPFilterConfig struct {
	Mode  string   `json:"mode"`   // allow | deny
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
	// Methods : méthodes mises en cache (défaut : ["GET", "HEAD"]).
	Methods []string `json:"methods,omitempty"`
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
	Name    string           `json:"name"`             // nom de la variable (sans $)
	Source  string           `json:"source"`           // header | cookie | query | method | remote_ip | path
	Key     string           `json:"key,omitempty"`    // nom du header/cookie/query param (si source=header/cookie/query)
	Default string           `json:"default,omitempty"` // valeur si aucun cas ne correspond
	Cases   []RequestVarCase `json:"cases,omitempty"`
}

// RequestVarCase mappe un pattern à une valeur de variable.
type RequestVarCase struct {
	Pattern string `json:"pattern"`           // valeur ou regex à matcher
	Value   string `json:"value"`             // valeur retournée si pattern correspond
	Regex   bool   `json:"regex,omitempty"`   // interpréter Pattern comme regex
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
	HSTS            bool              `json:"hsts"`
	HSTSMaxAge      int               `json:"hsts_max_age"`
	XFrameOptions   string            `json:"x_frame_options"`
	HideServer      bool              `json:"hide_server"`
	Custom          map[string]string `json:"custom,omitempty"`
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

type CBConfig struct {
	Threshold   int           `json:"threshold"`    // nb d'échecs consécutifs
	Timeout     time.Duration `json:"timeout"`      // durée open → half-open
}

type RetryConfig struct {
	Attempts    int           `json:"attempts"`
	InitialWait time.Duration `json:"initial_wait"`
	MaxWait     time.Duration `json:"max_wait"`
}

// WAFConfig configure le WAF par route.
type WAFConfig struct {
	Enabled          bool         `json:"enabled"`
	Mode             string       `json:"mode"`               // detect | block
	ExcludeIDs       []int        `json:"exclude_ids"`
	MaxBodyMB        int          `json:"max_body_mb"`
	AnomalyThreshold int          `json:"anomaly_threshold"`  // 0 = premier match, >0 = score cumulatif
	CustomRules      []CustomRule `json:"custom_rules,omitempty"`

	// Analyse comportementale — stateful, par IP, sur une fenêtre glissante.
	BehaviorEnabled   bool `json:"behavior_enabled"`
	BehaviorWindowSec int  `json:"behavior_window_s"`   // durée fenêtre (défaut 60s)
	BehaviorThreshold int  `json:"behavior_threshold"`  // score avant action (défaut 8)

	// TrustedProxies : CIDRs des proxies de confiance dont les headers X-Forwarded-For
	// sont acceptés pour déterminer l'IP réelle du client.
	// Vide = pas de confiance (on utilise RemoteAddr directement).
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}

// CustomRule est une règle WAF définie par l'utilisateur.
type CustomRule struct {
	ID       int      `json:"id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`          // critical | high | medium | low
	Pattern  string   `json:"pattern"`           // regex Go
	Targets  []string `json:"targets"`           // uri | args | body | headers | cookies
	Message  string   `json:"message"`
	Score    int      `json:"score,omitempty"`   // score anomalie (0 = déduit de la sévérité)
}

// BotConfig configure la protection bot.
type BotConfig struct {
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode,omitempty"` // block | monitor | log | challenge
	UABlacklist     []string `json:"ua_blacklist,omitempty"`
	JSChallenge     bool     `json:"js_challenge"`
	ChallengeSecret string   `json:"challenge_secret,omitempty"`
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
	Enabled          bool        `json:"enabled"`
	// Provider : authentik | authelia | basic | forward | pocket_id | oidc |
	//            keycloak | zitadel | google | microsoft | auth0 | okta | casdoor | dex |
	//            github | ldap | ldap_ad | saml
	Provider         string      `json:"provider"`
	ForwardAuthURL   string      `json:"forward_auth_url,omitempty"`
	HeadersToForward []string    `json:"headers_to_forward,omitempty"`
	BasicUsers       []BasicUser `json:"basic_users,omitempty"`
	Realm            string      `json:"realm,omitempty"`
	OIDC             *OIDCConfig  `json:"oidc,omitempty"`
	GitHub           *GitHubOAuthConfig `json:"github,omitempty"`
	LDAP             *LDAPConfig  `json:"ldap,omitempty"`
	SAML             *SAMLConfig  `json:"saml,omitempty"`
}

// GitHubOAuthConfig configure l'authentification via GitHub OAuth2.
type GitHubOAuthConfig struct {
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	AllowedOrgs   []string `json:"allowed_orgs,omitempty"`   // restreindre à ces orgs GitHub
	AllowedTeams  []string `json:"allowed_teams,omitempty"`  // format "org/team"
	SessionSecret string   `json:"session_secret"`
	SessionMaxAge int      `json:"session_max_age,omitempty"` // secondes, défaut 86400
}

// LDAPConfig configure l'authentification LDAP / Active Directory.
type LDAPConfig struct {
	URL          string `json:"url"`           // ex: ldap://dc.corp.local:389 ou ldaps://...
	BindDN       string `json:"bind_dn"`       // DN de lecture (service account)
	BindPassword string `json:"bind_password"`
	BaseDN       string `json:"base_dn"`       // ex: DC=corp,DC=local
	UserFilter   string `json:"user_filter"`   // ex: (sAMAccountName=%s) ou (uid=%s)
	GroupFilter  string `json:"group_filter,omitempty"` // filtre groupes (optionnel)
	AllowedGroups []string `json:"allowed_groups,omitempty"` // DNs ou CNs de groupes autorisés
	UsernameAttr string `json:"username_attr,omitempty"` // défaut: sAMAccountName / uid
	EmailAttr    string `json:"email_attr,omitempty"`    // défaut: mail
	TLSSkipVerify bool  `json:"tls_skip_verify,omitempty"`
	SessionSecret string `json:"session_secret"`
	SessionMaxAge int    `json:"session_max_age,omitempty"`
}

// SAMLConfig configure l'authentification SAML 2.0 (Service Provider).
type SAMLConfig struct {
	// SP (nous)
	EntityID    string `json:"entity_id"`    // ex: https://app.example.com/saml/metadata
	ACSPath     string `json:"acs_path"`     // ex: /saml/acs (assertion consumer service)
	MetadataPath string `json:"metadata_path,omitempty"` // ex: /saml/metadata
	CertPEM     string `json:"cert_pem"`     // certificat X.509 du SP (PEM)
	KeyPEM      string `json:"key_pem"`      // clé privée du SP (PEM) — jamais en DB
	// IdP (partenaire)
	IDPMetadataURL string `json:"idp_metadata_url,omitempty"` // URL XML métadonnées IdP
	IDPMetadataXML string `json:"idp_metadata_xml,omitempty"` // ou XML inline
	// Mapping attributs
	UsernameAttr  string `json:"username_attr,omitempty"`  // défaut: uid / NameID
	EmailAttr     string `json:"email_attr,omitempty"`
	GroupsAttr    string `json:"groups_attr,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	SessionSecret string `json:"session_secret"`
	SessionMaxAge int    `json:"session_max_age,omitempty"`
}

// OIDCConfig configure l'authentification via OIDC (Pocket ID, Keycloak, etc.)
// avec Authorization Code Flow + PKCE.
type OIDCConfig struct {
	IssuerURL     string   `json:"issuer_url"`               // ex: https://id.example.com
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`             // ex: https://app.example.com/_gpx/oidc/callback
	Scopes        []string `json:"scopes,omitempty"`         // défaut: [openid, email, profile]
	UsernameClaim string   `json:"username_claim,omitempty"` // défaut: "preferred_username"
	SessionSecret string   `json:"session_secret"`           // clé HMAC pour les cookies de session
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
	Backend     string `json:"backend"`               // URL du backend canary
	Weight      int    `json:"weight"`                // % du trafic [0-100] (mode aléatoire)
	Header      string `json:"header,omitempty"`      // header de déclenchement (ex: X-Canary)
	HeaderValue string `json:"header_value,omitempty"` // valeur attendue (vide = présence suffit)
	CookieName  string `json:"cookie_name,omitempty"` // cookie de déclenchement
	ContainerID string `json:"container_id,omitempty"` // discovery Docker — cycle de vie
}

// ShadowConfig duplique chaque requête vers un backend miroir (sans impacter la réponse).
type ShadowConfig struct {
	Backend     string `json:"backend"`                // URL du backend miroir
	ContainerID string `json:"container_id,omitempty"` // discovery Docker — cycle de vie
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
