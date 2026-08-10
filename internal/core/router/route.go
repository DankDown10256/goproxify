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

	// TLS
	TLSEnabled     bool   `json:"tls_enabled"`
	TLSPassthrough bool   `json:"tls_passthrough"` // SNI passthrough sans déchiffrement
	CertName       string `json:"cert_name"`       // clé dans CertStore
	TLSSkipVerify  bool   `json:"tls_skip_verify,omitempty"`  // ignorer le certificat backend auto-signé
	// nil (absent) = conserver le Host original (défaut, comme nginx) ; false = envoyer le host du backend
	PreserveHost   *bool  `json:"preserve_host,omitempty"`

	// TCP/UDP
	ListenPort int `json:"listen_port,omitempty"` // port d'écoute local (L4)

	// Sécurité
	RateLimit *RateLimitConfig `json:"rate_limit,omitempty"`
	IPFilter  *IPFilterConfig  `json:"ip_filter,omitempty"`
	GeoIP     *GeoIPConfig     `json:"geo_ip,omitempty"`
	Headers   *HeadersConfig   `json:"headers,omitempty"`
	CORS      *CORSConfig      `json:"cors,omitempty"`
	WAF  *WAFConfig  `json:"waf,omitempty"`
	Bot  *BotConfig  `json:"bot,omitempty"`
	JWT  *JWTConfig  `json:"jwt,omitempty"`
	MTLS *MTLSConfig `json:"mtls,omitempty"`
	SSO  *SSOConfig  `json:"sso,omitempty"`

	// Cache proxy sur disque (vide = désactivé)
	CachePath string `json:"cache_path,omitempty"`

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

type IPFilterConfig struct {
	Mode  string   `json:"mode"`   // allow | deny
	CIDRs []string `json:"cidrs"`
}

type HeadersConfig struct {
	HSTS            bool              `json:"hsts"`
	HSTSMaxAge      int               `json:"hsts_max_age"`
	XFrameOptions   string            `json:"x_frame_options"`
	HideServer      bool              `json:"hide_server"`
	Custom          map[string]string `json:"custom,omitempty"`
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
	Enabled    bool  `json:"enabled"`
	Mode       string `json:"mode"`        // detect | block
	ExcludeIDs []int  `json:"exclude_ids"`
	MaxBodyMB  int    `json:"max_body_mb"`
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
