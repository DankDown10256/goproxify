// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logapi décrit le contrat HTTP entre l'Admin et la base de logs d'une passerelle (ADR 0012) : paramètres
// de recherche, entrées, facettes, histogramme. La passerelle répond, l'Admin interroge chaque passerelle et fusionne.
package logapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"

	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
	"github.com/vincamok/goproxify/internal/ipsketch"
)

// Chemins de l'API interne de la passerelle.
const (
	PathSearch    = "/internal/v1/logs/search"
	PathHistogram = "/internal/v1/logs/histogram"
	PathFacets    = "/internal/v1/logs/facets"
	PathReveal    = "/internal/v1/logs/reveal"
	// PathTop : regroupement par champ (POST, filtres en paramètres, demande en JSON).
	PathTop = "/internal/v1/logs/top"
	// PathErase : effacement d'une IP des logs et de l'historique des bans de la passerelle (POST), avec les comptes.
	PathErase = "/internal/v1/logs/erase"
	// PathUniqueIPs : résumé des IP distinctes de la période (GET).
	PathUniqueIPs = "/internal/v1/logs/unique-ips"
)

// Plafonds d'une recherche : une page normale tient dans 500 lignes ; un export en réclame jusqu'à 100 000.
const (
	DefaultLimit = 50
	MaxLimit     = 500
	MaxBulkLimit = 100000
)

// Params sont les filtres d'une recherche, les mêmes que ceux de GET /api/v1/logs de l'Admin.
type Params struct {
	Level, Component, Domain, IP, Method, Status, Path string
	TLSJA3, TLSJA4, Search, RequestID                  string
	// Domains : plusieurs domaines séparés par des virgules (sélection multiple de Prism) ; PathPrefix : chemins qui
	// commencent par cette valeur (Path cherche à l'intérieur).
	Domains, PathPrefix string
	// IPFrom, IPTo : bornes de la colonne ip comme texte ([IPFrom, IPTo[), IPRanges : plusieurs intervalles « de|à » séparés par des virgules.
	IPFrom, IPTo, IPRanges string
	// Attributable : uniquement les lignes dont l'IP n'est pas tronquée.
	Attributable bool
	// DateFrom et DateTo : bornes RFC3339.
	DateFrom, DateTo string
	// Kind : "access", "system" ou vide (les deux).
	Kind            string
	ExcludeInternal bool
	// Cursor est le jeton Next de la page précédente ; vide pour la première page.
	Cursor string
	Limit  int
	// Bulk autorise une page jusqu'à MaxBulkLimit (export) : un seul à la fois, avec un délai plus long.
	Bulk bool
	// TZOffsetMin décale les tranches de l'histogramme (minutes à l'est de UTC) ; Bucket : minute, hour ou day.
	TZOffsetMin int
	Bucket      string
	// Fields : facettes demandées (virgules), pour /facets.
	Fields string
}

// Values encode les paramètres dans une requête.
func (p Params) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("level", p.Level)
	set("component", p.Component)
	set("domain", p.Domain)
	set("ip", p.IP)
	set("method", p.Method)
	set("status", p.Status)
	set("path", p.Path)
	set("tls_ja3", p.TLSJA3)
	set("tls_ja4", p.TLSJA4)
	set("search", p.Search)
	set("request_id", p.RequestID)
	set("domains", p.Domains)
	set("path_prefix", p.PathPrefix)
	set("ip_from", p.IPFrom)
	set("ip_to", p.IPTo)
	set("ip_ranges", p.IPRanges)
	if p.Attributable {
		v.Set("attributable", "1")
	}
	set("date_from", p.DateFrom)
	set("date_to", p.DateTo)
	set("kind", p.Kind)
	set("cursor", p.Cursor)
	set("bucket", p.Bucket)
	set("fields", p.Fields)
	if p.ExcludeInternal {
		v.Set("exclude_internal", "1")
	}
	if p.Bulk {
		v.Set("bulk", "1")
	}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.TZOffsetMin != 0 {
		v.Set("tz_offset_min", strconv.Itoa(p.TZOffsetMin))
	}
	return v
}

// ParamsFromValues décode les paramètres d'une requête.
func ParamsFromValues(v url.Values) Params {
	limit, _ := strconv.Atoi(v.Get("limit"))
	tz, _ := strconv.Atoi(v.Get("tz_offset_min"))
	return Params{
		Level: v.Get("level"), Component: v.Get("component"), Domain: v.Get("domain"), IP: v.Get("ip"),
		Method: v.Get("method"), Status: v.Get("status"), Path: v.Get("path"), TLSJA3: v.Get("tls_ja3"),
		TLSJA4: v.Get("tls_ja4"), Search: v.Get("search"), RequestID: v.Get("request_id"), DateFrom: v.Get("date_from"), DateTo: v.Get("date_to"),
		Kind: v.Get("kind"), ExcludeInternal: v.Get("exclude_internal") == "1" || v.Get("exclude_internal") == "true",
		Cursor: v.Get("cursor"), Limit: limit, Bulk: v.Get("bulk") == "1", TZOffsetMin: tz, Bucket: v.Get("bucket"),
		Fields: v.Get("fields"), Domains: v.Get("domains"), PathPrefix: v.Get("path_prefix"), IPFrom: v.Get("ip_from"), IPTo: v.Get("ip_to"), IPRanges: v.Get("ip_ranges"), Attributable: v.Get("attributable") == "1",
	}
}

// Entry est une ligne de log. Les champs suivent logs.Entry de l'Admin ; ID est l'identifiant global dans la base de
// la passerelle (période << 40 | rowid), unique pour un type (Kind) de cette passerelle.
type Entry struct {
	ID            int64    `json:"id"`
	Kind          string   `json:"kind"`
	Ts            string   `json:"ts"` // RFC3339Nano, UTC
	Level         string   `json:"level"`
	Component     string   `json:"component"`
	Domain        string   `json:"domain"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Status        int      `json:"status"`
	IP            string   `json:"ip"`
	LatencyMs     int64    `json:"latency_ms"`
	Bytes         int64    `json:"bytes"`
	Message       string   `json:"message"`
	Referrer      string   `json:"referrer,omitempty"`
	RequestID     string   `json:"request_id,omitempty"`
	WAFMatches    []string `json:"waf_matches,omitempty"`
	ThreatSignal  string   `json:"threat_signal,omitempty"`
	TLSJA3        string   `json:"tls_ja3,omitempty"`
	TLSJA4        string   `json:"tls_ja4,omitempty"`
	IPTruncated   bool     `json:"ip_truncated,omitempty"`
	Pseudonymized bool     `json:"pseudonymized,omitempty"`
}

// SearchResponse est une page de résultats, du plus récent au plus ancien. Next est le jeton de la page suivante.
// Partial : le délai de la recherche est écoulé avant qu'elle ait parcouru toute la période (affiner le filtre).
type SearchResponse struct {
	Entries []Entry `json:"entries"`
	Next    string  `json:"next"`
	HasMore bool    `json:"has_more"`
	Partial bool    `json:"partial"`
	// Via est l'identifiant de la passerelle qui a répondu, rempli par le client de l'Admin (jamais sur le fil) : les
	// identifiants de lignes sont ceux de sa base.
	Via string `json:"-"`
}

// FacetCount : une valeur d'un champ et son nombre d'entrées.
type FacetCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// FacetsResponse : les valeurs les plus fréquentes de chaque champ demandé, et le nombre total d'entrées filtrées.
type FacetsResponse struct {
	Total   int64                   `json:"total"`
	Facets  map[string][]FacetCount `json:"facets"`
	Partial bool                    `json:"partial"`
}

// HistPoint compte les entrées d'une tranche de temps, par niveau.
type HistPoint struct {
	Bucket string `json:"bucket"`
	Total  int64  `json:"total"`
	Warn   int64  `json:"warn"`
	Error  int64  `json:"error"`
}

// HistogramResponse : les tranches, dans l'ordre chronologique.
type HistogramResponse struct {
	Points  []HistPoint `json:"points"`
	Partial bool        `json:"partial"`
}

// TopRequest demande un regroupement (ADR 0012, P1). Mode : « best » (les K meilleures valeurs), « above » (toutes
// celles vues au moins Min fois) ou « exact » (les comptes des Values). WithIPs, en mode « exact », joint à chaque
// valeur le résumé de ses IP attribuables.
type TopRequest struct {
	Dim     string   `json:"dim"`
	Mode    string   `json:"mode"`
	K       int      `json:"k,omitempty"`
	Min     int64    `json:"min,omitempty"`
	Values  []string `json:"values,omitempty"`
	WithIPs bool     `json:"with_ips,omitempty"`
}

// TopItem additionne les accès d'une valeur ; tous ses compteurs s'additionnent d'une passerelle à l'autre.
type TopItem struct {
	Value      string            `json:"value"`
	Requests   int64             `json:"requests"`
	Errors     int64             `json:"errors"`
	Bytes      int64             `json:"bytes"`
	LatencySum int64             `json:"latency_sum"`
	Flagged    int64             `json:"flagged,omitempty"`
	Blocked    int64             `json:"blocked,omitempty"`
	Ok         int64             `json:"ok,omitempty"`
	Bots       int64             `json:"bots,omitempty"`
	FirstSeen  string            `json:"first_seen,omitempty"`
	LastSeen   string            `json:"last_seen,omitempty"`
	Truncated  bool              `json:"ip_truncated,omitempty"`
	JA3        string            `json:"ja3,omitempty"`
	IPs        *ipsketch.Summary `json:"ips,omitempty"`
}

// TopResponse : Complete dit qu'en mode « best » la passerelle a rendu toutes ses valeurs (elle en avait moins que K).
type TopResponse struct {
	Items    []TopItem `json:"items"`
	Complete bool      `json:"complete"`
	Partial  bool      `json:"partial"`
}

// UniqueIPsResponse : l'ensemble des IP vues, exact s'il est petit, estimé sinon (voir ipsketch).
type UniqueIPsResponse struct {
	IPs     ipsketch.Summary `json:"ips"`
	Partial bool             `json:"partial"`
}

// EraseRequest demande l'effacement d'une IP (droit à l'effacement RGPD).
type EraseRequest struct {
	IP string `json:"ip"`
}

// EraseResponse dit ce que la passerelle a supprimé : lignes de logs (accès et système, pseudonymisées comprises) et
// lignes de l'historique des bans. Elle est la preuve de l'effacement pour cette passerelle.
type EraseResponse struct {
	LogLines int64 `json:"log_lines"`
	BanRows  int64 `json:"ban_rows"`
}

// RevealRequest demande l'IP réelle d'une ligne pseudonymisée.
type RevealRequest struct {
	Kind string `json:"kind"`
	ID   int64  `json:"id"`
}

// RevealResponse porte l'IP réelle.
type RevealResponse struct {
	IP string `json:"ip"`
}

// TsLayout est le format des horodatages d'une Entry : largeur fixe, donc comparables en texte et utilisables tels
// quels dans un curseur. C'est aussi du RFC3339 valide.
const TsLayout = "2006-01-02T15:04:05.000000Z"

// Pos est la position d'une ligne dans un type de log de la passerelle : celle de la dernière ligne rendue.
type Pos struct {
	Ts string `json:"ts"`
	ID int64  `json:"id"`
}

// MaxCursorBytes borne un jeton de page reçu.
const MaxCursorBytes = 1024

// EncodeCursor fabrique le jeton d'une page à partir des positions par type ("access", "system").
func EncodeCursor(pos map[string]Pos) string {
	m := map[string]Pos{}
	for k, p := range pos {
		if p.Ts != "" {
			m[k] = p
		}
	}
	if len(m) == 0 {
		return ""
	}
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor lit un jeton de page ; un jeton vide est la première page.
func DecodeCursor(c string) (map[string]Pos, error) {
	if c == "" {
		return nil, nil
	}
	if len(c) > MaxCursorBytes {
		return nil, errors.New("jeton de page trop long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, err
	}
	var m map[string]Pos
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k := range m {
		if k != "access" && k != "system" {
			return nil, errors.New("jeton de page inconnu")
		}
	}
	return m, nil
}

// PathEphorReferences : ce que la passerelle a appris pour la note commune d'Ephor (GET).
const PathEphorReferences = "/internal/v1/ephor/references"

// EphorReferencesResponse décrit l'état appris de la passerelle : les références de débit par route et par heure (valeur,
// date, volume observé), le nombre de profils en cours, la base ASN et la table d'empreintes TLS.
type EphorReferencesResponse struct {
	References []behavior.RefInfo `json:"references"`
	Profiles   int                `json:"profiles"`
	ASN        ASNStatus          `json:"asn"`
	TLSTable   string             `json:"tls_table"`
}

// ASNStatus : la base IP → ASN dont dispose la passerelle (version vide = aucune).
type ASNStatus struct {
	Version  string `json:"version,omitempty"`
	V4Ranges int    `json:"v4_ranges,omitempty"`
	V6Ranges int    `json:"v6_ranges,omitempty"`
}

// PathEphorSim : simulation d'une configuration Ephor sur le trafic récent de la passerelle (POST).
const PathEphorSim = "/internal/v1/ephor/simulate"

// EphorSimRequest : les deux configurations à comparer (JSON de threat.Config), la fenêtre et un domaine facultatif.
// La passerelle rejoue ses propres accès, comme elle les traite en production.
type EphorSimRequest struct {
	Current   json.RawMessage `json:"current"`
	Candidate json.RawMessage `json:"candidate"`
	Hours     int             `json:"hours"`
	Domain    string          `json:"domain,omitempty"`
}

// EphorSimResponse : le rapport de chaque configuration. Skipped compte les accès dont l'IP est tronquée ou illisible,
// Truncated dit que la passerelle a plus d'accès que SimMaxEvents sur la fenêtre (les plus récents sont rejoués).
type EphorSimResponse struct {
	Current   threat.SimReport `json:"current"`
	Candidate threat.SimReport `json:"candidate"`
	Events    int              `json:"events"`
	Skipped   int              `json:"skipped"`
	Truncated bool             `json:"truncated"`
	Partial   bool             `json:"partial"`
}

// SimMaxEvents borne les accès rejoués par une passerelle.
const SimMaxEvents = 200_000

// Surface d'un proxy (ADR 0016). La passerelle tient les profils ; l'Admin les lit et les affiche.
const (
	// PathSurface : un résumé par proxy en apprentissage (GET).
	PathSurface = "/internal/v1/surface"
	// PathSurfaceReport : rapport complet d'un proxy, ?route=<identifiant ou hôte> (GET).
	PathSurfaceReport = "/internal/v1/surface/report"
	// PathSurfaceReset : efface le profil d'un proxy, l'apprentissage repart de zéro (POST).
	PathSurfaceReset = "/internal/v1/surface/reset"
	// PathSurfaceProposals : réglages proposés pour un proxy à partir de son profil, ?route=<identifiant ou hôte> (GET).
	PathSurfaceProposals = "/internal/v1/surface/proposals"
	// PathSurfaceOpenAPI : politique OpenAPI générée à partir du profil, ?route=<identifiant ou hôte>[&include_low_support=1] (GET).
	PathSurfaceOpenAPI = "/internal/v1/surface/openapi"
	// PathSurfaceForget : efface des violations du profil d'un proxy, que la politique couvre désormais (POST).
	PathSurfaceForget = "/internal/v1/surface/forget"
	// PathInventory : applications reconnues derrière les proxies de la passerelle, ?route=<identifiant ou hôte> (GET).
	PathInventory = "/internal/v1/inventory"
	// PathInventoryExport : empreintes des réponses des backends, que les pairs d'un groupe HA se tirent entre eux (GET).
	PathInventoryExport = "/internal/v1/inventory/export"
	// PathSurfaceExport : profils locaux, que les pairs d'un groupe HA se tirent entre eux (GET).
	PathSurfaceExport = "/internal/v1/surface/export"
)

// SurfaceListResponse : les proxies dont la passerelle apprend la surface.
type SurfaceListResponse struct {
	Proxies []surface.Summary `json:"proxies"`
}

// SurfaceResetRequest désigne le proxy à remettre à zéro.
type SurfaceResetRequest struct {
	Route string `json:"route"`
}

// SurfaceResetResponse : false si la passerelle n'avait aucun profil pour ce proxy.
type SurfaceResetResponse struct {
	Reset bool `json:"reset"`
}

// SurfaceForgetRequest désigne les violations (« raison MÉTHODE chemin ») à effacer du profil d'un proxy.
type SurfaceForgetRequest struct {
	Route string   `json:"route"`
	Keys  []string `json:"keys"`
}

// SurfaceForgetResponse : le nombre de violations effacées du profil de la passerelle.
type SurfaceForgetResponse struct {
	Forgotten int `json:"forgotten"`
}

// InventoryEntry : ce que la passerelle sait de l'application servie par un backend d'un proxy (ADR 0017). Product, Version et CPE
// sont vides quand l'image n'est pas dans la table des produits connus : l'entrée est alors listée « non couverte ».
type InventoryEntry struct {
	Route     string `json:"route"`
	Host      string `json:"host"`
	Backend   string `json:"backend"`
	Container string `json:"container,omitempty"`
	// Coverage : si la recherche de CVE peut traiter l'entrée (covered, no_version, no_cpe, unknown), voir appinv.
	Coverage string `json:"coverage,omitempty"`
	appinv.Finding
}

// InventoryResponse : l'inventaire d'une passerelle.
type InventoryResponse struct {
	Entries []InventoryEntry `json:"entries"`
}
