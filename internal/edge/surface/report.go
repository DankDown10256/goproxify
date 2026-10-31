// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Critères de convergence (ADR 0016) : un profil n'est fiable qu'après un cycle complet (le week-end compris), un volume
// minimal, et plus aucun nouveau gabarit depuis 48 h.
const (
	MinAge        = 7 * 24 * time.Hour
	MinLearned    = 1000
	QuietFor      = 48 * time.Hour
	MinSupportIPs = 3
	MinSupportDay = 2
	maxReported   = 500 // gabarits listés dans un rapport
)

// Count est une valeur et le nombre de fois où elle a été vue.
type Count struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// ParamInfo décrit un paramètre de requête d'un gabarit.
type ParamInfo struct {
	Name     string   `json:"name"`
	Count    int64    `json:"count"`
	Kinds    []string `json:"kinds"`
	MaxLen   int      `json:"max_len"`
	Distinct int      `json:"distinct"`
	// Enum : peu de valeurs distinctes sur beaucoup de requêtes, donc un choix dans une liste.
	Enum bool `json:"enum,omitempty"`
}

// TemplateInfo est un gabarit de chemin et ce qu'on y a vu.
type TemplateInfo struct {
	Path          string      `json:"path"`
	Requests      int64       `json:"requests"`
	First         time.Time   `json:"first"`
	Last          time.Time   `json:"last"`
	Methods       []Count     `json:"methods"`
	Statuses      []Count     `json:"statuses"`
	RequestMedia  []Count     `json:"request_media,omitempty"`
	ResponseMedia []Count     `json:"response_media,omitempty"`
	BodyMax       int64       `json:"body_max,omitempty"`
	BodyP99       int64       `json:"body_p99,omitempty"`
	Params        []ParamInfo `json:"params,omitempty"`
	Clients       int         `json:"clients"`
	Days          int         `json:"days"`
	// LowSupport : peu de clients ou de jours distincts. Un gabarit pareil ne serait pas proposé (un seul client, un
	// scanner par exemple, pourrait l'avoir inscrit).
	LowSupport bool `json:"low_support,omitempty"`
}

// ViolationReasons liste les types de violation de la politique (ceux de `block_reasons` du contrôle openapi).
var ViolationReasons = []string{"unknown_path", "unknown_method", "invalid_param", "invalid_body", "unsupported_media", "too_large"}

// ViolationInfo est un groupe de requêtes que le contrôle openapi du proxy a jugées hors de la spécification.
type ViolationInfo struct {
	// Reason : unknown_path | unknown_method | invalid_param | invalid_body | unsupported_media | too_large.
	Reason  string `json:"reason"`
	Method  string `json:"method"`
	Path    string `json:"path"` // normalisé : jamais un identifiant
	Count   int64  `json:"count"`
	Legit   int64  `json:"legit"`
	Blocked int64  `json:"blocked"`
	Clients int    `json:"clients"`
	// CleanClients et Days : clients distincts d'IP propres, et jours où ils sont venus.
	CleanClients int       `json:"clean_clients"`
	Days         int       `json:"days"`
	First        time.Time `json:"first"`
	Last         time.Time `json:"last"`
	// LikelyLegit : ces requêtes réussissent le plus souvent, depuis plusieurs clients propres : c'est probablement un chemin
	// légitime qui manque à la politique, pas une attaque.
	LikelyLegit bool `json:"likely_legit,omitempty"`
}

// WAFRuleInfo est une règle du WAF déclenchée sur le proxy.
type WAFRuleInfo struct {
	ID       int     `json:"id"`
	Category string  `json:"category"`
	Message  string  `json:"message"`
	Targets  []Count `json:"targets"`
	Hits     int64   `json:"hits"`
	Clean    int64   `json:"clean"`
	Served   int64   `json:"served"`
	Blocked  int64   `json:"blocked"`
	Clients  int     `json:"clients"`
	Days     int     `json:"days"`
	Paths    []Count `json:"paths"`
}

// Convergence dit si le profil est assez mûr pour qu'on s'y fie.
type Convergence struct {
	Converged     bool     `json:"converged"`
	AgeSeconds    int64    `json:"age_seconds"`
	MinAgeSeconds int64    `json:"min_age_seconds"`
	Learned       int64    `json:"learned"`
	MinLearned    int64    `json:"min_learned"`
	NewTemplates  int      `json:"new_templates"`
	QuietSeconds  int64    `json:"quiet_seconds"`
	Overflow      bool     `json:"overflow,omitempty"`
	Reasons       []string `json:"reasons,omitempty"`
}

// Report est le rapport d'un proxy.
type Report struct {
	Route string `json:"route"`
	Host  string `json:"host"`
	Mode  string `json:"mode"`
	// Type : api | site, tel que la configuration du proxy le déclare. TypeHint : ce que le trafic laisse penser (vide si trop peu de requêtes).
	Type        string `json:"type,omitempty"`
	TypeHint    string `json:"type_hint,omitempty"`
	TypeHintWhy string `json:"type_hint_why,omitempty"`
	// Members : nombre de profils fusionnés (celui de la passerelle et ceux de ses pairs de groupe).
	Members   int       `json:"members"`
	Since     time.Time `json:"since"`
	Last      time.Time `json:"last"`
	Requests  int64     `json:"requests"`
	Learned   int64     `json:"learned"`
	Excluded  int64     `json:"excluded"`
	Overflow  int64     `json:"overflow,omitempty"`
	Failed    []Count   `json:"failed"`
	Methods   []Count   `json:"methods"`
	Headers   []Count   `json:"headers"`
	Protocols []Count   `json:"protocols"`
	TLS       []Count   `json:"tls"`
	Countries []Count   `json:"countries"`
	ASNs      []Count   `json:"asns"`
	Clients   int       `json:"clients"`
	// RequestMedia, ResponseMedia, BodyMax et BodyP99 : pour le proxy entier.
	RequestMedia  []Count        `json:"request_media"`
	ResponseMedia []Count        `json:"response_media"`
	BodyMax       int64          `json:"body_max,omitempty"`
	BodyP99       int64          `json:"body_p99,omitempty"`
	TemplateCount int            `json:"template_count"`
	Templates     []TemplateInfo `json:"templates"`
	Convergence   Convergence    `json:"convergence"`
	// ViolationTotals et Violations : ce que le contrôle openapi du proxy a vu hors de la spécification (ADR 0016, étape 3).
	ViolationTotals    []Count         `json:"violation_totals"`
	BlockedTotals      []Count         `json:"blocked_totals"`
	Violations         []ViolationInfo `json:"violations"`
	ViolationsOverflow int64           `json:"violations_overflow,omitempty"`
	// Suggestions : ce que la politique devrait probablement ajouter (ADR 0016, étape 5). Elle ne s'élargit jamais seule.
	Suggestions []Suggestion `json:"suggestions"`
	// WAF : les règles du WAF déclenchées, les plus fréquentes sur des clients propres d'abord.
	WAF         []WAFRuleInfo `json:"waf"`
	WAFOverflow int64         `json:"waf_overflow,omitempty"`
}

// Summary est la ligne d'un proxy dans la liste.
type Summary struct {
	Route     string    `json:"route"`
	Host      string    `json:"host"`
	Mode      string    `json:"mode"`
	Members   int       `json:"members"`
	Requests  int64     `json:"requests"`
	Learned   int64     `json:"learned"`
	Excluded  int64     `json:"excluded"`
	Templates int       `json:"templates"`
	Since     time.Time `json:"since"`
	Last      time.Time `json:"last"`
	Converged bool      `json:"converged"`
	// Suggestions : nombre d'ajouts suggérés à la politique.
	Suggestions int `json:"suggestions"`
}

// Report rend le rapport du proxy, vu par le groupe. mode est celui de la configuration du proxy.
func (c *Collector) Report(routeID, mode string) (Report, bool) {
	rp, members := c.merged(routeID)
	if rp == nil {
		return Report{}, false
	}
	return buildReport(routeID, mode, rp, members, c.opt.Now()), true
}

// Summary rend la ligne du proxy ; faux s'il n'a aucun profil.
func (c *Collector) Summary(routeID, mode string) (Summary, bool) {
	rp, members := c.merged(routeID)
	if rp == nil {
		return Summary{}, false
	}
	now := c.opt.Now()
	tpls := templates(rp)
	return Summary{
		Route: routeID, Host: rp.Host, Mode: mode, Members: members,
		Requests: rp.Requests, Learned: rp.Learned, Excluded: rp.Excluded, Templates: len(tpls),
		Since: unix(rp.Since), Last: unix(rp.Last), Converged: convergence(rp, tpls, now).Converged, Suggestions: len(suggestionsOf(rp)),
	}, true
}

func unix(ts int64) time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
}

func buildReport(id, mode string, rp *RouteProfile, members int, now time.Time) Report {
	tpls := templates(rp)
	r := Report{
		Route: id, Host: rp.Host, Mode: mode, Members: members, Since: unix(rp.Since), Last: unix(rp.Last),
		Requests: rp.Requests, Learned: rp.Learned, Excluded: rp.Excluded, Overflow: rp.Overflow,
		Methods: counts(rp.Methods), Headers: counts(rp.Headers), Protocols: counts(rp.Protocols), TLS: counts(rp.TLS),
		Countries: counts(rp.Countries), Clients: rp.Clients.Estimate(), TemplateCount: len(tpls),
		Type: rp.Type, RequestMedia: counts(rp.ReqMedia), ResponseMedia: counts(rp.RespMedia), BodyMax: rp.BodyMax, BodyP99: bodyP99Of(rp.BodyHist, rp.BodyMax),
		Failed: []Count{}, ASNs: []Count{},
	}
	for st, n := range rp.Failed {
		name := strconv.Itoa(st)
		if st == 0 {
			name = "(autres)"
		}
		r.Failed = append(r.Failed, Count{Name: name, Count: n})
	}
	sortCounts(r.Failed)
	asn := make(map[string]int64, len(rp.ASNs))
	for a, n := range rp.ASNs {
		asn["AS"+strconv.FormatUint(uint64(a), 10)] = n
	}
	r.ASNs = counts(asn)
	r.Convergence = convergence(rp, tpls, now)
	r.TypeHint, r.TypeHintWhy = typeHint(rp)
	r.ViolationTotals, r.Violations, r.ViolationsOverflow = violationInfos(rp)
	r.BlockedTotals = counts(rp.BlockedTotals)
	r.Suggestions = suggestionsOf(rp)
	r.WAF, r.WAFOverflow = wafInfos(rp)
	if len(tpls) > maxReported {
		tpls = tpls[:maxReported]
	}
	r.Templates = tpls
	return r
}

// convergence évalue ancienneté, volume, nouveaux gabarits et débordement.
func convergence(rp *RouteProfile, tpls []TemplateInfo, now time.Time) Convergence {
	c := Convergence{
		MinAgeSeconds: int64(MinAge.Seconds()), Learned: rp.Learned, MinLearned: MinLearned,
		QuietSeconds: int64(QuietFor.Seconds()), Overflow: rp.Overflow > 0,
	}
	if rp.Since != 0 {
		c.AgeSeconds = now.Unix() - rp.Since
	}
	site := IsSite(rp.Type)
	if site {
		// Un site a des milliers de chemins qui changent chaque jour : ni leurs nouveautés ni leur débordement ne disent rien de la maturité.
		c.Overflow = false
	}
	for _, t := range tpls {
		if !site && now.Sub(t.First) < QuietFor {
			c.NewTemplates++
		}
	}
	if c.AgeSeconds < c.MinAgeSeconds {
		c.Reasons = append(c.Reasons, fmt.Sprintf("ancienneté %s sur %s", dur(c.AgeSeconds), dur(c.MinAgeSeconds)))
	}
	if c.Learned < c.MinLearned {
		c.Reasons = append(c.Reasons, fmt.Sprintf("volume %d sur %d requêtes", c.Learned, c.MinLearned))
	}
	if c.NewTemplates > 0 {
		c.Reasons = append(c.Reasons, fmt.Sprintf("%d nouveau(x) gabarit(s) de chemin depuis %d h", c.NewTemplates, int(QuietFor.Hours())))
	}
	if c.Overflow {
		c.Reasons = append(c.Reasons, "trop de chemins distincts : une partie n'a pas pu être retenue")
	}
	c.Converged = len(c.Reasons) == 0
	return c
}

func dur(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	if d >= 24*time.Hour {
		return fmt.Sprintf("%d j", int(d.Hours()/24))
	}
	return fmt.Sprintf("%d h", int(d.Hours()))
}

// templates liste les gabarits du profil, les plus demandés d'abord.
func templates(rp *RouteProfile) []TemplateInfo {
	var out []TemplateInfo
	var walk func(n *Node, segs []string)
	walk = func(n *Node, segs []string) {
		if t := n.Stats; t != nil && t.Requests > 0 {
			out = append(out, templateInfo("/"+strings.Join(segs, "/"), t))
		}
		for k, c := range n.Children {
			walk(c, append(segs[:len(segs):len(segs)], k))
		}
	}
	walk(rp.Root, nil)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func templateInfo(path string, t *Template) TemplateInfo {
	ti := TemplateInfo{
		Path: path, Requests: t.Requests, First: unix(t.First), Last: unix(t.Last),
		Methods: counts(t.Methods), RequestMedia: counts(t.ReqMedia), ResponseMedia: counts(t.RespMedia),
		BodyMax: t.BodyMax, BodyP99: bodyP99(t), Clients: t.Clients.Estimate(), Days: len(t.Days), Statuses: []Count{},
	}
	for st, n := range t.Statuses {
		ti.Statuses = append(ti.Statuses, Count{Name: strconv.Itoa(st), Count: n})
	}
	sortCounts(ti.Statuses)
	for name, p := range t.Params {
		ti.Params = append(ti.Params, ParamInfo{
			Name: name, Count: p.Count, Kinds: kindNames(p.Kinds), MaxLen: p.MaxLen, Distinct: p.Distinct,
			Enum: p.Distinct > 0 && p.Distinct < maxParamValues && p.Count >= 20,
		})
	}
	sort.Slice(ti.Params, func(i, j int) bool { return ti.Params[i].Name < ti.Params[j].Name })
	ti.LowSupport = ti.Clients < MinSupportIPs || ti.Days < MinSupportDay
	return ti
}

func kindNames(k uint8) []string {
	out := []string{}
	for _, e := range []struct {
		bit  uint8
		name string
	}{{KindInt, "entier"}, {KindUUID, "uuid"}, {KindBool, "booléen"}, {KindText, "texte"}, {KindEmpty, "vide"}} {
		if k&e.bit != 0 {
			out = append(out, e.name)
		}
	}
	return out
}

// bodyP99 rend la borne haute du 99e centile de la taille des corps de requête.
func bodyP99(t *Template) int64 { return bodyP99Of(t.Body, t.BodyMax) }

// bodyP99Of rend la borne haute du 99e centile d'un histogramme de tailles de corps (index i = valeurs de 2^(i-1) à 2^i-1 octets).
func bodyP99Of(hist []int64, max int64) int64 {
	var total int64
	for _, n := range hist {
		total += n
	}
	if total == 0 {
		return 0
	}
	rank := (total*99 + 99) / 100
	var cum int64
	for i, n := range hist {
		cum += n
		if cum >= rank {
			if i == 0 {
				return 0
			}
			upper := int64(1)<<uint(i) - 1
			if max > 0 && upper > max {
				upper = max
			}
			return upper
		}
	}
	return max
}

func counts[K ~string](m map[K]int64) []Count {
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{Name: string(k), Count: n})
	}
	sortCounts(out)
	return out
}

func sortCounts(c []Count) {
	sort.Slice(c, func(i, j int) bool {
		if c[i].Count != c[j].Count {
			return c[i].Count > c[j].Count
		}
		return c[i].Name < c[j].Name
	})
}

func violationInfos(rp *RouteProfile) ([]Count, []ViolationInfo, int64) {
	totals := counts(rp.ViolationTotals)
	list := make([]ViolationInfo, 0, len(rp.Violations))
	for key, v := range rp.Violations {
		parts := strings.SplitN(key, " ", 3)
		if len(parts) != 3 {
			continue
		}
		vi := ViolationInfo{
			Reason: parts[0], Method: parts[1], Path: parts[2], Count: v.Count, Legit: v.Legit, Blocked: v.Blocked,
			Clients: v.Clients.Estimate(), CleanClients: v.CleanClients.Estimate(), Days: len(v.Days), First: unix(v.First), Last: unix(v.Last),
		}
		vi.LikelyLegit = v.Legit >= 5 && vi.Clients >= MinSupportIPs && v.Legit*2 >= v.Count
		list = append(list, vi)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Reason+list[i].Method+list[i].Path < list[j].Reason+list[j].Method+list[j].Path
	})
	if len(list) > 50 {
		list = list[:50]
	}
	return totals, list, rp.ViolationsOverflow
}

func wafInfos(rp *RouteProfile) ([]WAFRuleInfo, int64) {
	out := make([]WAFRuleInfo, 0, len(rp.WAF))
	for id, w := range rp.WAF {
		out = append(out, WAFRuleInfo{
			ID: id, Category: w.Category, Message: w.Message, Targets: counts(w.Targets), Hits: w.Hits, Clean: w.Clean,
			Served: w.Served, Blocked: w.Blocked, Clients: w.Clients.Estimate(), Days: len(w.Days), Paths: counts(w.Paths),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Clean != out[j].Clean {
			return out[i].Clean > out[j].Clean
		}
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > 30 {
		out = out[:30]
	}
	return out, rp.WAFOverflow
}

// typeHint dit si le trafic ressemble à une API ou à un site, pour que l'administrateur le déclare : un niveau de chemin qui compte plus
// de valeurs distinctes que maxLiteralChildren (articles, pages, noms propres) ou des chemins que le profil n'a pas pu retenir sont ceux
// d'un contenu ouvert, pas d'une surface fermée.
func typeHint(rp *RouteProfile) (string, string) {
	if rp.Learned < minProposeLearn {
		return "", ""
	}
	if rp.Overflow > 0 {
		return TypeSite, "plus de chemins distincts que le profil n'en retient : c'est un contenu ouvert"
	}
	if n := countVarNodes(rp.Root); n > 0 {
		return TypeSite, fmt.Sprintf("%d niveau(x) de chemin comptent plus de %d valeurs distinctes (pages, articles, noms) : c'est un contenu ouvert", n, maxLiteralChildren)
	}
	return TypeAPI, "les chemins sont peu nombreux et se regroupent en gabarits d'identifiants : c'est une surface fermée"
}

func countVarNodes(n *Node) int {
	c := 0
	for k, ch := range n.Children {
		if k == clsVar {
			c++
		}
		c += countVarNodes(ch)
	}
	return c
}
