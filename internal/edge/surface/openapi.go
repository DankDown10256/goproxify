// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Génération d'une spécification OpenAPI à partir du profil (ADR 0016, étape 3). La politique positive n'est pas un nouveau
// format : c'est le contrôle `openapi` que le proxy a déjà, posé en mode `detect` (la requête passe toujours, la violation est
// comptée). Le profil ne sait pas décrire un corps JSON : la spécification déclare les chemins, les méthodes, les paramètres
// typés et les types de contenu, et laisse les schémas de corps vides.

// OpenAPIOptions règle la génération.
type OpenAPIOptions struct {
	// IncludeLowSupport garde aussi les chemins vus par peu de clients ou de jours (à confirmer).
	IncludeLowSupport bool
	// Replaces : le proxy a déjà un contrôle openapi activé, que cette configuration remplacerait.
	Replaces bool
}

// ExcludedPath est un chemin du profil que la spécification ne contient pas, avec la raison.
type ExcludedPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// OpenAPIResult est la politique générée pour un proxy.
type OpenAPIResult struct {
	Route       string      `json:"route"`
	Host        string      `json:"host"`
	Members     int         `json:"members"`
	Learned     int64       `json:"learned"`
	Convergence Convergence `json:"convergence"`
	// Ready : le profil est fiable (convergé, sans débordement) : la politique peut passer en `block` après lecture des violations.
	Ready bool `json:"ready"`
	// Config est la valeur du réglage `openapi` du proxy : activée, en mode detect, chemins inconnus comptés comme violations.
	Config json.RawMessage `json:"config,omitempty"`
	// Command pose la configuration : l'enregistrer d'abord dans le fichier (champ config), `proxy option … openapi @fichier`.
	Command    string         `json:"command,omitempty"`
	Paths      int            `json:"paths"`
	Operations int            `json:"operations"`
	Parameters int            `json:"parameters"`
	Replaces   bool           `json:"replaces,omitempty"`
	Excluded   []ExcludedPath `json:"excluded"`
	Cautions   []string       `json:"cautions"`
	// Error : pourquoi aucune spécification n'a pu être produite.
	Error string `json:"error,omitempty"`
}

type oaSeg struct {
	key   string // segment littéral, ou classe ({int}, {uuid}…)
	class bool
}

type oaCandidate struct {
	segs []oaSeg
	info TemplateInfo
	t    *Template
}

// OpenAPI génère la politique du proxy à partir de son profil. Faux si la passerelle n'a pas de profil.
func (c *Collector) OpenAPI(routeID string, opt OpenAPIOptions) (OpenAPIResult, bool) {
	rp, members := c.merged(routeID)
	if rp == nil {
		return OpenAPIResult{}, false
	}
	now := c.opt.Now()
	tpls := templates(rp)
	res := OpenAPIResult{
		Route: routeID, Host: rp.Host, Members: members, Learned: rp.Learned, Replaces: opt.Replaces,
		Convergence: convergence(rp, tpls, now), Excluded: []ExcludedPath{}, Cautions: []string{},
	}
	if IsSite(rp.Type) {
		res.Error = "ce proxy est de type site (surface ouverte, milliers de chemins) : une liste de chemins autorisés n'a pas de sens ; le profil propose des tailles, des réseaux, des pays et l'exclusion de règles du WAF, pas une politique de chemins. Déclarez surface.type = api si c'est une API"
		return res, true
	}
	if rp.Learned < minProposeLearn {
		res.Error = fmt.Sprintf("seulement %d requêtes apprises sur %d nécessaires", rp.Learned, minProposeLearn)
		return res, true
	}

	var cands []*oaCandidate
	var walk func(n *Node, segs []oaSeg)
	walk = func(n *Node, segs []oaSeg) {
		if t := n.Stats; t != nil && t.Requests > 0 {
			cands = append(cands, &oaCandidate{segs: append([]oaSeg(nil), segs...), t: t, info: templateInfo(pathOf(segs), t)})
		}
		for k, ch := range n.Children {
			walk(ch, append(segs[:len(segs):len(segs)], oaSeg{key: k, class: isClassKey(k)}))
		}
	}
	walk(rp.Root, nil)

	var kept []*oaCandidate
	exclude := func(path, why string, args ...any) {
		if len(res.Excluded) < 50 {
			res.Excluded = append(res.Excluded, ExcludedPath{Path: path, Reason: fmt.Sprintf(why, args...)})
		}
	}
	for _, cd := range cands {
		switch {
		case hasSeg(cd.segs, clsMore):
			exclude(cd.info.Path, "chemin plus profond que %d segments", maxSegments)
		case hasBraceLiteral(cd.segs):
			exclude(cd.info.Path, "un segment contient une accolade : inexprimable dans OpenAPI")
		case cd.info.LowSupport && !opt.IncludeLowSupport:
			exclude(cd.info.Path, "faible soutien (%d client(s), %d jour(s)) : à confirmer", cd.info.Clients, cd.info.Days)
		default:
			kept = append(kept, cd)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].info.Requests > kept[j].info.Requests })

	paths, ops, params := buildOpenAPIPaths(kept)
	if len(paths) == 0 {
		res.Error = "aucun chemin assez soutenu pour entrer dans la politique : attendre que plusieurs clients l'aient utilisé sur plusieurs jours, ou inclure les chemins à confirmer"
		return res, true
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Surface apprise de " + rp.Host,
			"version":     "appris-" + now.UTC().Format("2006-01-02"),
			"description": "Générée par l'apprentissage de surface de GoProxify (ADR 0016) à partir du trafic légitime observé. Ne décrit ni les corps ni les réponses.",
		},
		"paths": paths,
	}
	cfg, err := json.Marshal(map[string]any{
		"enabled": true, "mode": "detect", "unknown_paths": "block", "spec": doc,
	})
	if err != nil {
		res.Error = err.Error()
		return res, true
	}
	res.Config = cfg
	res.Command = fmt.Sprintf("goproxify proxy option %s openapi @openapi.json", routeID)
	res.Paths, res.Operations, res.Parameters = len(paths), ops, params
	res.Ready = res.Convergence.Converged
	res.Cautions = openAPICautions(rp, res, kept)
	return res, true
}

func openAPICautions(rp *RouteProfile, res OpenAPIResult, kept []*oaCandidate) []string {
	out := []string{"mode detect : aucune requête n'est refusée ; les chemins, méthodes, types de contenu et paramètres hors de la politique sont comptés (rapport de surface, métrique openapi) avant tout passage en block"}
	if !res.Convergence.Converged {
		out = append(out, "profil pas encore fiable : "+strings.Join(res.Convergence.Reasons, " ; "))
	}
	if rp.Overflow > 0 {
		out = append(out, fmt.Sprintf("%d requêtes sur des chemins que le profil n'a pas pu retenir : elles seraient vues comme violations", rp.Overflow))
	}
	if n := len(res.Excluded); n > 0 {
		out = append(out, fmt.Sprintf("%d chemin(s) du profil ne sont pas dans la politique (voir excluded) : leurs requêtes seraient vues comme violations", n))
	}
	for _, cd := range kept {
		if hasSeg(cd.segs, clsVar) {
			out = append(out, "un niveau de chemin comptait plus de 64 valeurs distinctes : il est écrit {name}, sans type")
			break
		}
	}
	out = append(out,
		"le profil n'apprend pas le contenu des corps : la politique ne les contrôle que par leur type de contenu",
		"le contrôle openapi ne refuse pas un paramètre de requête inconnu : seuls les paramètres déclarés sont contrôlés",
	)
	if res.Replaces {
		out = append(out, "ce proxy a déjà un contrôle openapi activé : cette configuration le remplacerait")
	}
	return out
}

func hasSeg(segs []oaSeg, key string) bool {
	for _, s := range segs {
		if s.key == key {
			return true
		}
	}
	return false
}

func hasBraceLiteral(segs []oaSeg) bool {
	for _, s := range segs {
		if !s.class && strings.ContainsAny(s.key, "{}") {
			return true
		}
	}
	return false
}

func pathOf(segs []oaSeg) string {
	if len(segs) == 0 {
		return "/"
	}
	parts := make([]string, len(segs))
	for i, s := range segs {
		parts[i] = s.key
	}
	return "/" + strings.Join(parts, "/")
}

// opAcc accumule les méthodes d'un chemin OpenAPI : plusieurs gabarits du profil qui se recouvrent (/x/{int} et /x/{var})
// n'en font qu'un, sans quoi le contrôle, qui choisit le premier chemin qui correspond, refuserait à tort.
type opAcc struct {
	statuses map[int]bool
	media    map[string]bool
	otherMed bool
	body     bool
	params   map[string]uint8
}

type pathAcc struct {
	segs  []oaSeg
	kinds []map[string]bool // classes vues à chaque position de paramètre
	ops   map[string]*opAcc
}

var oaMethods = map[string]bool{"GET": true, "PUT": true, "POST": true, "DELETE": true, "OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": true}

func buildOpenAPIPaths(kept []*oaCandidate) (map[string]any, int, int) {
	groups := map[string]*pathAcc{}
	var order []string
	for _, cd := range kept {
		sig := make([]string, len(cd.segs))
		for i, s := range cd.segs {
			if s.class {
				sig[i] = "{}"
			} else {
				sig[i] = s.key
			}
		}
		key := strings.Join(sig, "/")
		g := groups[key]
		if g == nil {
			g = &pathAcc{segs: cd.segs, ops: map[string]*opAcc{}}
			for _, s := range cd.segs {
				if s.class {
					g.kinds = append(g.kinds, map[string]bool{})
				}
			}
			groups[key] = g
			order = append(order, key)
		}
		pi := 0
		for _, s := range cd.segs {
			if s.class {
				g.kinds[pi][s.key] = true
				pi++
			}
		}
		for m := range cd.t.Methods {
			if !oaMethods[m] {
				continue
			}
			op := g.ops[m]
			if op == nil {
				op = &opAcc{statuses: map[int]bool{}, media: map[string]bool{}, params: map[string]uint8{}}
				g.ops[m] = op
			}
			for st := range cd.t.Statuses {
				op.statuses[st] = true
			}
			for mt := range cd.t.ReqMedia {
				if mt == "(autres)" {
					op.otherMed = true
				} else {
					op.media[mt] = true
				}
			}
			if len(cd.t.Body) > 0 {
				op.body = true
			}
			for name, p := range cd.t.Params {
				op.params[name] |= p.Kinds
			}
		}
	}

	paths := map[string]any{}
	var nOps, nParams int
	for _, key := range order {
		g := groups[key]
		if len(g.ops) == 0 {
			continue
		}
		names, shown := pathParamNames(g)
		item := map[string]any{}
		for m, op := range g.ops {
			o := map[string]any{"summary": "observé pendant l'apprentissage"}
			var plist []any
			pi := 0
			for _, s := range g.segs {
				if s.class {
					plist = append(plist, map[string]any{"name": names[pi], "in": "path", "required": true, "schema": classSchema(g.kinds[pi])})
					pi++
				}
			}
			qnames := make([]string, 0, len(op.params))
			for n := range op.params {
				qnames = append(qnames, n)
			}
			sort.Strings(qnames)
			for _, n := range qnames {
				plist = append(plist, map[string]any{"name": n, "in": "query", "required": false, "schema": kindSchema(op.params[n])})
			}
			nParams += len(plist)
			if len(plist) > 0 {
				o["parameters"] = plist
			}
			if (m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE") && len(op.media) > 0 && !op.otherMed {
				content := map[string]any{}
				for mt := range op.media {
					content[mt] = map[string]any{}
				}
				o["requestBody"] = map[string]any{"required": false, "content": content}
			}
			resp := map[string]any{}
			for st := range op.statuses {
				resp[strconv.Itoa(st)] = map[string]any{"description": "observé"}
			}
			if len(resp) == 0 {
				resp["default"] = map[string]any{"description": "observé"}
			}
			o["responses"] = resp
			item[strings.ToLower(m)] = o
			nOps++
		}
		paths[shown] = item
	}
	return paths, nOps, nParams
}

// pathParamNames nomme les paramètres de chemin d'après le segment qui les précède (/users/{users_id}) et rend le chemin OpenAPI.
func pathParamNames(g *pathAcc) ([]string, string) {
	var names []string
	used := map[string]int{}
	parts := make([]string, len(g.segs))
	prev := "p"
	pi := 0
	for i, s := range g.segs {
		if !s.class {
			parts[i] = s.key
			if b := sanitizeName(s.key); b != "" {
				prev = b
			}
			continue
		}
		suffix := "value"
		if len(g.kinds[pi]) == 1 {
			for k := range g.kinds[pi] {
				suffix = classSuffix(k)
			}
		}
		n := prev + "_" + suffix
		used[n]++
		if used[n] > 1 {
			n += strconv.Itoa(used[n])
		}
		names = append(names, n)
		parts[i] = "{" + n + "}"
		pi++
	}
	if len(parts) == 0 {
		return names, "/"
	}
	return names, "/" + strings.Join(parts, "/")
}

func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteByte('_')
		}
	}
	if b.Len() > 24 {
		return b.String()[:24]
	}
	return b.String()
}

func classSuffix(cls string) string {
	switch cls {
	case clsInt:
		return "id"
	case clsUUID:
		return "uuid"
	case clsDate:
		return "date"
	case clsHex:
		return "hash"
	case clsEmail:
		return "email"
	case clsToken:
		return "token"
	case clsVar:
		return "name"
	}
	return "value"
}

// classSchema : le schéma d'un paramètre de chemin ; plusieurs classes à la même position se rabattent sur un texte.
func classSchema(kinds map[string]bool) map[string]any {
	if len(kinds) != 1 {
		return map[string]any{"type": "string"}
	}
	for k := range kinds {
		switch k {
		case clsInt:
			return map[string]any{"type": "integer"}
		case clsUUID:
			return map[string]any{"type": "string", "format": "uuid"}
		case clsDate:
			return map[string]any{"type": "string", "format": "date"}
		case clsHex:
			return map[string]any{"type": "string", "pattern": "^[0-9a-fA-F]+$"}
		}
	}
	return map[string]any{"type": "string"}
}

// kindSchema : le schéma d'un paramètre de requête d'après les types de valeurs vus. Une valeur vide ou plusieurs types donnent un texte.
func kindSchema(k uint8) map[string]any {
	switch k {
	case KindInt:
		return map[string]any{"type": "integer"}
	case KindBool:
		return map[string]any{"type": "boolean"}
	case KindUUID:
		return map[string]any{"type": "string", "format": "uuid"}
	}
	return map[string]any{"type": "string"}
}
