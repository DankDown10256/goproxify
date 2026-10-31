// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Réglages que le profil sait proposer (ADR 0016, étape 2). Ce sont des réglages ordinaires du proxy : rien n'est appliqué, la
// proposition dit quoi poser, pourquoi, et ce que cela aurait refusé sur le trafic appris.
const (
	SettingMaxBody  = "max_body_size"
	SettingRate     = "rate_limit"
	SettingGeo      = "geo_ip"
	SettingIPFilter = "ip_filter"
	SettingCORS     = "cors"
	// SettingWAF : la configuration `waf` du proxy, avec des règles de plus dans exclude_ids.
	SettingWAF = "waf"
)

const (
	defaultMaxBody   = 100 << 20 // limite d'un proxy qui n'en règle pas
	minProposeLearn  = 100       // en dessous, aucun réglage n'est proposé
	maxProposeRanges = 16        // au-delà, le trafic vient d'Internet : une liste d'IP autorisées n'a pas de sens
	maxProposeGeo    = 15        // idem pour les pays
	maxProposeOrigin = 10
	geoCoverage      = 0.995 // part des requêtes résolues que les pays proposés doivent couvrir
	minBodyLimit     = 16 << 10
)

// Current est ce que le proxy règle déjà : une proposition ne remplace jamais un réglage de l'administrateur.
type Current struct {
	Host    string
	Aliases []string
	// MaxBodySize : 0 = limite par défaut (100 Mo), -1 = illimité.
	MaxBodySize                      int64
	RateLimit, IPFilter, GeoIP, CORS bool
	// WAF : la configuration `waf` du proxy (JSON), vide si le proxy n'en a pas en propre ; WAFFromSnippet : elle vient d'un snippet,
	// qu'une exclusion posée sur le proxy ne remplacerait pas. CustomRuleIDs : les règles écrites par l'administrateur, qu'on ne
	// propose jamais d'exclure.
	WAF            json.RawMessage
	WAFFromSnippet bool
	CustomRuleIDs  []int
}

// RateRef est une référence de débit apprise par Ephor pour une heure du jour (requêtes par minute et par IP).
type RateRef struct {
	Hour      int
	Median    float64
	Threshold float64
	Ready     bool
}

// Proposal est un réglage proposé, avec sa justification.
type Proposal struct {
	Setting string `json:"setting"`
	// Option et Value : la clé de configuration du proxy et sa valeur, telles que `goproxify proxy option` les pose.
	Option  string          `json:"option"`
	Value   json.RawMessage `json:"value"`
	Command string          `json:"command"`
	Current string          `json:"current"`
	Summary string          `json:"summary"`
	// Evidence : ce que le profil a vu ; Cautions : ce que le réglage ne sait pas dire.
	Evidence []string `json:"evidence"`
	Cautions []string `json:"cautions,omitempty"`
	// WouldRefuse sur Of requêtes apprises, quand le profil permet de le mesurer (Measured).
	WouldRefuse int64 `json:"would_refuse"`
	Of          int64 `json:"of"`
	Measured    bool  `json:"measured"`
}

// Skipped est un réglage que le profil ne propose pas, avec la raison.
type Skipped struct {
	Setting string `json:"setting"`
	Reason  string `json:"reason"`
}

// Proposals est la réponse d'une passerelle pour un proxy.
type Proposals struct {
	Route       string      `json:"route"`
	Host        string      `json:"host"`
	Members     int         `json:"members"`
	Learned     int64       `json:"learned"`
	Convergence Convergence `json:"convergence"`
	Items       []Proposal  `json:"items"`
	Skipped     []Skipped   `json:"skipped"`
	// Type : le type déclaré du proxy ; Notes : ce que ce type change aux propositions (ou l'indice que le trafic donne).
	Type  string   `json:"type,omitempty"`
	Notes []string `json:"notes"`
}

// Proposals propose des réglages pour le proxy à partir de son profil. Faux si la passerelle n'en a pas.
func (c *Collector) Proposals(routeID string, cur Current, refs []RateRef) (Proposals, bool) {
	rp, members := c.merged(routeID)
	if rp == nil {
		return Proposals{}, false
	}
	return propose(routeID, rp, members, cur, refs, c.opt.Now()), true
}

func propose(id string, rp *RouteProfile, members int, cur Current, refs []RateRef, now time.Time) Proposals {
	tpls := templates(rp)
	out := Proposals{
		Route: id, Host: rp.Host, Members: members, Learned: rp.Learned,
		Convergence: convergence(rp, tpls, now), Items: []Proposal{}, Skipped: []Skipped{}, Type: rp.Type, Notes: []string{},
	}
	switch hint, why := typeHint(rp); {
	case IsSite(rp.Type):
		out.Notes = append(out.Notes, "proxy de type site : la politique de chemins (OpenAPI) et ses ajouts ne sont pas proposés ; les tailles, réseaux, pays, CORS, débit et exclusions du WAF le sont comme pour une API")
	case rp.Type == "" && hint == TypeSite:
		out.Notes = append(out.Notes, "ce trafic ressemble à celui d'un site ("+why+") : déclarez surface.type = site pour que la convergence ne dépende plus des chemins et que la politique de chemins ne soit pas proposée")
	}
	skip := func(setting, why string, args ...any) {
		out.Skipped = append(out.Skipped, Skipped{Setting: setting, Reason: fmt.Sprintf(why, args...)})
	}
	if rp.Learned < minProposeLearn {
		for _, s := range []string{SettingMaxBody, SettingRate, SettingGeo, SettingIPFilter, SettingCORS, SettingWAF} {
			skip(s, "seulement %d requêtes apprises sur %d nécessaires", rp.Learned, minProposeLearn)
		}
		return out
	}
	add := func(p Proposal, value any) {
		b, _ := json.Marshal(value)
		p.Option, p.Value = p.Setting, b
		p.Command = fmt.Sprintf("goproxify proxy option %s %s '%s'", id, p.Setting, b)
		out.Items = append(out.Items, p)
	}
	proposeMaxBody(rp, cur, add, skip)
	proposeRate(refs, cur, add, skip)
	proposeGeo(rp, cur, add, skip)
	proposeIPFilter(rp, cur, add, skip)
	proposeCORS(rp, cur, add, skip)
	proposeWAF(rp, cur, add, skip)
	return out
}

type (
	addFn  func(Proposal, any)
	skipFn func(string, string, ...any)
)

func proposeMaxBody(rp *RouteProfile, cur Current, add addFn, skip skipFn) {
	// Les corps sont mesurés pour le proxy entier, pas par gabarit : des chemins que le profil n'a pas retenus ne les font pas oublier.
	var bodies int64
	for _, n := range rp.BodyHist {
		bodies += n
	}
	max, p99 := rp.BodyMax, bodyP99Of(rp.BodyHist, rp.BodyMax)
	if cur.MaxBodySize > 0 && cur.MaxBodySize < minBodyLimit {
		skip(SettingMaxBody, "limite actuelle déjà basse (%s)", fmtBytes(cur.MaxBodySize))
		return
	}
	if rp.UnknownBody > 0 {
		skip(SettingMaxBody, "%d requêtes envoient un corps de taille inconnue (transfert par morceaux) : leur taille n'est pas mesurable", rp.UnknownBody)
		return
	}
	limit := int64(65536)
	ev := []string{fmt.Sprintf("aucune requête avec corps sur %d requêtes apprises", rp.Learned)}
	if bodies > 0 {
		limit = niceBytes(max * 2)
		ev = []string{
			fmt.Sprintf("%d requêtes avec corps sur %d apprises", bodies, rp.Learned),
			fmt.Sprintf("plus gros corps vu : %s ; 99ᵉ centile au plus %s", fmtBytes(max), fmtBytes(p99)),
			"marge : le double du plus gros corps, arrondi au palier supérieur",
		}
	}
	effective := cur.MaxBodySize
	if effective == 0 {
		effective = defaultMaxBody
	}
	if effective > 0 && limit >= effective {
		skip(SettingMaxBody, "la limite actuelle (%s) est déjà au plus près du trafic appris", fmtBytes(effective))
		return
	}
	currentText := "limite par défaut (" + fmtBytes(defaultMaxBody) + ")"
	if cur.MaxBodySize < 0 {
		currentText = "illimité"
	} else if cur.MaxBodySize > 0 {
		currentText = fmtBytes(cur.MaxBodySize)
	}
	add(Proposal{
		Setting: SettingMaxBody, Current: currentText, Summary: "Limiter le corps des requêtes à " + fmtBytes(limit),
		Evidence: ev, WouldRefuse: 0, Of: bodies, Measured: true,
		Cautions: []string{"une route rarement appelée (import, envoi de fichier) peut dépasser : elle n'apparaît dans le profil que si elle a été utilisée pendant l'apprentissage"},
	}, limit)
}

func proposeRate(refs []RateRef, cur Current, add addFn, skip skipFn) {
	if cur.RateLimit {
		skip(SettingRate, "un rate limit est déjà réglé sur ce proxy")
		return
	}
	var ready int
	var thr, med float64
	for _, r := range refs {
		if !r.Ready {
			continue
		}
		ready++
		thr = math.Max(thr, r.Threshold)
		med = math.Max(med, r.Median)
	}
	if ready == 0 {
		skip(SettingRate, "les références de débit d'Ephor sont encore en apprentissage (30 minutes observées par heure du jour, 24 h d'ancienneté de la route)")
		return
	}
	rps := math.Max(5, math.Ceil(thr*2/60))
	burst := int(math.Max(10, rps*2))
	add(Proposal{
		Setting: SettingRate, Current: "aucun",
		Summary: fmt.Sprintf("Limiter chaque IP à %.0f requêtes par seconde (rafale %d)", rps, burst),
		Evidence: []string{
			fmt.Sprintf("%d heure(s) du jour sur 24 ont une référence de débit fiable", ready),
			fmt.Sprintf("seuil de comportement le plus haut : %.0f requêtes par minute et par IP (médiane la plus haute : %.0f)", thr, med),
			"marge : le double de ce seuil, converti en requêtes par seconde, jamais sous 5",
		},
		Cautions: []string{"le débit est mesuré par IP : plusieurs personnes derrière une même adresse (entreprise, mobile) partagent ce plafond", "non mesuré sur le trafic appris : seul Ephor connaît le débit par IP"},
	}, map[string]any{"rps": rps, "burst": burst})
}

func proposeGeo(rp *RouteProfile, cur Current, add addFn, skip skipFn) {
	if cur.GeoIP {
		skip(SettingGeo, "un filtre géographique est déjà réglé sur ce proxy")
		return
	}
	var resolved int64
	type kv struct {
		cc string
		n  int64
	}
	var list []kv
	for cc, n := range rp.Countries {
		if cc == "(autres)" {
			continue
		}
		resolved += n
		list = append(list, kv{cc, n})
	}
	if resolved == 0 || resolved*10 < rp.Learned*9 {
		skip(SettingGeo, "le pays est inconnu pour %d requêtes apprises sur %d (base GeoIP absente, ou clients en réseau privé)", rp.Learned-resolved, rp.Learned)
		return
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].cc < list[j].cc
	})
	var chosen []string
	var covered int64
	for _, e := range list {
		if float64(covered) >= geoCoverage*float64(resolved) {
			break
		}
		chosen = append(chosen, e.cc)
		covered += e.n
	}
	if len(chosen) > maxProposeGeo {
		skip(SettingGeo, "il faudrait %d pays pour couvrir le trafic : c'est un service mondial", len(chosen))
		return
	}
	refused := rp.Learned - covered
	if refused*100 > rp.Learned {
		skip(SettingGeo, "refuserait %d requêtes apprises sur %d (clients sans pays connu, réseau privé ?)", refused, rp.Learned)
		return
	}
	sort.Strings(chosen)
	parts := make([]string, 0, len(list))
	for _, e := range list[:min(len(list), 6)] {
		parts = append(parts, fmt.Sprintf("%s %.1f %%", e.cc, 100*float64(e.n)/float64(rp.Learned)))
	}
	add(Proposal{
		Setting: SettingGeo, Current: "aucun",
		Summary: "N'accepter que les clients de : " + strings.Join(chosen, ", "),
		Evidence: []string{
			fmt.Sprintf("%d pays vus ; ceux-ci couvrent %.1f %% des requêtes dont le pays est connu", len(list), 100*float64(covered)/float64(resolved)),
			"répartition : " + strings.Join(parts, ", "),
		},
		Cautions:    []string{"un voyageur ou un nouveau partenaire dans un autre pays serait refusé", "une adresse sans pays connu (réseau privé) est refusée en mode allow"},
		WouldRefuse: refused, Of: rp.Learned, Measured: true,
	}, map[string]any{"mode": "allow", "countries": chosen})
}

func proposeIPFilter(rp *RouteProfile, cur Current, add addFn, skip skipFn) {
	if cur.IPFilter {
		skip(SettingIPFilter, "un filtre d'IP est déjà réglé sur ce proxy")
		return
	}
	var counted int64
	for _, n := range rp.Ranges {
		counted += n
	}
	switch {
	case rp.RangesOverflow > 0 || len(rp.Ranges) > maxProposeRanges:
		skip(SettingIPFilter, "les clients viennent de plus de %d réseaux : c'est un service public", maxProposeRanges)
		return
	case len(rp.Ranges) == 0 || counted < rp.Learned*99/100:
		skip(SettingIPFilter, "le profil ne connaît le réseau que de %d requêtes sur %d", counted, rp.Learned)
		return
	}
	keys := make([]uint64, 0, len(rp.Ranges))
	for k := range rp.Ranges {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if rp.Ranges[keys[i]] != rp.Ranges[keys[j]] {
			return rp.Ranges[keys[i]] > rp.Ranges[keys[j]]
		}
		return keys[i] < keys[j]
	})
	cidrs := make([]string, len(keys))
	parts := make([]string, 0, len(keys))
	for i, k := range keys {
		cidrs[i] = rangeCIDR(k)
		parts = append(parts, fmt.Sprintf("%s %.1f %%", cidrs[i], 100*float64(rp.Ranges[k])/float64(rp.Learned)))
	}
	add(Proposal{
		Setting: SettingIPFilter, Current: "aucun",
		Summary: fmt.Sprintf("N'accepter que %d réseau(x) de clients", len(cidrs)),
		Evidence: []string{
			fmt.Sprintf("tous les clients appris viennent de %d réseau(x) /24 ou /48 seulement", len(cidrs)),
			"réseaux : " + strings.Join(parts, ", "),
		},
		Cautions: []string{
			"ne protège que si les clients futurs sortent des mêmes réseaux (application interne, partenaires fixes) : un client mobile ou un nouveau site serait refusé",
			"les réseaux sont élargis au /24 (IPv4) ou /48 (IPv6) : le profil ne garde jamais l'adresse exacte",
		},
		WouldRefuse: 0, Of: rp.Learned, Measured: true,
	}, map[string]any{"mode": "allow", "cidrs": cidrs})
}

func proposeCORS(rp *RouteProfile, cur Current, add addFn, skip skipFn) {
	if cur.CORS {
		skip(SettingCORS, "CORS est déjà réglé sur ce proxy")
		return
	}
	own := map[string]bool{strings.ToLower(cur.Host): true, strings.ToLower(rp.Host): true}
	for _, a := range cur.Aliases {
		own[strings.ToLower(a)] = true
	}
	type kv struct {
		origin string
		n      int64
	}
	var cross []kv
	var total int64
	for o, n := range rp.Origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || own[strings.ToLower(u.Hostname())] {
			continue
		}
		cross = append(cross, kv{o, n})
		total += n
	}
	switch {
	case len(cross) == 0:
		skip(SettingCORS, "aucune requête venant d'une autre origine : le navigateur n'a pas besoin de CORS ici")
		return
	case len(cross) > maxProposeOrigin || rp.OriginsOverflow > 0:
		skip(SettingCORS, "plus de %d origines distinctes : à régler à la main", maxProposeOrigin)
		return
	}
	sort.Slice(cross, func(i, j int) bool {
		if cross[i].n != cross[j].n {
			return cross[i].n > cross[j].n
		}
		return cross[i].origin < cross[j].origin
	})
	origins := make([]string, len(cross))
	parts := make([]string, len(cross))
	for i, e := range cross {
		origins[i] = e.origin
		parts[i] = fmt.Sprintf("%s (%d)", e.origin, e.n)
	}
	var methods []string
	rank := map[string]int{"GET": 0, "HEAD": 1, "POST": 2, "PUT": 3, "PATCH": 4, "DELETE": 5}
	for m := range rp.Methods {
		if m != "OPTIONS" && m != "(autres)" {
			methods = append(methods, m)
		}
	}
	sort.Slice(methods, func(i, j int) bool {
		ri, iok := rank[methods[i]]
		rj, jok := rank[methods[j]]
		if iok != jok {
			return iok
		}
		if iok && ri != rj {
			return ri < rj
		}
		return methods[i] < methods[j]
	})
	value := map[string]any{"allowed_origins": origins}
	if len(methods) > 0 {
		value["allowed_methods"] = methods
	}
	add(Proposal{
		Setting: SettingCORS, Current: "aucun",
		Summary: fmt.Sprintf("Autoriser %d origine(s) à appeler ce proxy depuis un navigateur", len(origins)),
		Evidence: []string{
			fmt.Sprintf("%d requêtes viennent d'une autre origine que le proxy", total),
			"origines : " + strings.Join(parts, ", "),
			"méthodes vues : " + strings.Join(methods, ", "),
		},
		Cautions: []string{
			"un site qui n'a pas appelé ce proxy pendant l'apprentissage serait ignoré par le navigateur",
			"si le backend répond déjà lui-même aux en-têtes CORS, la passerelle les ajoutera en plus",
		},
	}, value)
}

// niceBytes arrondit à un palier courant (16 Ko, 32 Ko, 64 Ko, 128 Ko… puis 1, 2, 5, 10, 20, 50, 100 Mo).
func niceBytes(n int64) int64 {
	for _, step := range []int64{16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 5 << 20, 10 << 20, 20 << 20, 50 << 20, 100 << 20} {
		if n <= step {
			return step
		}
	}
	return 100 << 20
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d Mo", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f Mo", float64(n)/(1<<20))
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d Ko", n>>10)
	case n >= 1<<10:
		return fmt.Sprintf("%.1f Ko", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d o", n)
}

// Exclusion de règles du WAF (ADR 0016) : une règle qui se déclenche de façon répétée sur des clients ordinaires est probablement un
// faux positif. Le WAF est le dernier rempart d'une application, et une exclusion pour tout le proxy laisse sans défense toute la
// partie où la règle ne se trompait pas : la proposition borne donc l'exclusion **aux chemins où le profil l'a vue se déclencher**
// (waf.exclusions), jamais au proxy entier. Quand ces chemins ne se délimitent pas (racine, identifiant en premier segment, trop de
// chemins pour que le profil les retienne tous), elle conseille un seuil d'anomalie ou le mode detect plutôt qu'une exclusion large.
const (
	wafServedMin     = 10 // déclenchements servis par le backend, depuis des clients propres
	wafBlockedMin    = 10 // idem, refusés par le WAF
	wafClients       = 3
	wafClientsBlock  = 5
	wafRecurrence    = 3  // déclenchements par client propre au moins : un client ordinaire recommence, une attaque change d'IP
	wafTuneThreshold = 10 // seuil d'anomalie conseillé : deux règles critiques (5 points) au lieu d'une seule
)

type wafCandidate struct {
	id    int
	rule  *WAFRule
	tier  string   // served | blocked
	scope []string // préfixes de chemin où borner l'exclusion ; vide : impossible à borner
	whole bool     // les chemins retenus par le profil sont tous ceux de la règle (pas de débordement)
}

func proposeWAF(rp *RouteProfile, cur Current, add addFn, skip skipFn) {
	switch {
	case cur.WAFFromSnippet:
		skip(SettingWAF, "le WAF de ce proxy vient d'un snippet : ajoutez les règles à exclure à ce snippet, pas au proxy")
		return
	case len(cur.WAF) == 0:
		skip(SettingWAF, "aucun WAF activé sur ce proxy")
		return
	case len(rp.WAF) == 0:
		skip(SettingWAF, "aucune règle du WAF ne s'est déclenchée pendant l'apprentissage")
		return
	}
	var cfg map[string]any
	if json.Unmarshal(cur.WAF, &cfg) != nil || cfg["enabled"] != true {
		skip(SettingWAF, "aucun WAF activé sur ce proxy")
		return
	}
	excluded := map[int]bool{}
	if list, ok := cfg["exclude_ids"].([]any); ok {
		for _, v := range list {
			if f, ok := v.(float64); ok {
				excluded[int(f)] = true
			}
		}
	}
	custom := map[int]bool{}
	for _, id := range cur.CustomRuleIDs {
		custom[id] = true
	}
	covered := coveredRules(cfg)

	var cands []wafCandidate
	untested := 0
	for id, w := range rp.WAF {
		if excluded[id] || custom[id] {
			continue
		}
		clients := w.Clients.Estimate()
		tier := ""
		switch {
		case w.Served >= wafServedMin && clients >= wafClients && len(w.Days) >= MinSupportDay && w.Served*10 >= w.Clean*7 && w.Served >= int64(wafRecurrence*clients):
			tier = "served"
		case w.Blocked >= wafBlockedMin && clients >= wafClientsBlock && len(w.Days) >= 3 && w.Blocked*10 >= w.Clean*7 && w.Blocked >= int64(wafRecurrence*clients):
			tier = "blocked"
		default:
			untested++
			continue
		}
		scope, whole := scopeOf(w.Paths)
		if len(scope) > 0 && allCovered(covered[id], scope) {
			continue // déjà exclue sous ces chemins
		}
		cands = append(cands, wafCandidate{id: id, rule: w, tier: tier, scope: scope, whole: whole})
	}
	if len(cands) == 0 {
		skip(SettingWAF, "%d règle(s) se sont déclenchées mais aucune ne revient assez, de clients ordinaires distincts sur plusieurs jours, ni n'est restée sans exclusion, pour passer pour un faux positif à exclure", untested)
		return
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].id < cands[j].id })

	var scoped, loose []wafCandidate
	for _, c := range cands {
		if len(c.scope) > 0 {
			scoped = append(scoped, c)
		} else {
			loose = append(loose, c)
		}
	}
	if len(scoped) > 0 {
		proposeWAFExclusions(cloneCfg(cfg), scoped, add)
	}
	if len(loose) > 0 {
		proposeWAFTuning(cloneCfg(cfg), loose, add, skip)
	}
}

// scopeOf rend les préfixes de chemin où borner l'exclusion d'une règle, d'après les chemins où le profil l'a vue se déclencher.
// whole est faux si le profil n'a pas retenu tous ses chemins (débordement) ; la liste est vide si un de ces chemins ne se borne pas.
func scopeOf(paths map[string]int64) (prefixes []string, whole bool) {
	whole = true
	set := map[string]bool{}
	for key := range paths {
		if key == "(autres)" {
			whole = false
			continue
		}
		pre, ok := scopePrefix(key)
		if !ok {
			return nil, false
		}
		set[pre] = true
	}
	for p := range set {
		sub := false
		for q := range set {
			if q != p && underPrefix(p, q) {
				sub = true
			}
		}
		if !sub {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	return prefixes, whole
}

// scopePrefix rend le préfixe de chemin d'un gabarit normalisé (« GET /api/users/{int}/x » → « /api/users ») : ce qui précède le premier
// identifiant. Faux si rien ne précède (racine, identifiant en premier segment) : l'exclusion vaudrait pour tout le proxy.
func scopePrefix(key string) (string, bool) {
	path := key
	if i := strings.IndexByte(key, ' '); i >= 0 {
		path = key[i+1:]
	}
	var keep []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg == "" {
			continue
		}
		if isClassKey(seg) {
			break
		}
		keep = append(keep, seg)
	}
	if len(keep) == 0 {
		return "", false
	}
	return "/" + strings.Join(keep, "/"), true
}

// underPrefix : le préfixe q est sous le préfixe p, sur une frontière de segment.
func underPrefix(q, p string) bool {
	return q == p || strings.HasPrefix(q, strings.TrimSuffix(p, "/")+"/")
}

// coveredRules rend, par règle, les chemins sous lesquels une exclusion par chemin déjà réglée la retire.
func coveredRules(cfg map[string]any) map[int][]string {
	out := map[int][]string{}
	list, _ := cfg["exclusions"].([]any)
	for _, e := range list {
		ex, _ := e.(map[string]any)
		paths := strSliceOf(ex["paths"])
		ids, _ := ex["rule_ids"].([]any)
		for _, v := range ids {
			if f, ok := v.(float64); ok {
				out[int(f)] = append(out[int(f)], paths...)
			}
		}
	}
	return out
}

func strSliceOf(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func allCovered(have, want []string) bool {
	for _, w := range want {
		ok := false
		for _, h := range have {
			ok = ok || underPrefix(w, h)
		}
		if !ok {
			return false
		}
	}
	return true
}

func wafEvidence(c wafCandidate) string {
	w, clients := c.rule, c.rule.Clients.Estimate()
	what, n := "servies par le backend", w.Served
	if c.tier == "blocked" {
		what, n = "refusées par le WAF", w.Blocked
	}
	top := ""
	if p := counts(w.Paths); len(p) > 0 {
		top = ", surtout sur " + p[0].Name
	}
	return fmt.Sprintf("règle %d (%s) « %s » : %d requête(s) %s de %d client(s) ordinaire(s) sur %d jour(s)%s", c.id, w.Category, w.Message, n, what, clients, len(w.Days), top)
}

func sensitiveCategory(c string) bool { return c == "rce" || c == "lfi" || c == "rfi" || c == "sqli" }

// proposeWAFExclusions propose waf.exclusions : chaque règle n'est retirée que sous les chemins où elle se déclenche.
func proposeWAFExclusions(cfg map[string]any, cands []wafCandidate, add addFn) {
	type group struct {
		paths []string
		ids   []int
		notes []string
	}
	groups := map[string]*group{}
	var order []string
	var ev, cau []string
	incomplete, refused := false, false
	for _, c := range cands {
		key := strings.Join(c.scope, "\x00")
		g := groups[key]
		if g == nil {
			g = &group{paths: c.scope}
			groups[key] = g
			order = append(order, key)
		}
		g.ids = append(g.ids, c.id)
		g.notes = append(g.notes, fmt.Sprintf("%d (%s)", c.id, c.rule.Category))
		ev = append(ev, wafEvidence(c)+" ; exclusion limitée à "+strings.Join(c.scope, ", "))
		incomplete = incomplete || !c.whole
		refused = refused || c.tier == "blocked"
		if sensitiveCategory(c.rule.Category) {
			cau = append(cau, fmt.Sprintf("la règle %d (%s) arrête de vraies attaques : sous ces chemins elle ne protège plus ; limitez l'accès à ces chemins (authentification, filtre d'IP) ou corrigez le champ qui la déclenche", c.id, c.rule.Category))
		}
	}
	list, _ := cfg["exclusions"].([]any)
	for _, key := range order {
		g := groups[key]
		sort.Ints(g.ids)
		list = append(list, map[string]any{"paths": g.paths, "rule_ids": g.ids, "note": "appris : règles " + strings.Join(g.notes, ", ") + " déclenchées par des clients ordinaires"})
	}
	cfg["exclusions"] = list
	cautions := append([]string{
		"l'exclusion ne vaut que sous les chemins indiqués : partout ailleurs la règle reste active",
		"un faux positif et une attaque lente ont la même apparence : vérifiez ce que la règle reconnaît sous ces chemins avant de l'exclure",
		"les chemins sont des préfixes : ils couvrent aussi ce qui se trouve en dessous, au-delà des gabarits observés",
	}, cau...)
	if incomplete {
		cautions = append(cautions, "le profil n'a pas retenu tous les chemins où la règle se déclenche : elle restera active sur les autres, qui peuvent encore donner des faux positifs")
	}
	if refused {
		cautions = append(cautions, "certaines requêtes sont refusées par le WAF : on ne sait pas si l'application les aurait servies")
	}
	add(Proposal{
		Setting: SettingWAF, Current: fmt.Sprintf("%d exclusion(s) par chemin", len(coveredRulesList(cfg))-len(order)),
		Summary:  fmt.Sprintf("Exclure %d règle(s) du WAF, sous les chemins où elles se déclenchent seulement", len(cands)),
		Evidence: ev, Cautions: cautions,
	}, cfg)
}

func coveredRulesList(cfg map[string]any) []any {
	l, _ := cfg["exclusions"].([]any)
	return l
}

// proposeWAFTuning conseille, pour des règles dont les chemins ne se délimitent pas, de ne pas exclure mais d'adoucir le WAF : un seuil
// d'anomalie plus haut (une règle isolée n'arrête plus la requête), ou le mode detect le temps de comprendre.
func proposeWAFTuning(cfg map[string]any, cands []wafCandidate, add addFn, skip skipFn) {
	thr, _ := cfg["anomaly_threshold"].(float64)
	mode, _ := cfg["mode"].(string)
	var ev []string
	for _, c := range cands {
		why := "chemins impossibles à délimiter (racine ou identifiant en premier segment)"
		if len(c.scope) == 0 && len(c.rule.Paths) == 0 {
			why = "aucun chemin retenu"
		}
		ev = append(ev, wafEvidence(c)+" ; "+why)
	}
	if int(thr) >= wafTuneThreshold || mode == "detect" {
		skip(SettingWAF, "%d règle(s) se déclenchent sur des clients ordinaires sans chemin à borner, mais le WAF est déjà en mode detect ou à un seuil d'anomalie de %d ou plus : %s", len(cands), wafTuneThreshold, strings.Join(ev, " ; "))
		return
	}
	cfg["anomaly_threshold"] = wafTuneThreshold
	add(Proposal{
		Setting: SettingWAF, Current: fmt.Sprintf("seuil d'anomalie %d (%s)", int(thr), map[bool]string{true: "la première règle arrête", false: "score cumulé"}[thr == 0]),
		Summary:  fmt.Sprintf("Adoucir le WAF au lieu d'exclure : seuil d'anomalie à %d", wafTuneThreshold),
		Evidence: ev,
		Cautions: []string{
			"ces règles se déclenchent sur des clients ordinaires mais leurs chemins ne se bornent pas : une exclusion vaudrait pour tout le proxy, ce que la proposition évite",
			fmt.Sprintf("avec un seuil de %d, une requête n'est arrêtée que si ses règles totalisent au moins ce score (une règle critique pèse 5) : une attaque qui ne déclenche qu'une règle passe", wafTuneThreshold),
			"alternative plus prudente : passer d'abord le WAF en mode detect (mode: detect) le temps de voir ce qui se déclenche, sans rien refuser",
			"à valider sur du trafic réel avant de l'appliquer en block",
		},
	}, cfg)
}

// cloneCfg copie une configuration JSON : chaque proposition part de l'état actuel du proxy, pas de celui qu'une autre a modifié.
func cloneCfg(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
