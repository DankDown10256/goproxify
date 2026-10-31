// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"hash/maphash"
	"math/bits"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Bornes d'un profil : la mémoire d'une route ne dépend que d'elles, jamais du trafic.
const (
	maxNodes           = 2000 // gabarits de chemin (et segments intermédiaires) par route
	maxSegments        = 12
	maxLiteralChildren = 64 // au-delà, les segments littéraux d'un même parent deviennent {var}
	maxHeaders         = 64
	maxParams          = 32
	maxStatuses        = 16
	maxMedia           = 8
	maxMethods         = 16
	maxASN             = 200
	maxDays            = 64
	maxParamValues     = 9 // une énumération a au plus 8 valeurs ; le 9e dit « plus que ça »
	maxNameLen         = 64
	maxRanges          = 256 // réseaux /24 (IPv4) et /48 (IPv6) distincts
	maxOrigins         = 50
	maxOriginLen       = 200
	maxWAFRules        = 64  // règles du WAF distinctes par proxy
	maxWAFPaths        = 10  // chemins retenus par règle
	maxViolations      = 100 // violations de la politique distinctes (raison, méthode, chemin normalisé)
)

// Classes de segments de chemin et de valeurs de paramètres.
const (
	clsInt   = "{int}"
	clsUUID  = "{uuid}"
	clsHex   = "{hex}"
	clsDate  = "{date}"
	clsEmail = "{email}"
	clsToken = "{token}"
	clsBad   = "{bad}"
	clsVar   = "{var}"
	clsMore  = "{…}" // le chemin continue au-delà de maxSegments
)

// Bits de Param.Kinds.
const (
	KindInt uint8 = 1 << iota
	KindUUID
	KindBool
	KindText
	KindEmpty
)

var valueSeed = maphash.MakeSeed()

// Node est un segment de chemin. Les enfants sont des segments littéraux ou des classes ({int}, {uuid}…).
type Node struct {
	Children map[string]*Node `json:"c,omitempty"`
	// Lits : nombre d'enfants littéraux (les classes ne comptent pas).
	Lits  int       `json:"l,omitempty"`
	Stats *Template `json:"s,omitempty"`
}

// Param décrit un paramètre de requête d'un gabarit : jamais ses valeurs.
type Param struct {
	Count  int64 `json:"n"`
	Kinds  uint8 `json:"k"`
	MaxLen int   `json:"m"`
	// Distinct : valeurs distinctes vues, plafonné à maxParamValues. Les empreintes qui servent à le compter ne sont pas
	// conservées : après un redémarrage le compte repart de sa valeur sauvegardée et peut se surestimer.
	Distinct int `json:"d"`
	seen     map[uint64]struct{}
}

// Template regroupe les requêtes d'un même gabarit de chemin (/api/users/{int}).
type Template struct {
	Requests  int64            `json:"n"`
	First     int64            `json:"f"`
	Last      int64            `json:"t"`
	Methods   map[string]int64 `json:"me,omitempty"`
	Statuses  map[int]int64    `json:"st,omitempty"`
	ReqMedia  map[string]int64 `json:"rq,omitempty"`
	RespMedia map[string]int64 `json:"rs,omitempty"`
	// Body : histogramme du corps des requêtes (index i = valeurs de 2^(i-1) à 2^i-1 octets).
	Body    []int64           `json:"b,omitempty"`
	BodyMax int64             `json:"bm,omitempty"`
	Params  map[string]*Param `json:"p,omitempty"`
	Clients *Sketch           `json:"c"`
	Days    []int32           `json:"d,omitempty"`
}

// RouteProfile est ce que la passerelle a appris du trafic légitime d'un proxy.
type RouteProfile struct {
	Host string `json:"host"`
	// Type : api | site, ce que la configuration du proxy déclare ; vide = non précisé (traité comme une API).
	Type  string `json:"type,omitempty"`
	Since int64  `json:"since"`
	Last  int64  `json:"last"`
	// Requests : toutes les requêtes vues ; Learned : celles qui ont alimenté le profil ; Excluded : celles d'une IP
	// suspecte ; Failed : les autres, par statut (400, 404, 405, 5xx…).
	Requests  int64            `json:"requests"`
	Learned   int64            `json:"learned"`
	Excluded  int64            `json:"excluded"`
	Overflow  int64            `json:"overflow,omitempty"`
	Failed    map[int]int64    `json:"failed,omitempty"`
	Methods   map[string]int64 `json:"methods,omitempty"`
	Headers   map[string]int64 `json:"headers,omitempty"`
	Protocols map[string]int64 `json:"protocols,omitempty"`
	TLS       map[string]int64 `json:"tls,omitempty"`
	Countries map[string]int64 `json:"countries,omitempty"`
	ASNs      map[uint32]int64 `json:"asns,omitempty"`
	// ReqMedia et RespMedia : types de contenu des requêtes et des réponses du proxy entier ; BodyHist et BodyMax : taille des corps de
	// requête du proxy entier. Ils ne passent pas par l'arbre des chemins : un proxy dont les chemins débordent garde ses mesures.
	ReqMedia  map[string]int64 `json:"req_media,omitempty"`
	RespMedia map[string]int64 `json:"resp_media,omitempty"`
	BodyHist  []int64          `json:"body_hist,omitempty"`
	BodyMax   int64            `json:"body_max,omitempty"`
	// Ranges : requêtes apprises par réseau /24 (IPv4) ou /48 (IPv6), jamais par adresse (rangeKey). Au-delà de maxRanges
	// réseaux distincts, RangesOverflow compte le reste : une liste d'IP autorisées n'a alors plus de sens.
	Ranges         map[uint64]int64 `json:"ranges,omitempty"`
	RangesOverflow int64            `json:"ranges_overflow,omitempty"`
	// Origins : valeurs de l'en-tête Origin des requêtes apprises (des noms d'hôtes, pas des données personnelles).
	Origins         map[string]int64 `json:"origins,omitempty"`
	OriginsOverflow int64            `json:"origins_overflow,omitempty"`
	// UnknownBody : requêtes POST, PUT ou PATCH dont la taille du corps n'est pas annoncée (transfert par morceaux) :
	// leur taille échappe à la mesure.
	UnknownBody int64 `json:"unknown_body,omitempty"`
	// Violations : requêtes que le contrôle openapi du proxy a jugées hors de la spécification, par (raison, méthode, chemin
	// normalisé). ViolationTotals les compte par raison ; au-delà de maxViolations entrées distinctes, le reste va dans
	// ViolationsOverflow.
	Violations      map[string]*Violation `json:"violations,omitempty"`
	ViolationTotals map[string]int64      `json:"violation_totals,omitempty"`
	// BlockedTotals : parmi elles, celles que le contrôle a refusées (ADR 0016, étape 4), par raison.
	BlockedTotals      map[string]int64 `json:"blocked_totals,omitempty"`
	ViolationsOverflow int64            `json:"violations_overflow,omitempty"`
	// WAF : les règles du WAF déclenchées par les requêtes, et par qui (ADR 0016 : proposition d'exclusion de règles). WAFOverflow
	// compte les déclenchements de règles au-delà de maxWAFRules règles distinctes.
	WAF         map[int]*WAFRule `json:"waf,omitempty"`
	WAFOverflow int64            `json:"waf_overflow,omitempty"`
	Clients     *Sketch          `json:"clients"`
	Nodes       int              `json:"nodes"`
	Root        *Node            `json:"root"`
}

func newRouteProfile(host string) *RouteProfile {
	return &RouteProfile{Host: host, Root: &Node{}, Clients: newSketch(routePrecision), Nodes: 1}
}

// normalize rend utilisable un profil relu : maps et sketchs présents, nombre de nœuds recompté.
func (rp *RouteProfile) normalize() {
	if rp.Root == nil {
		rp.Root = &Node{}
	}
	if rp.Clients == nil || len(rp.Clients.Regs) != 1<<routePrecision {
		rp.Clients = newSketch(routePrecision)
	}
	rp.Nodes = countNodes(rp.Root)
}

func countNodes(n *Node) int {
	c := 1
	for _, ch := range n.Children {
		c += countNodes(ch)
	}
	return c
}

func (rp *RouteProfile) clone() *RouteProfile {
	b, err := json.Marshal(rp)
	if err != nil {
		return newRouteProfile(rp.Host)
	}
	var out RouteProfile
	if json.Unmarshal(b, &out) != nil {
		return newRouteProfile(rp.Host)
	}
	out.normalize()
	return &out
}

// input est ce que le profil retient d'une requête terminée.
type input struct {
	Method, Path, RawQuery string
	Status                 int
	ReqMedia, RespMedia    string
	BodyLen                int64 // -1 : inconnue
	Header                 http.Header
	IP, Proto, TLS         string
	Country                string
	ASN                    uint32
	Origin                 string
	Type                   string
	Violation              string // raison de la violation de la politique openapi, vide si la requête est conforme
	WAFHits                []WAFHit
	WAFBlocked             bool // le WAF a refusé la requête
	CleanApartFromWAF      bool // l'IP est propre si l'on met de côté les règles du WAF qu'elle déclenche
	Blocked                bool // le contrôle openapi a refusé la requête
	Clean                  bool
}

// learnable : le statut montre que la route existe (réussie, redirigée, ou derrière une authentification).
func learnable(status int) bool {
	return (status >= 200 && status < 400) || status == http.StatusUnauthorized
}

func (rp *RouteProfile) observe(in *input, now time.Time) {
	ts := now.Unix()
	rp.Type = in.Type
	if rp.Since == 0 {
		rp.Since = ts
	}
	rp.Last = ts
	rp.Requests++
	if in.Violation != "" {
		rp.recordViolation(in, now)
	}
	if len(in.WAFHits) > 0 {
		rp.recordWAF(in, now)
	}
	if !in.Clean {
		rp.Excluded++
		return
	}
	status := in.Status
	if status == 0 {
		status = http.StatusOK
	}
	if !learnable(status) {
		if rp.Failed == nil {
			rp.Failed = map[int]int64{}
		}
		if _, ok := rp.Failed[status]; !ok && len(rp.Failed) >= maxStatuses {
			status = 0
		}
		rp.Failed[status]++
		return
	}
	rp.Learned++
	bump(&rp.Methods, in.Method, maxMethods)
	if in.ReqMedia != "" {
		bump(&rp.ReqMedia, in.ReqMedia, maxMedia+4)
	}
	if in.RespMedia != "" {
		bump(&rp.RespMedia, in.RespMedia, maxMedia+4)
	}
	if in.BodyLen > 0 {
		idx := bits.Len64(uint64(in.BodyLen))
		if idx > 40 {
			idx = 40
		}
		if rp.BodyHist == nil {
			rp.BodyHist = make([]int64, 41)
		}
		rp.BodyHist[idx]++
		if in.BodyLen > rp.BodyMax {
			rp.BodyMax = in.BodyLen
		}
	}
	for name := range in.Header {
		if len(name) <= maxNameLen {
			bump(&rp.Headers, name, maxHeaders)
		}
	}
	bump(&rp.Protocols, in.Proto, 8)
	bump(&rp.TLS, in.TLS, 8)
	if in.Country != "" {
		bump(&rp.Countries, in.Country, 300)
	}
	if in.ASN != 0 {
		if rp.ASNs == nil {
			rp.ASNs = map[uint32]int64{}
		}
		if _, ok := rp.ASNs[in.ASN]; ok || len(rp.ASNs) < maxASN {
			rp.ASNs[in.ASN]++
		}
	}
	h := hashIP(in.IP)
	rp.Clients.add(h)
	if k := rangeKey(in.IP); k != 0 {
		if _, ok := rp.Ranges[k]; ok || len(rp.Ranges) < maxRanges {
			if rp.Ranges == nil {
				rp.Ranges = map[uint64]int64{}
			}
			rp.Ranges[k]++
		} else {
			rp.RangesOverflow++
		}
	}
	if in.Origin != "" && len(in.Origin) <= maxOriginLen {
		if _, ok := rp.Origins[in.Origin]; ok || len(rp.Origins) < maxOrigins {
			if rp.Origins == nil {
				rp.Origins = map[string]int64{}
			}
			rp.Origins[in.Origin]++
		} else {
			rp.OriginsOverflow++
		}
	}
	if in.BodyLen < 0 && (in.Method == http.MethodPost || in.Method == http.MethodPut || in.Method == http.MethodPatch) {
		rp.UnknownBody++
	}

	n := rp.locate(in.Path)
	if n == nil {
		rp.Overflow++
		return
	}
	if n.Stats == nil {
		n.Stats = &Template{Clients: newSketch(templatePrecision)}
	}
	n.Stats.record(in, status, ts, h)
}

// bump compte une valeur dans une map bornée ; au-delà de limit valeurs distinctes, le reste va dans "(autres)".
func bump(m *map[string]int64, k string, limit int) {
	if *m == nil {
		*m = map[string]int64{}
	}
	if _, ok := (*m)[k]; !ok && len(*m) >= limit {
		k = "(autres)"
	}
	(*m)[k]++
}

func (t *Template) record(in *input, status int, ts int64, ipHash uint64) {
	if t.Requests == 0 {
		t.First = ts
	}
	t.Last = ts
	t.Requests++
	bump(&t.Methods, in.Method, maxMethods)
	if t.Statuses == nil {
		t.Statuses = map[int]int64{}
	}
	if _, ok := t.Statuses[status]; ok || len(t.Statuses) < maxStatuses {
		t.Statuses[status]++
	}
	if in.ReqMedia != "" {
		bump(&t.ReqMedia, in.ReqMedia, maxMedia)
	}
	if in.RespMedia != "" {
		bump(&t.RespMedia, in.RespMedia, maxMedia)
	}
	if in.BodyLen > 0 {
		idx := bits.Len64(uint64(in.BodyLen))
		if idx > 40 {
			idx = 40
		}
		if t.Body == nil {
			t.Body = make([]int64, 41)
		}
		t.Body[idx]++
		if in.BodyLen > t.BodyMax {
			t.BodyMax = in.BodyLen
		}
	}
	t.Clients.add(ipHash)
	t.addDay(int32(ts / 86400))
	if in.RawQuery != "" {
		t.recordQuery(in.RawQuery)
	}
}

func (t *Template) addDay(d int32) { t.Days = appendDay(t.Days, d) }

// appendDay ajoute un jour (numéro depuis 1970) à une liste bornée de jours distincts, en remplaçant le plus ancien au-delà.
func appendDay(days []int32, d int32) []int32 {
	for _, x := range days {
		if x == d {
			return days
		}
	}
	if len(days) >= maxDays {
		oldest := 0
		for i, x := range days {
			if x < days[oldest] {
				oldest = i
			}
		}
		days[oldest] = d
		return days
	}
	return append(days, d)
}

func (t *Template) recordQuery(q string) {
	for q != "" {
		var kv string
		if i := strings.IndexByte(q, '&'); i >= 0 {
			kv, q = q[:i], q[i+1:]
		} else {
			kv, q = q, ""
		}
		if kv == "" {
			continue
		}
		name, val := kv, ""
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name, val = kv[:i], kv[i+1:]
		}
		if name == "" || len(name) > maxNameLen {
			continue
		}
		p := t.Params[name]
		if p == nil {
			if len(t.Params) >= maxParams {
				continue
			}
			if t.Params == nil {
				t.Params = map[string]*Param{}
			}
			p = &Param{}
			t.Params[name] = p
		}
		p.Count++
		p.Kinds |= valueKind(val)
		if len(val) > p.MaxLen {
			p.MaxLen = len(val)
		}
		if p.Distinct < maxParamValues {
			if p.seen == nil {
				p.seen = map[uint64]struct{}{}
			}
			hv := maphash.String(valueSeed, val)
			if _, ok := p.seen[hv]; !ok {
				p.seen[hv] = struct{}{}
				if len(p.seen) > p.Distinct {
					p.Distinct = len(p.seen)
				}
			}
		}
	}
}

func valueKind(v string) uint8 {
	switch {
	case v == "":
		return KindEmpty
	case v == "true" || v == "false":
		return KindBool
	case len(v) <= 18 && isDigits(v):
		return KindInt
	case isUUID(v):
		return KindUUID
	}
	return KindText
}

// locate descend dans l'arbre des gabarits et rend le nœud du chemin, créé au besoin. nil : la route a trop de gabarits.
func (rp *RouteProfile) locate(path string) *Node {
	n := rp.Root
	depth := 0
	for i := 0; i < len(path); {
		if path[i] == '/' {
			i++
			continue
		}
		seg := path[i:]
		if j := strings.IndexByte(seg, '/'); j >= 0 {
			seg = seg[:j]
		}
		i += len(seg)
		if depth == maxSegments {
			return rp.sub(n, clsMore, false)
		}
		depth++
		if n = rp.child(n, seg); n == nil {
			return nil
		}
	}
	return n
}

func (rp *RouteProfile) child(n *Node, seg string) *Node {
	if cls := classify(seg); cls != "" {
		return rp.sub(n, cls, false)
	}
	if c := n.Children[seg]; c != nil {
		return c
	}
	if v := n.Children[clsVar]; v != nil {
		return v
	}
	if n.Lits >= maxLiteralChildren {
		rp.collapse(n)
		return n.Children[clsVar]
	}
	return rp.sub(n, seg, true)
}

func (rp *RouteProfile) sub(n *Node, key string, literal bool) *Node {
	if c := n.Children[key]; c != nil {
		return c
	}
	if rp.Nodes >= maxNodes {
		return nil
	}
	if n.Children == nil {
		n.Children = map[string]*Node{}
	}
	c := &Node{}
	n.Children[key] = c
	rp.Nodes++
	if literal {
		n.Lits++
	}
	return c
}

func isClassKey(k string) bool { return len(k) > 2 && k[0] == '{' && k[len(k)-1] == '}' }

// collapse regroupe les enfants littéraux de n sous {var} : trop de valeurs distinctes à ce niveau, c'est un identifiant
// ou un nom propre à une donnée, pas une route.
func (rp *RouteProfile) collapse(n *Node) {
	v := n.Children[clsVar]
	if v == nil {
		v = &Node{}
		n.Children[clsVar] = v
	}
	var lits []string
	for k := range n.Children {
		if k != clsVar && !isClassKey(k) {
			lits = append(lits, k)
		}
	}
	for _, k := range lits {
		c := n.Children[k]
		delete(n.Children, k)
		rp.mergeNode(v, c)
	}
	n.Lits = 0
	rp.Nodes = countNodes(rp.Root)
}

// mergeNode verse src dans dst : statistiques, puis enfants un à un, avec les mêmes règles que pour une requête.
func (rp *RouteProfile) mergeNode(dst, src *Node) {
	if src.Stats != nil {
		if dst.Stats == nil {
			dst.Stats = &Template{Clients: newSketch(templatePrecision)}
		}
		dst.Stats.merge(src.Stats)
	}
	for k, c := range src.Children {
		var d *Node
		if isClassKey(k) {
			d = rp.sub(dst, k, false)
		} else {
			d = rp.child(dst, k)
		}
		if d == nil {
			rp.Overflow++
			continue
		}
		rp.mergeNode(d, c)
	}
}

func (t *Template) merge(o *Template) {
	if o.Requests == 0 {
		return
	}
	if t.Requests == 0 || o.First < t.First {
		t.First = o.First
	}
	if o.Last > t.Last {
		t.Last = o.Last
	}
	t.Requests += o.Requests
	addMap(&t.Methods, o.Methods)
	if len(o.Statuses) > 0 && t.Statuses == nil {
		t.Statuses = map[int]int64{}
	}
	for k, v := range o.Statuses {
		if _, ok := t.Statuses[k]; ok || len(t.Statuses) < maxStatuses {
			t.Statuses[k] += v
		}
	}
	addMap(&t.ReqMedia, o.ReqMedia)
	addMap(&t.RespMedia, o.RespMedia)
	if len(o.Body) > 0 {
		if t.Body == nil {
			t.Body = make([]int64, 41)
		}
		for i, v := range o.Body {
			if i < len(t.Body) {
				t.Body[i] += v
			}
		}
	}
	if o.BodyMax > t.BodyMax {
		t.BodyMax = o.BodyMax
	}
	for name, op := range o.Params {
		p := t.Params[name]
		if p == nil {
			if len(t.Params) >= maxParams {
				continue
			}
			if t.Params == nil {
				t.Params = map[string]*Param{}
			}
			p = &Param{}
			t.Params[name] = p
		}
		p.Count += op.Count
		p.Kinds |= op.Kinds
		if op.MaxLen > p.MaxLen {
			p.MaxLen = op.MaxLen
		}
		if op.Distinct > p.Distinct {
			p.Distinct = op.Distinct
		}
	}
	t.Clients.merge(o.Clients)
	for _, d := range o.Days {
		t.addDay(d)
	}
}

func addMap(dst *map[string]int64, src map[string]int64) {
	for k, v := range src {
		if *dst == nil {
			*dst = map[string]int64{}
		}
		if _, ok := (*dst)[k]; !ok && len(*dst) >= 300 {
			k = "(autres)"
		}
		(*dst)[k] += v
	}
}

// mergeFrom verse dans rp le profil o, vu par un autre membre du groupe. rp est une copie jetable : la fusion ne sert qu'à
// l'affichage, ce qui la rend idempotente (le profil d'un pair est remplacé à chaque échange, jamais additionné deux fois).
func (rp *RouteProfile) mergeFrom(o *RouteProfile) {
	if o == nil {
		return
	}
	if rp.Host == "" {
		rp.Host = o.Host
	}
	if o.Since != 0 && (rp.Since == 0 || o.Since < rp.Since) {
		rp.Since = o.Since
	}
	if o.Last > rp.Last {
		rp.Last = o.Last
	}
	if rp.Type == "" {
		rp.Type = o.Type
	}
	rp.Requests += o.Requests
	rp.Learned += o.Learned
	addMap(&rp.ReqMedia, o.ReqMedia)
	addMap(&rp.RespMedia, o.RespMedia)
	if len(o.BodyHist) > 0 {
		if rp.BodyHist == nil {
			rp.BodyHist = make([]int64, 41)
		}
		for i, v := range o.BodyHist {
			if i < len(rp.BodyHist) {
				rp.BodyHist[i] += v
			}
		}
	}
	if o.BodyMax > rp.BodyMax {
		rp.BodyMax = o.BodyMax
	}
	rp.Excluded += o.Excluded
	rp.Overflow += o.Overflow
	for k, v := range o.Failed {
		if rp.Failed == nil {
			rp.Failed = map[int]int64{}
		}
		if _, ok := rp.Failed[k]; ok || len(rp.Failed) < maxStatuses {
			rp.Failed[k] += v
		}
	}
	addMap(&rp.Methods, o.Methods)
	addMap(&rp.Headers, o.Headers)
	addMap(&rp.Protocols, o.Protocols)
	addMap(&rp.TLS, o.TLS)
	addMap(&rp.Countries, o.Countries)
	for k, v := range o.ASNs {
		if rp.ASNs == nil {
			rp.ASNs = map[uint32]int64{}
		}
		if _, ok := rp.ASNs[k]; ok || len(rp.ASNs) < maxASN {
			rp.ASNs[k] += v
		}
	}
	rp.Clients.merge(o.Clients)
	rp.RangesOverflow += o.RangesOverflow
	for k, v := range o.Ranges {
		if rp.Ranges == nil {
			rp.Ranges = map[uint64]int64{}
		}
		if _, ok := rp.Ranges[k]; ok || len(rp.Ranges) < maxRanges {
			rp.Ranges[k] += v
		} else {
			rp.RangesOverflow += v
		}
	}
	rp.OriginsOverflow += o.OriginsOverflow
	for k, v := range o.Origins {
		if rp.Origins == nil {
			rp.Origins = map[string]int64{}
		}
		if _, ok := rp.Origins[k]; ok || len(rp.Origins) < maxOrigins {
			rp.Origins[k] += v
		} else {
			rp.OriginsOverflow += v
		}
	}
	rp.UnknownBody += o.UnknownBody
	rp.ViolationsOverflow += o.ViolationsOverflow
	rp.WAFOverflow += o.WAFOverflow
	for id, ow := range o.WAF {
		if rp.WAF == nil {
			rp.WAF = map[int]*WAFRule{}
		}
		w := rp.WAF[id]
		if w == nil {
			if len(rp.WAF) >= maxWAFRules {
				rp.WAFOverflow += ow.Hits
				continue
			}
			w = &WAFRule{Category: ow.Category, Message: ow.Message, Clients: newSketch(templatePrecision)}
			rp.WAF[id] = w
		}
		w.merge(ow)
	}
	for k, n := range o.ViolationTotals {
		if rp.ViolationTotals == nil {
			rp.ViolationTotals = map[string]int64{}
		}
		rp.ViolationTotals[k] += n
	}
	for k, n := range o.BlockedTotals {
		if rp.BlockedTotals == nil {
			rp.BlockedTotals = map[string]int64{}
		}
		rp.BlockedTotals[k] += n
	}
	for k, ov := range o.Violations {
		if rp.Violations == nil {
			rp.Violations = map[string]*Violation{}
		}
		v := rp.Violations[k]
		if v == nil {
			if len(rp.Violations) >= maxViolations {
				rp.ViolationsOverflow += ov.Count
				continue
			}
			v = &Violation{Clients: newSketch(templatePrecision), First: ov.First}
			rp.Violations[k] = v
		}
		v.merge(ov)
	}
	if o.Root != nil {
		rp.mergeNode(rp.Root, o.Root)
	}
}

// classify rend la classe d'un segment (ou d'une valeur) qui est un identifiant, "" si c'est un nom de route.
func classify(seg string) string {
	n := len(seg)
	if n == 0 {
		return ""
	}
	if n > maxNameLen {
		return clsToken
	}
	for i := 0; i < n; i++ {
		if seg[i] < 0x20 || seg[i] == 0x7f {
			return clsBad
		}
	}
	switch {
	case n <= 18 && isDigits(seg):
		return clsInt
	case isUUID(seg):
		return clsUUID
	case isDate(seg):
		return clsDate
	case n >= 16 && isHex(seg):
		return clsHex
	}
	if at := strings.IndexByte(seg, '@'); at > 0 && strings.IndexByte(seg[at:], '.') > 0 {
		return clsEmail
	}
	if n >= 24 {
		return clsToken
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return s != ""
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
		} else if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isDate(s string) bool {
	return len(s) == 10 && s[4] == '-' && s[7] == '-' && isDigits(s[:4]) && isDigits(s[5:7]) && isDigits(s[8:])
}

// rangeKey réduit une IP à son réseau (/24 en IPv4, /48 en IPv6) : 1<<56 | octets pour IPv4, 2<<56 | octets pour IPv6. 0 : IP
// illisible. L'adresse complète n'est jamais gardée.
func rangeKey(ip string) uint64 {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return 1<<56 | uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
	}
	b := a.As16()
	return 2<<56 | uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

// rangeCIDR écrit un réseau retenu par rangeKey.
func rangeCIDR(k uint64) string {
	if k>>56 == 1 {
		return fmt.Sprintf("%d.%d.%d.0/24", byte(k>>16), byte(k>>8), byte(k))
	}
	return fmt.Sprintf("%x:%x:%x::/48", uint16(k>>32), uint16(k>>16), uint16(k))
}

// Violation est une requête hors de la politique, regroupée par raison, méthode et chemin normalisé.
type Violation struct {
	Count int64 `json:"n"`
	// Legit : celles qui ont pourtant réussi depuis une IP propre. Un chemin souvent dans ce cas est probablement légitime et
	// manque à la politique.
	Legit int64 `json:"l"`
	// Blocked : celles que le contrôle a refusées.
	Blocked int64   `json:"b,omitempty"`
	First   int64   `json:"f"`
	Last    int64   `json:"t"`
	Clients *Sketch `json:"c"`
	// Clean, CleanClients et Days : les requêtes venues d'IP propres (quelle qu'ait été leur issue), les clients distincts qui les
	// ont faites et les jours où elles sont venues. Une violation refusée n'a jamais de réussite : c'est la seule preuve qu'elle
	// vient de clients ordinaires et qu'elle revient (ADR 0016, étape 5).
	Clean        int64   `json:"cl,omitempty"`
	CleanClients *Sketch `json:"cc,omitempty"`
	Days         []int32 `json:"d,omitempty"`
}

func (v *Violation) merge(o *Violation) {
	if o.First != 0 && (v.First == 0 || o.First < v.First) {
		v.First = o.First
	}
	if o.Last > v.Last {
		v.Last = o.Last
	}
	v.Count += o.Count
	v.Legit += o.Legit
	v.Blocked += o.Blocked
	v.Clients.merge(o.Clients)
	v.Clean += o.Clean
	if o.CleanClients != nil {
		if v.CleanClients == nil {
			v.CleanClients = newSketch(templatePrecision)
		}
		v.CleanClients.merge(o.CleanClients)
	}
	for _, d := range o.Days {
		v.Days = appendDay(v.Days, d)
	}
}

func (rp *RouteProfile) recordViolation(in *input, now time.Time) {
	if rp.ViolationTotals == nil {
		rp.ViolationTotals = map[string]int64{}
	}
	rp.ViolationTotals[in.Violation]++
	if in.Blocked {
		if rp.BlockedTotals == nil {
			rp.BlockedTotals = map[string]int64{}
		}
		rp.BlockedTotals[in.Violation]++
	}
	key := in.Violation + " " + in.Method + " " + normalizePath(in.Path)
	v := rp.Violations[key]
	if v == nil {
		if len(rp.Violations) >= maxViolations {
			rp.ViolationsOverflow++
			return
		}
		if rp.Violations == nil {
			rp.Violations = map[string]*Violation{}
		}
		v = &Violation{Clients: newSketch(templatePrecision), First: now.Unix()}
		rp.Violations[key] = v
	}
	v.Count++
	if in.Blocked {
		v.Blocked++
	}
	v.Last = now.Unix()
	status := in.Status
	if status == 0 {
		status = http.StatusOK
	}
	if in.Clean && learnable(status) {
		v.Legit++
	}
	if in.Clean {
		v.Clean++
		if v.CleanClients == nil {
			v.CleanClients = newSketch(templatePrecision)
		}
		v.CleanClients.add(hashIP(in.IP))
		v.Days = appendDay(v.Days, int32(now.Unix()/86400))
	}
	v.Clients.add(hashIP(in.IP))
}

// normalizePath réduit un chemin refusé à une forme qui ne garde pas d'identifiant : les segments qui en sont un deviennent
// leur classe ({int}, {uuid}…), les autres sont gardés (tronqués), au plus huit segments.
func normalizePath(path string) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(path); {
		if path[i] == '/' {
			i++
			continue
		}
		seg := path[i:]
		if j := strings.IndexByte(seg, '/'); j >= 0 {
			seg = seg[:j]
		}
		i += len(seg)
		if n == 8 {
			b.WriteString("/" + clsMore)
			break
		}
		n++
		b.WriteByte('/')
		if cls := classify(seg); cls != "" {
			b.WriteString(cls)
		} else if len(seg) > 40 {
			b.WriteString(seg[:40])
		} else {
			b.WriteString(seg)
		}
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

// WAFHit est une règle du WAF déclenchée par une requête.
type WAFHit struct {
	RuleID   int
	Category string
	Message  string
	Target   string
}

// WAFRule résume les déclenchements d'une règle du WAF sur un proxy. Clean, Served, Blocked, Clients et Days ne comptent que les
// requêtes d'IP propres si l'on met de côté la règle elle-même : c'est ce qui distingue un faux positif (un client ordinaire dont
// chaque recherche déclenche la règle) d'une attaque (qui fait vite remonter d'autres signaux).
type WAFRule struct {
	Category string           `json:"cat"`
	Message  string           `json:"msg"`
	Targets  map[string]int64 `json:"tg,omitempty"`
	Hits     int64            `json:"h"`
	Clean    int64            `json:"cl,omitempty"`
	// Served : parmi les requêtes propres, celles que le backend a servies (le WAF ne les a pas refusées) ; Blocked : celles que
	// le WAF a refusées.
	Served  int64            `json:"sv,omitempty"`
	Blocked int64            `json:"bl,omitempty"`
	Clients *Sketch          `json:"c"`
	Days    []int32          `json:"d,omitempty"`
	Paths   map[string]int64 `json:"p,omitempty"`
}

func (w *WAFRule) merge(o *WAFRule) {
	w.Hits += o.Hits
	w.Clean += o.Clean
	w.Served += o.Served
	w.Blocked += o.Blocked
	w.Clients.merge(o.Clients)
	for _, d := range o.Days {
		w.Days = appendDay(w.Days, d)
	}
	addMap(&w.Targets, o.Targets)
	addMap(&w.Paths, o.Paths)
}

func (rp *RouteProfile) recordWAF(in *input, now time.Time) {
	status := in.Status
	if status == 0 {
		status = http.StatusOK
	}
	path := ""
	for _, h := range in.WAFHits {
		w := rp.WAF[h.RuleID]
		if w == nil {
			if len(rp.WAF) >= maxWAFRules {
				rp.WAFOverflow++
				continue
			}
			if rp.WAF == nil {
				rp.WAF = map[int]*WAFRule{}
			}
			w = &WAFRule{Category: h.Category, Message: h.Message, Clients: newSketch(templatePrecision)}
			rp.WAF[h.RuleID] = w
		}
		w.Hits++
		if h.Target != "" {
			bump(&w.Targets, h.Target, 6)
		}
		if !in.CleanApartFromWAF {
			continue
		}
		w.Clean++
		w.Clients.add(hashIP(in.IP))
		w.Days = appendDay(w.Days, int32(now.Unix()/86400))
		switch {
		case in.WAFBlocked:
			w.Blocked++
		case learnable(status):
			w.Served++
		}
		if path == "" {
			path = in.Method + " " + normalizePath(in.Path)
		}
		bump(&w.Paths, path, maxWAFPaths)
	}
}
