// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package prismedge fournit à Prism les classements et les comptes qui exigent les lignes d'accès : elles vivent dans
// la base de logs de chaque passerelle (ADR 0012), l'Admin les interroge et fusionne. Les résultats ont la forme de
// ceux du paquet analytics, qui lit encore la copie de l'Admin tant que celle-ci existe.
package prismedge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/edgetop"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// nodeTimeout : un classement exact demande jusqu'à trois lectures de la période à la passerelle.
const nodeTimeout = 25 * time.Second

// Source interroge les passerelles. Client est celui des appels de logs (délai assez long pour un classement).
type Source struct {
	DB     *sql.DB
	Client *edgeproxy.Client
	// Geo (optionnel) géolocalise à la demande les IP des listes affichées.
	Geo *analytics.GeoResolver
	// Bulk (optionnel) lit les longues listes de lignes (traces d'IP) ; créé au premier usage.
	Bulk *edgeproxy.Client
}

// NewClient : client HTTP dont le délai couvre un classement exact.
func NewClient() *edgeproxy.Client { return edgeproxy.NewClientTimeout(nodeTimeout + 5*time.Second) }

// Unreachable est une passerelle qui n'a pas répondu.
type Unreachable struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Error    string `json:"error"`
}

// Meta dit d'où viennent les chiffres : combien de passerelles ont été interrogées, lesquelles manquent, et si l'une
// d'elles a rendu un résultat partiel (délai écoulé avant la fin de la période).
type Meta struct {
	Nodes       int           `json:"nodes"`
	Partial     bool          `json:"partial"`
	Unreachable []Unreachable `json:"unreachable"`
	// Estimated : un compte (IP uniques) est une estimation, pas un compte exact.
	Estimated bool `json:"estimated,omitempty"`
}

// Degraded : le résultat n'est pas celui de toutes les lignes.
func (m Meta) Degraded() bool { return m.Partial || len(m.Unreachable) > 0 }

// ErrNoGateway : aucune passerelle à interroger (aucune enregistrée, ou celle du filtre n'existe pas).
var ErrNoGateway = errors.New("prismedge: aucune passerelle à interroger")

// ErrUnsupported : toutes les passerelles interrogées sont d'une version qui ne sait pas faire ce calcul.
var ErrUnsupported = errors.New("prismedge: passerelles trop anciennes pour ce calcul")
// targets désigne les passerelles à interroger pour des lignes de logs : toutes, ou celle du filtre.
func (s *Source) targets(ctx context.Context, p analytics.Params) ([]edgeproxy.Target, error) {
	return s.memberTargets(ctx, p)
}
// targets désigne les passerelles à interroger pour des lignes de logs : toutes, ou celle du filtre.func (s *Source) targets(ctx context.Context, p analytics.Params) ([]edgeproxy.Target, error) {	return s.memberTargets(ctx, p)}

// memberTargets désigne les passerelles une à une : pour ce que chaque passerelle fait de son propre trafic (simulation
// Ephor, références apprises), où un pair ne répond pas à sa place.
func (s *Source) memberTargets(ctx context.Context, p analytics.Params) ([]edgeproxy.Target, error) {
	all, err := edgeproxy.ListTargets(ctx, s.DB)
	if err != nil {
		return nil, err
	}
	if p.NodeName == "" {
		return all, nil
	}
	var out []edgeproxy.Target
	for _, t := range all {
		if t.NodeName == p.NodeName {
			out = append(out, t)
		}
	}
	return out, nil
}

// Available dit s'il y a au moins une passerelle à interroger pour ce filtre.
func (s *Source) Available(ctx context.Context, p analytics.Params) bool {
	t, err := s.targets(ctx, p)
	return err == nil && len(t) > 0
}

// Params traduit les filtres de Prism en filtres de la base d'une passerelle. Les bornes incluent la seconde de fin
// en entier, comme la copie de l'Admin, dont les dates sont à la seconde.
func Params(p analytics.Params) logapi.Params {
	out := logapi.Params{Domains: p.Proxy, IP: p.IP, PathPrefix: p.Path}
	if !p.From.IsZero() {
		out.DateFrom = p.From.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	if !p.To.IsZero() {
		out.DateTo = p.To.UTC().Truncate(time.Second).Add(time.Second - time.Microsecond).Format(logapi.TsLayout)
	}
	return out
}

func (s *Source) client() *edgeproxy.Client {
	if s.Client == nil {
		s.Client = NewClient()
	}
	return s.Client
}

// meta fabrique le rapport à partir de ce que chaque passerelle a répondu.
func meta(targets []edgeproxy.Target, failed map[int]error, partial bool) (Meta, error) {
	m := Meta{Nodes: len(targets) - len(failed), Partial: partial, Unreachable: []Unreachable{}}
	unsupported := 0
	for i, t := range targets {
		err, ok := failed[i]
		if !ok {
			continue
		}
		m.Unreachable = append(m.Unreachable, Unreachable{NodeID: t.ID, NodeName: t.NodeName, Error: err.Error()})
		var he *edgeproxy.HTTPError
		if errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusMethodNotAllowed) {
			unsupported++
		}
	}
	if m.Nodes == 0 && unsupported == len(targets) && len(targets) > 0 {
		return m, ErrUnsupported
	}
	return m, nil
}

// Top classe les valeurs d'un champ des accès. Les passerelles qui manquent sont dans Meta.
func (s *Source) Top(ctx context.Context, p analytics.Params, extra func(*logapi.Params), dim string, k int, withIPs bool) ([]edgetop.Item, Meta, error) {
	targets, err := s.targets(ctx, p)
	if err != nil {
		return nil, Meta{}, err
	}
	if len(targets) == 0 {
		return nil, Meta{}, ErrNoGateway
	}
	lp := Params(p)
	if extra != nil {
		extra(&lp)
	}
	client := s.client()
	res := edgetop.Top(ctx, len(targets), func(ctx context.Context, n int, req logapi.TopRequest) (*logapi.TopResponse, error) {
		cctx, cancel := context.WithTimeout(ctx, nodeTimeout)
		defer cancel()
		return client.LogTop(cctx, targets[n], lp, req)
	}, edgetop.Request{Dim: dim, K: k, WithIPs: withIPs})
	m, err := meta(targets, res.Failed, res.Partial)
	return res.Items, m, err
}

// UniqueIPs compte les IP distinctes de la période : l'union de celles de chaque passerelle.
func (s *Source) UniqueIPs(ctx context.Context, p analytics.Params) (int64, Meta, error) {
	targets, err := s.targets(ctx, p)
	if err != nil {
		return 0, Meta{}, err
	}
	if len(targets) == 0 {
		return 0, Meta{}, ErrNoGateway
	}
	lp := Params(p)
	client := s.client()
	res := edgetop.Unique(ctx, len(targets), func(ctx context.Context, n int) (*logapi.UniqueIPsResponse, error) {
		cctx, cancel := context.WithTimeout(ctx, nodeTimeout)
		defer cancel()
		return client.LogUniqueIPs(cctx, targets[n], lp)
	})
	m, err := meta(targets, res.Failed, res.Partial)
	m.Estimated = !res.Exact
	return res.Count, m, err
}

// --- Les formes de réponse de Prism -------------------------------------------------------------------------------

func avg(sum, n int64) float64 {
	if n == 0 {
		return 0
	}
	return float64(sum) / float64(n)
}

// TopPaths : les chemins les plus demandés, page de limit à partir de offset, comme analytics.GetTopPaths.
func (s *Source) TopPaths(ctx context.Context, p analytics.Params, search string, limit, offset int) ([]analytics.PathEntry, bool, Meta, error) {
	if limit <= 0 {
		limit = 20
	}
	k := min(offset+limit+1, 10000)
	items, m, err := s.Top(ctx, p, func(lp *logapi.Params) { lp.Path = search }, "path", k, false)
	if err != nil {
		return nil, false, m, err
	}
	if offset >= len(items) {
		return []analytics.PathEntry{}, false, m, nil
	}
	items = items[offset:]
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	out := make([]analytics.PathEntry, len(items))
	for i, it := range items {
		out[i] = analytics.PathEntry{Path: it.Value, Requests: it.Requests, Errors: it.Errors, AvgLatMs: avg(it.LatencySum, it.Requests), Bytes: it.Bytes}
	}
	return out, hasMore, m, nil
}

// TopIPs : les IP les plus actives, comme analytics.GetTopIPs.
func (s *Source) TopIPs(ctx context.Context, p analytics.Params, limit int) ([]analytics.IPEntry, Meta, error) {
	if limit <= 0 {
		limit = 50
	}
	items, m, err := s.Top(ctx, p, nil, "ip", limit, false)
	if err != nil {
		return nil, m, err
	}
	out := make([]analytics.IPEntry, len(items))
	for i, it := range items {
		out[i] = analytics.IPEntry{IP: it.Value, Requests: it.Requests, Errors: it.Errors, Bytes: it.Bytes, IPTruncated: it.Truncated}
	}
	return out, m, nil
}

// TopComponents : la répartition par composant (« agents » de l'écran Prism), comme analytics.GetTopAgents.
func (s *Source) TopComponents(ctx context.Context, p analytics.Params, limit int) ([]analytics.AgentEntry, Meta, error) {
	if limit <= 0 {
		limit = 30
	}
	items, m, err := s.Top(ctx, p, nil, "component", limit, false)
	if err != nil {
		return nil, m, err
	}
	var total int64
	for _, it := range items {
		total += it.Requests
	}
	out := make([]analytics.AgentEntry, len(items))
	for i, it := range items {
		name := it.Value
		if name == "" {
			name = "unknown"
		}
		pct := 0.0
		if total > 0 {
			pct = float64(it.Requests) / float64(total) * 100
		}
		out[i] = analytics.AgentEntry{Name: name, Requests: it.Requests, Pct: pct, IsBot: analytics.IsBot(name)}
	}
	return out, m, nil
}

// TopReferrers : les référents les plus fréquents, comme analytics.GetTopReferrers.
func (s *Source) TopReferrers(ctx context.Context, p analytics.Params, limit int) ([]analytics.ReferrerEntry, Meta, error) {
	if limit <= 0 {
		limit = 30
	}
	items, m, err := s.Top(ctx, p, nil, "referrer", limit, false)
	if err != nil {
		return nil, m, err
	}
	var total int64
	for _, it := range items {
		total += it.Requests
	}
	out := make([]analytics.ReferrerEntry, len(items))
	for i, it := range items {
		out[i] = analytics.ReferrerEntry{Referrer: it.Value, Requests: it.Requests}
		if total > 0 {
			out[i].Pct = float64(it.Requests) / float64(total) * 100
		}
	}
	return out, m, nil
}

// TopTLSFingerprints : les empreintes JA4 les plus actives, comme analytics.GetTopTLSFingerprints.
func (s *Source) TopTLSFingerprints(ctx context.Context, p analytics.Params, limit int) ([]analytics.TLSFingerprintEntry, Meta, error) {
	if limit <= 0 {
		limit = 30
	}
	items, m, err := s.Top(ctx, p, nil, "tls_ja4", limit, true)
	if err != nil {
		return nil, m, err
	}
	out := make([]analytics.TLSFingerprintEntry, len(items))
	for i, it := range items {
		out[i] = analytics.TLSFingerprintEntry{JA4: it.Value, JA3: it.JA3, Requests: it.Requests, Errors: it.Errors, Flagged: it.Flagged, UniqueIPs: it.UniqueIPs}
	}
	return out, m, nil
}

// Header porte Meta dans deux en-têtes pour les réponses dont le corps est une liste.
func (m Meta) Header(h http.Header) {
	h.Set("X-Prism-Source", "edge")
	if m.Partial {
		h.Set("X-Prism-Partial", "1")
	}
	if m.Estimated {
		h.Set("X-Prism-Estimated", "1")
	}
	if len(m.Unreachable) > 0 {
		names := make([]string, len(m.Unreachable))
		for i, u := range m.Unreachable {
			names[i] = u.NodeName
		}
		h.Set("X-Prism-Unreachable", strings.Join(names, ","))
	}
}

// --- Carte et pays ------------------------------------------------------------------------------------------------

// IPStat est le trafic d'une IP sur la période, additionné sur les passerelles.
type IPStat struct {
	IP                            string
	Requests, Errors, Blocked, Ok int64
	Truncated                     bool
}

// everyValue demande à chaque passerelle toutes les valeurs d'un champ (au moins une requête) et additionne leurs
// comptes : exact, sans classement. ranges borne la colonne ip de chaque passerelle (voir IPStats). Chaque passerelle
// rend jusqu'à logstore.MaxTopAbove valeurs ; au-delà le résultat est marqué partiel.
func (s *Source) everyValue(ctx context.Context, p analytics.Params, dim string, ranges [][2]string) (map[string]*logapi.TopItem, Meta, error) {
	targets, err := s.targets(ctx, p)
	if err != nil {
		return nil, Meta{}, err
	}
	if len(targets) == 0 {
		return nil, Meta{}, ErrNoGateway
	}
	lp := Params(p)
	if len(ranges) > 0 {
		parts := make([]string, len(ranges))
		for i, r := range ranges {
			parts[i] = r[0] + "|" + r[1]
		}
		lp.IPRanges = strings.Join(parts, ",")
	}
	client := s.client()
	resps := make([]*logapi.TopResponse, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, nodeTimeout)
			defer cancel()
			resps[i], errs[i] = client.LogTop(cctx, targets[i], lp, logapi.TopRequest{Dim: dim, Mode: "above", Min: 1})
		}()
	}
	wg.Wait()
	failed, partial := map[int]error{}, false
	by := map[string]*logapi.TopItem{}
	for i, r := range resps {
		if errs[i] != nil {
			failed[i] = errs[i]
			continue
		}
		partial = partial || r.Partial
		for _, it := range r.Items {
			c := by[it.Value]
			if c == nil {
				c = &logapi.TopItem{Value: it.Value}
				by[it.Value] = c
			}
			c.Requests += it.Requests
			c.Errors += it.Errors
			c.Bytes += it.Bytes
			c.Blocked += it.Blocked
			c.Ok += it.Ok
			c.Truncated = c.Truncated || it.Truncated
		}
	}
	m, err := meta(targets, failed, partial)
	return by, m, err
}

// IPStats énumère les IP de la période avec leurs comptes (requêtes, erreurs, refusées ou signalées, réussies). ranges
// borne la colonne ip de chaque passerelle par des intervalles de texte (voir security.TraceIPRange) : un sur-ensemble,
// que l'appelant raffine. Chaque passerelle rend toutes ses IP (jusqu'à logstore.MaxTopAbove) ; au-delà le résultat
// est marqué partiel.
func (s *Source) IPStats(ctx context.Context, p analytics.Params, ranges [][2]string) ([]IPStat, Meta, error) {
	by, m, err := s.everyValue(ctx, p, "ip", ranges)
	out := make([]IPStat, 0, len(by))
	for ip, c := range by {
		out = append(out, IPStat{IP: ip, Requests: c.Requests, Errors: c.Errors, Blocked: c.Blocked, Ok: c.Ok, Truncated: c.Truncated})
	}
	return out, m, err
}

// IPCounts : les comptes par IP de la période, matière de la répartition par pays et de la carte.
func (s *Source) IPCounts(ctx context.Context, p analytics.Params) ([]analytics.IPCount, Meta, error) {
	stats, m, err := s.IPStats(ctx, p, nil)
	out := make([]analytics.IPCount, len(stats))
	for i, st := range stats {
		out[i] = analytics.IPCount{IP: st.IP, Requests: st.Requests, Errors: st.Errors}
	}
	return out, m, err
}

// Totals rend les totaux de la sélection (requêtes, erreurs, premier et dernier passage, tronquée) : un seul groupe.
// found est faux quand aucune ligne ne correspond.
func (s *Source) Totals(ctx context.Context, p analytics.Params) (it logapi.TopItem, found bool, m Meta, err error) {
	items, m, err := s.Top(ctx, p, nil, "all", 1, false)
	if err != nil || len(items) == 0 {
		return logapi.TopItem{}, false, m, err
	}
	return items[0].TopItem, true, m, nil
}

func (s *Source) locate(ctx context.Context, counts []analytics.IPCount) {
	if s.Geo != nil {
		s.Geo.Ensure(ctx, ipsOf(counts))
	}
}

func ipsOf(counts []analytics.IPCount) []string {
	out := make([]string, len(counts))
	for i, c := range counts {
		out[i] = c.IP
	}
	return out
}

// GeoBreakdown : le trafic par pays, comme analytics.GetGeoBreakdown.
func (s *Source) GeoBreakdown(ctx context.Context, p analytics.Params) ([]analytics.GeoEntry, Meta, error) {
	counts, m, err := s.IPCounts(ctx, p)
	if err != nil {
		return nil, m, err
	}
	s.locate(ctx, counts)
	return analytics.GeoBreakdownFromIPs(ctx, s.DB, counts), m, nil
}

// GeoPoints : le trafic par ville, comme analytics.GetGeoPoints.
func (s *Source) GeoPoints(ctx context.Context, p analytics.Params, limit int) ([]analytics.GeoPoint, Meta, error) {
	counts, m, err := s.IPCounts(ctx, p)
	if err != nil {
		return nil, m, err
	}
	s.locate(ctx, counts)
	return analytics.GeoPointsFromIPs(ctx, s.DB, counts, limit), m, nil
}

// LiveIPs rend les accès les plus récents de toutes les passerelles depuis since, du plus récent au plus ancien,
// comme analytics.GetLiveIPs.
func (s *Source) LiveIPs(ctx context.Context, since time.Time, proxy, nodeName string, limit int) ([]analytics.LiveIPEvent, Meta, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	p := analytics.Params{Proxy: proxy, NodeName: nodeName}
	targets, err := s.targets(ctx, p)
	if err != nil {
		return nil, Meta{}, err
	}
	if len(targets) == 0 {
		return nil, Meta{}, ErrNoGateway
	}
	lp := logapi.Params{Kind: "access", Domains: proxy, DateFrom: since.UTC().Format(time.RFC3339), Limit: limit}
	client := s.client()
	resps := make([]*logapi.SearchResponse, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			resps[i], errs[i] = client.LogSearch(cctx, targets[i], lp)
		}()
	}
	wg.Wait()
	failed, partial := map[int]error{}, false
	var lines []analytics.LiveLine
	for i, r := range resps {
		if errs[i] != nil {
			failed[i] = errs[i]
			continue
		}
		partial = partial || r.Partial
		for _, e := range r.Entries {
			if e.Status > 0 {
				lines = append(lines, analytics.LiveLine{IP: e.IP, Status: e.Status, Domain: e.Domain, Ts: e.Ts})
			}
		}
	}
	m, err := meta(targets, failed, partial)
	if err != nil {
		return nil, m, err
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Ts > lines[j].Ts })
	if len(lines) > limit {
		lines = lines[:limit]
	}
	ips := make([]string, len(lines))
	for i, l := range lines {
		ips[i] = l.IP
	}
	if s.Geo != nil {
		s.Geo.Ensure(ctx, ips)
	}
	return analytics.LiveEventsFromLines(ctx, s.DB, lines), m, nil
}

// --- Lignes ------------------------------------------------------------------------------------------------------

// Line est une ligne de log d'une passerelle.
type Line struct {
	Node string
	logapi.Entry
}

// bulkTimeout : une page de 20 000 lignes peut demander à la passerelle plusieurs secondes de lecture.
const bulkTimeout = 70 * time.Second

// pageLines : lignes lues par requête ; la passerelle n'en sert qu'une à la fois pour un export.
const pageLines = 20000

// Lines rend les lignes (accès et système) qui correspondent aux filtres de lp, des plus récentes aux plus anciennes
// sur chaque passerelle, au plus max lignes en tout ; capped dit que la limite a coupé la lecture (les plus
// anciennes manquent). node restreint à une passerelle par son nom.
func (s *Source) Lines(ctx context.Context, lp logapi.Params, node string, max int) (lines []Line, capped bool, m Meta, err error) {
	return s.fetchLines(ctx, lp, node, func(n int) int { return max / n })
}

// NewestLines rend les n lignes les plus récentes de l'ensemble des passerelles, fusionnées par date : chaque passerelle
// en donne au plus n, puis on garde les n premières. capped dit que des lignes plus anciennes existaient.
func (s *Source) NewestLines(ctx context.Context, lp logapi.Params, node string, n int) (lines []Line, capped bool, m Meta, err error) {
	lines, capped, m, err = s.fetchLines(ctx, lp, node, func(int) int { return n })
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].Ts != lines[j].Ts {
			return lines[i].Ts > lines[j].Ts
		}
		if lines[i].Node != lines[j].Node {
			return lines[i].Node < lines[j].Node
		}
		return lines[i].ID > lines[j].ID
	})
	if len(lines) > n {
		lines, capped = lines[:n], true
	}
	return lines, capped, m, err
}

func (s *Source) fetchLines(ctx context.Context, lp logapi.Params, node string, perNodeOf func(nodes int) int) (lines []Line, capped bool, m Meta, err error) {
	targets, err := s.targets(ctx, analytics.Params{NodeName: node})
	if err != nil {
		return nil, false, Meta{}, err
	}
	if len(targets) == 0 {
		return nil, false, Meta{}, ErrNoGateway
	}
	if s.Bulk == nil {
		s.Bulk = edgeproxy.NewBulkClient()
	}
	perNode := perNodeOf(len(targets))
	results := make([][]Line, len(targets))
	cappedAt := make([]bool, len(targets))
	errs := make([]error, len(targets))
	partials := make([]bool, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := lp
			p.Bulk = true
			for len(results[i]) < perNode {
				p.Limit = min(pageLines, perNode-len(results[i]))
				cctx, cancel := context.WithTimeout(ctx, bulkTimeout)
				r, err := s.Bulk.LogSearch(cctx, targets[i], p)
				cancel()
				if err != nil {
					errs[i] = err
					return
				}
				partials[i] = partials[i] || r.Partial
				for _, e := range r.Entries {
					node := targets[i].NodeName
					results[i] = append(results[i], Line{Node: node, Entry: e})
				}
				if !r.HasMore {
					return
				}
				p.Cursor = r.Next
			}
			cappedAt[i] = true
		}()
	}
	wg.Wait()
	failed, partial := map[int]error{}, false
	for i := range targets {
		if errs[i] != nil {
			failed[i] = errs[i]
			continue
		}
		partial = partial || partials[i]
		capped = capped || cappedAt[i]
		lines = append(lines, results[i]...)
	}
	m, err = meta(targets, failed, partial)
	return lines, capped, m, err
}

// Anomalies adapte la source aux règles de détection d'anomalies de Prism (analytics.Remote).
type Anomalies struct{ S *Source }

func (a Anomalies) Available(ctx context.Context, p analytics.Params) bool {
	return a.S != nil && a.S.Available(ctx, p)
}

// TopAttributableIP rend l'IP attribuable (ni tronquée ni pseudonymisée) la plus active de la période.
func (a Anomalies) TopAttributableIP(ctx context.Context, p analytics.Params) (analytics.IPEntry, bool, error) {
	items, _, err := a.S.Top(ctx, p, func(lp *logapi.Params) { lp.Attributable = true }, "ip", 1, false)
	if err != nil || len(items) == 0 {
		return analytics.IPEntry{}, false, err
	}
	it := items[0]
	return analytics.IPEntry{IP: it.Value, Requests: it.Requests, Errors: it.Errors, Bytes: it.Bytes}, true, nil
}

func (a Anomalies) FilteredTimeline(ctx context.Context, p analytics.Params, bucket string) ([]analytics.TimePoint, error) {
	pts, _, err := a.S.MinuteSeries(ctx, p)
	return analytics.TimelineFromMinutes(pts, bucket), err
}

func (a Anomalies) FilteredTotals(ctx context.Context, p analytics.Params) (analytics.Totals, error) {
	t, _, err := a.S.FilteredTotals(ctx, p)
	return t, err
}

func (a Anomalies) GeoBreakdown(ctx context.Context, p analytics.Params) ([]analytics.GeoEntry, error) {
	entries, _, err := a.S.GeoBreakdown(ctx, p)
	return entries, err
}

// ExportRows rend les lignes d'accès les plus récentes de la sélection (analytics.ExportMaxRows au plus), fusionnées
// depuis les passerelles, comme analytics.ExportCSV les lit dans la copie de l'Admin.
func (s *Source) ExportRows(ctx context.Context, p analytics.Params) ([]analytics.ExportRow, Meta, error) {
	lp := Params(p)
	lp.Kind = "access"
	lines, _, m, err := s.NewestLines(ctx, lp, p.NodeName, analytics.ExportMaxRows)
	if err != nil {
		return nil, m, err
	}
	out := make([]analytics.ExportRow, len(lines))
	for i, l := range lines {
		out[i] = analytics.ExportRow{Ts: l.Ts, Domain: l.Domain, Method: l.Method, Path: l.Path, Status: l.Status, IP: l.IP,
			LatencyMs: l.LatencyMs, Bytes: l.Bytes, Message: l.Message}
	}
	return out, m, nil
}

// --- Simulation Ephor ---------------------------------------------------------------------------------------------

// EphorSim est la simulation de deux configurations Ephor sur le trafic de toutes les passerelles. Chaque passerelle
// applique Ephor à son propre trafic : les rapports s'additionnent, une IP qui passe par deux passerelles compte
// pour chacune.
type EphorSim struct {
	Current, Candidate threat.SimReport
	Events, Skipped    int
	Truncated          bool
	Gateways           int
	Meta               Meta
}

// SimulateEphor rejoue les accès récents de chaque passerelle contre la configuration actuelle et la candidate.
func (s *Source) SimulateEphor(ctx context.Context, current, candidate threat.Config, hours int, domain string) (EphorSim, error) {
	targets, err := s.memberTargets(ctx, analytics.Params{})
	if err != nil {
		return EphorSim{}, err
	}
	if len(targets) == 0 {
		return EphorSim{}, ErrNoGateway
	}
	cur, _ := json.Marshal(current)
	cand, _ := json.Marshal(candidate)
	req := logapi.EphorSimRequest{Current: cur, Candidate: cand, Hours: hours, Domain: domain}
	if s.Bulk == nil {
		s.Bulk = edgeproxy.NewBulkClient()
	}
	resps := make([]*logapi.EphorSimResponse, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, bulkTimeout)
			defer cancel()
			resps[i], errs[i] = s.Bulk.EphorSimulate(cctx, targets[i], req)
		}()
	}
	wg.Wait()
	failed, partial := map[int]error{}, false
	out := EphorSim{Current: emptyReport(), Candidate: emptyReport()}
	for i, r := range resps {
		if errs[i] != nil {
			failed[i] = errs[i]
			continue
		}
		partial = partial || r.Partial
		out.Gateways++
		out.Events += r.Events
		out.Skipped += r.Skipped
		out.Truncated = out.Truncated || r.Truncated
		addReport(&out.Current, r.Current)
		addReport(&out.Candidate, r.Candidate)
	}
	out.Meta, err = meta(targets, failed, partial)
	finishReport(&out.Current)
	finishReport(&out.Candidate)
	return out, err
}

// GatewayReferences : ce qu'une passerelle a appris.
type GatewayReferences struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	logapi.EphorReferencesResponse
}

// EphorReferences demande à chaque passerelle (ou à celle de nodeName) ce qu'elle a appris pour la note commune d'Ephor.
func (s *Source) EphorReferences(ctx context.Context, nodeName string) ([]GatewayReferences, Meta, error) {
	targets, err := s.memberTargets(ctx, analytics.Params{NodeName: nodeName})
	if err != nil {
		return nil, Meta{}, err
	}
	if len(targets) == 0 {
		return nil, Meta{}, ErrNoGateway
	}
	if s.Bulk == nil {
		s.Bulk = edgeproxy.NewBulkClient()
	}
	resps := make([]*logapi.EphorReferencesResponse, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, bulkTimeout)
			defer cancel()
			resps[i], errs[i] = s.Bulk.EphorReferences(cctx, targets[i])
		}()
	}
	wg.Wait()
	failed := map[int]error{}
	out := []GatewayReferences{}
	for i, r := range resps {
		if errs[i] != nil {
			failed[i] = errs[i]
			continue
		}
		out = append(out, GatewayReferences{NodeID: targets[i].ID, NodeName: targets[i].NodeName, EphorReferencesResponse: *r})
	}
	m, err := meta(targets, failed, false)
	return out, m, err
}

func emptyReport() threat.SimReport {
	return threat.SimReport{ByReason: map[string]int{}, Bans: []threat.SimBan{}, TopIPs: []threat.SimIPStat{}}
}

func addReport(dst *threat.SimReport, r threat.SimReport) {
	dst.Events += r.Events
	dst.Blocked += r.Blocked
	dst.BlockedByBan += r.BlockedByBan
	dst.LegitBlocked += r.LegitBlocked
	dst.BlockedIPs += r.BlockedIPs
	for k, v := range r.ByReason {
		dst.ByReason[k] += v
	}
	dst.Bans = append(dst.Bans, r.Bans...)
	for _, st := range r.TopIPs {
		merged := false
		for i := range dst.TopIPs {
			if dst.TopIPs[i].IP == st.IP {
				d := &dst.TopIPs[i]
				d.Blocked += st.Blocked
				d.LegitBlocked += st.LegitBlocked
				d.Reasons = unionStrings(d.Reasons, st.Reasons, 5)
				d.SamplePaths = unionStrings(d.SamplePaths, st.SamplePaths, 3)
				merged = true
				break
			}
		}
		if !merged {
			dst.TopIPs = append(dst.TopIPs, st)
		}
	}
}

func unionStrings(a, b []string, max int) []string {
	for _, v := range b {
		if len(a) >= max {
			break
		}
		found := false
		for _, x := range a {
			found = found || x == v
		}
		if !found {
			a = append(a, v)
		}
	}
	return a
}

// finishReport remet les bans dans l'ordre du temps et ne garde que les dix IP les plus touchées.
func finishReport(r *threat.SimReport) {
	sort.SliceStable(r.Bans, func(i, j int) bool { return r.Bans[i].At.Before(r.Bans[j].At) })
	sort.SliceStable(r.TopIPs, func(i, j int) bool {
		if r.TopIPs[i].Blocked != r.TopIPs[j].Blocked {
			return r.TopIPs[i].Blocked > r.TopIPs[j].Blocked
		}
		return r.TopIPs[i].IP < r.TopIPs[j].IP
	})
	if len(r.TopIPs) > 10 {
		r.TopIPs = r.TopIPs[:10]
	}
}

// --- Prism filtré par IP ou par chemin --------------------------------------------------------------------------------

// Filtered dit si la sélection porte sur des lignes (IP, chemin) : les cumuls par minute ne la portent pas, seules les
// passerelles peuvent la compter.
func Filtered(p analytics.Params) bool { return p.IP != "" || p.Path != "" }

// FilteredTotals rend les totaux de la sélection : un seul groupe côté passerelles.
func (s *Source) FilteredTotals(ctx context.Context, p analytics.Params) (analytics.Totals, Meta, error) {
	it, found, m, err := s.Totals(ctx, p)
	if err != nil || !found {
		return analytics.Totals{}, m, err
	}
	t := analytics.Totals{Requests: it.Requests, Bytes: it.Bytes, Errors: it.Errors, Bots: it.Bots}
	if it.Requests > 0 {
		t.AvgLatencyMs = float64(it.LatencySum) / float64(it.Requests)
	}
	return t, m, nil
}

// FilteredKPIs : les KPIs d'une sélection filtrée par IP ou chemin, avec l'écart sur la période précédente (filtrée de
// la même façon). includeUnique ajoute les IP distinctes.
func (s *Source) FilteredKPIs(ctx context.Context, p analytics.Params, includeUnique bool) (analytics.KPIs, Meta, error) {
	cur, m, err := s.FilteredTotals(ctx, p)
	if err != nil {
		return analytics.KPIs{}, m, err
	}
	prevP := analytics.PreviousPeriod(p, false)
	prevP.IP, prevP.Path = p.IP, p.Path
	prev, _, err := s.FilteredTotals(ctx, prevP)
	if err != nil {
		return analytics.KPIs{}, m, err
	}
	var unique int64
	if includeUnique {
		if unique, _, err = s.UniqueIPs(ctx, p); err != nil {
			return analytics.KPIs{}, m, err
		}
	}
	return analytics.BuildKPIs(cur, prev, unique), m, nil
}

// MinuteSeries rend le trafic de la sélection minute par minute (UTC).
func (s *Source) MinuteSeries(ctx context.Context, p analytics.Params) ([]analytics.MinutePoint, Meta, error) {
	by, m, err := s.everyValue(ctx, p, "minute", nil)
	out := make([]analytics.MinutePoint, 0, len(by))
	for minute, c := range by {
		out = append(out, analytics.MinutePoint{Minute: minute, Requests: c.Requests, Errors: c.Errors, Bytes: c.Bytes})
	}
	return out, m, err
}

// StatusCounts rend les requêtes de la sélection par code HTTP.
func (s *Source) StatusCounts(ctx context.Context, p analytics.Params) (map[int]int64, Meta, error) {
	by, m, err := s.everyValue(ctx, p, "status", nil)
	out := make(map[int]int64, len(by))
	for code, c := range by {
		var n int
		if _, scanErr := fmt.Sscanf(code, "%d", &n); scanErr == nil {
			out[n] += c.Requests
		}
	}
	return out, m, err
}
