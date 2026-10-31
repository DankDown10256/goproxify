// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// Recherche dans les logs des passerelles (ADR 0012) : les lignes brutes vivent dans la base de chaque passerelle,
// l'Admin interroge toutes celles qui sont visées et fusionne leurs pages. Activée par `source=edge` sur les routes
// de logs ; sans ce paramètre l'Admin répond depuis sa propre base, comme avant.

const (
	remoteNodeTimeout = 10 * time.Second
	remoteBulkTimeout = 70 * time.Second
	remoteMaxPage     = logapi.MaxLimit
	remoteExportRows  = logapi.MaxBulkLimit
)

// remoteEntry est une ligne de log d'une passerelle dans la réponse de l'API Admin. Les champs suivent logs.Entry ;
// ID est une référence « <passerelle>:<type>:<id> » qui désigne la ligne chez sa passerelle (révélation d'IP).
type remoteEntry struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Ts            string   `json:"ts"`
	Level         string   `json:"level"`
	Component     string   `json:"component"`
	NodeName      string   `json:"node_name"`
	NodeID        string   `json:"node_id"`
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
	Country       string   `json:"country,omitempty"`
}

type unreachableNode struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Error    string `json:"error"`
}

// nodeResult est la réponse d'une passerelle à une recherche, ou son échec.
type nodeResult struct {
	T    edgeproxy.Target
	Resp *logapi.SearchResponse
	Err  error
}

type mergedPage struct {
	Entries     []remoteEntry
	Cursor      string
	HasMore     bool
	Partial     bool
	Unreachable []unreachableNode
}

func remoteRef(nodeID, kind string, id int64) string {
	return nodeID + ":" + kind + ":" + strconv.FormatInt(id, 10)
}

// parseRemoteRef lit la référence d'une ligne ; l'identifiant de passerelle est un UUID, sans « : ».
func parseRemoteRef(ref string) (nodeID, kind string, id int64, err error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 3 {
		return "", "", 0, errors.New("référence de ligne invalide")
	}
	id, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil || id <= 0 || (parts[1] != "access" && parts[1] != "system") {
		return "", "", 0, errors.New("référence de ligne invalide")
	}
	return parts[0], parts[1], id, nil
}

// encodeRemoteCursor et decodeRemoteCursor portent, par passerelle, le jeton de page que celle-ci a rendu.
func encodeRemoteCursor(m map[string]string) string {
	clean := map[string]string{}
	for k, v := range m {
		if v != "" {
			clean[k] = v
		}
	}
	if len(clean) == 0 {
		return ""
	}
	b, _ := json.Marshal(clean)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeRemoteCursor(c string) (map[string]string, error) {
	if c == "" {
		return map[string]string{}, nil
	}
	if len(c) > 64*1024 {
		return nil, errors.New("jeton de page trop long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mergeSearch fusionne les pages des passerelles, du plus récent au plus ancien, et garde limit lignes. Le jeton
// rendu place chaque passerelle juste après la dernière ligne qu'on en a retenue (et non celle qu'elle a rendue) :
// ce qu'on n'a pas retenu reviendra à la page suivante. Une passerelle injoignable garde sa position.
func mergeSearch(results []nodeResult, prev map[string]string, limit int) mergedPage {
	type item struct {
		e    remoteEntry
		node string
	}
	var all []item
	var out mergedPage
	moreFromNode := false
	for _, r := range results {
		if r.Err != nil {
			out.Unreachable = append(out.Unreachable, unreachableNode{NodeID: r.T.ID, NodeName: r.T.NodeName, Error: r.Err.Error()})
			continue
		}
		if r.Resp.Partial {
			out.Partial = true
		}
		if r.Resp.HasMore {
			moreFromNode = true
		}
		for _, e := range r.Resp.Entries {
			via, owner := r.T, r.T
			all = append(all, item{node: r.T.ID, e: remoteEntry{
				ID: remoteRef(via.ID, e.Kind, e.ID), Kind: e.Kind, Ts: e.Ts, Level: e.Level, Component: e.Component,
				NodeName: owner.NodeName, NodeID: owner.ID, Domain: e.Domain, Method: e.Method, Path: e.Path, Status: e.Status,
				IP: e.IP, LatencyMs: e.LatencyMs, Bytes: e.Bytes, Message: e.Message, Referrer: e.Referrer,
				RequestID: e.RequestID, WAFMatches: e.WAFMatches, ThreatSignal: e.ThreatSignal, TLSJA3: e.TLSJA3,
				TLSJA4: e.TLSJA4, IPTruncated: e.IPTruncated, Pseudonymized: e.Pseudonymized,
			}})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].e.Ts != all[j].e.Ts {
			return all[i].e.Ts > all[j].e.Ts
		}
		if all[i].node != all[j].node {
			return all[i].node < all[j].node
		}
		return all[i].e.ID > all[j].e.ID
	})
	if len(all) > limit {
		all = all[:limit]
		out.HasMore = true
	}
	out.HasMore = out.HasMore || moreFromNode
	// Positions par passerelle : celles de la page précédente, avancées jusqu'à la dernière ligne retenue.
	next := map[string]string{}
	positions := map[string]map[string]logapi.Pos{}
	for node, c := range prev {
		next[node] = c
		if pos, err := logapi.DecodeCursor(c); err == nil && pos != nil {
			positions[node] = pos
		}
	}
	for _, it := range all {
		if positions[it.node] == nil {
			positions[it.node] = map[string]logapi.Pos{}
		}
		_, _, id, _ := parseRemoteRef(it.e.ID)
		positions[it.node][it.e.Kind] = logapi.Pos{Ts: it.e.Ts, ID: id}
		out.Entries = append(out.Entries, it.e)
		next[it.node] = logapi.EncodeCursor(positions[it.node])
	}
	if out.Entries == nil {
		out.Entries = []remoteEntry{}
	}
	out.Cursor = encodeRemoteCursor(next)
	return out
}

// remoteParams traduit les filtres de l'API Admin en paramètres de recherche d'une passerelle.
func remoteParams(p logs.SearchParams) logapi.Params {
	return logapi.Params{
		Level: p.Level, Component: p.Component, Domain: p.Domain, IP: p.IP, Method: p.Method, Status: p.Status,
		Path: p.Path, TLSJA3: p.TLSJA3, TLSJA4: p.TLSJA4, Search: p.Search, RequestID: p.RequestID, DateFrom: p.DateFrom, DateTo: p.DateTo,
		Kind: p.Kind, ExcludeInternal: p.ExcludeInternal,
	}
}

func validRemoteDates(p logs.SearchParams) bool {
	for _, d := range []string{p.DateFrom, p.DateTo} {
		if d == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, d); err != nil {
			return false
		}
	}
	return true
}

func (h *LogsHandler) edgeClient(bulk bool) *edgeproxy.Client {
	if bulk {
		if h.BulkEdges == nil {
			h.BulkEdges = edgeproxy.NewBulkClient()
		}
		return h.BulkEdges
	}
	if h.Edges == nil {
		h.Edges = edgeproxy.NewClient()
	}
	return h.Edges
}

// remoteTargets désigne les passerelles visées : toutes, ou celle de node_id / node_name.
func (h *LogsHandler) remoteTargets(ctx context.Context, q url.Values) ([]edgeproxy.Target, error) {
	if q.Get("component") == "admin" || q.Get("node_name") == localNodeID {
		return nil, nil // le filtre ne vise que l'Admin
	}
	all, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return nil, err
	}
	id, name := q.Get("node_id"), q.Get("node_name")
	if id == "" && name == "" {
		return all, nil
	}
	var out []edgeproxy.Target
	for _, t := range all {
		if id != "" && t.ID == id {
			out = append(out, t)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	// La liste des nœuds identifie une passerelle par son nom ou par l'identifiant de sa fiche, pas par celui de son
	// jeton : à défaut de correspondance exacte, le nom (celui de node_name, sinon celui que porte node_id) désigne la cible.
	for _, t := range all {
		if (name != "" && t.NodeName == name) || (id != "" && t.NodeName == id) {
			out = append(out, t)
		}
	}
	return out, nil
}

// canonNodeID ramène un node_id reçu de l'interface (identifiant de fiche de nœud ou nom) à l'identifiant de jeton
// que portent les lignes de logs de l'Admin ; inchangé s'il ne désigne aucune passerelle.
func (h *LogsHandler) canonNodeID(ctx context.Context, p *logs.SearchParams) {
	if p.NodeID == "" || h.DB == nil {
		return
	}
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return
	}
	for _, t := range targets {
		if t.ID == p.NodeID {
			return
		}
	}
	for _, t := range targets {
		if t.NodeName == p.NodeID || (p.NodeName != "" && t.NodeName == p.NodeName) {
			p.NodeID = t.ID
			return
		}
	}
}

// fanOut exécute fn pour chaque passerelle en parallèle, chacune avec son propre délai.
func fanOut[T any](ctx context.Context, targets []edgeproxy.Target, timeout time.Duration, fn func(ctx context.Context, t edgeproxy.Target) (T, error)) ([]T, []error) {
	res := make([]T, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			res[i], errs[i] = fn(cctx, t)
		}()
	}
	wg.Wait()
	return res, errs
}

func (h *LogsHandler) searchRemote(ctx context.Context, targets []edgeproxy.Target, base logapi.Params, local *logs.SearchParams, prev map[string]string, limit int, bulk bool) mergedPage {
	timeout := remoteNodeTimeout
	if bulk {
		timeout = remoteBulkTimeout
	}
	client := h.edgeClient(bulk)
	resp, errs := fanOut(ctx, targets, timeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.SearchResponse, error) {
		p := base
		p.Cursor, p.Limit, p.Bulk = prev[t.ID], limit, bulk
		return client.LogSearch(ctx, t, p)
	})
	results := make([]nodeResult, len(targets), len(targets)+1)
	for i, t := range targets {
		results[i] = nodeResult{T: t, Resp: resp[i], Err: errs[i]}
	}
	if local != nil {
		results = append(results, h.localPage(*local, prev[localNodeID], limit))
	}
	return mergeSearch(results, prev, limit)
}

// countries renseigne le pays de chaque IP d'après le cache GeoIP déjà alimenté (même source que la liste locale).
func (h *LogsHandler) countries(ips map[string]struct{}) map[string]string {
	cc := map[string]string{}
	if h.DB == nil || len(ips) == 0 {
		return cc
	}
	args := make([]any, 0, len(ips))
	placeholders := make([]string, 0, len(ips))
	for ip := range ips {
		placeholders = append(placeholders, "?")
		args = append(args, ip)
	}
	rows, err := h.DB.Query(`SELECT ip, country_code FROM geoip_cache WHERE ip IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return cc
	}
	defer rows.Close()
	for rows.Next() {
		var ip, code string
		if rows.Scan(&ip, &code) == nil && code != "" && code != "XX" {
			cc[ip] = code
		}
	}
	return cc
}

func (h *LogsHandler) attachRemoteCountries(entries []remoteEntry) {
	ips := map[string]struct{}{}
	for _, e := range entries {
		if e.IP != "" {
			ips[e.IP] = struct{}{}
		}
	}
	cc := h.countries(ips)
	for i := range entries {
		entries[i].Country = cc[entries[i].IP]
	}
}

func remotePageSize(q url.Values) int {
	n, _ := strconv.Atoi(q.Get("page_size"))
	switch {
	case n <= 0:
		return logapi.DefaultLimit
	case n > remoteMaxPage:
		return remoteMaxPage
	}
	return n
}

// errRemoteBadRequest signale une requête invalide (date, jeton de page) : réponse 400.
type errRemoteBadRequest string

func (e errRemoteBadRequest) Error() string { return string(e) }

// ListEdges rend une page fusionnée des lignes de toutes les passerelles visées par q (mêmes paramètres que
// GET /api/v1/logs, plus node_id / node_name, cursor et page_size), avec les lignes propres de l'Admin. C'est la
// logique de la route et celle de l'outil MCP.
func (h *LogsHandler) ListEdges(ctx context.Context, q url.Values) (map[string]any, error) {
	p := logsParamsFromValues(q)
	if !validRemoteDates(p) {
		return nil, errRemoteBadRequest("date_from / date_to : RFC3339 requis")
	}
	prev, err := decodeRemoteCursor(q.Get("cursor"))
	if err != nil {
		return nil, errRemoteBadRequest("cursor invalide")
	}
	targets, err := h.remoteTargets(ctx, q)
	if err != nil {
		return nil, err
	}
	limit := remotePageSize(q)
	var local *logs.SearchParams
	if lp, ok := h.localParams(p, q); ok {
		local = &lp
	}
	page := h.searchRemote(ctx, targets, remoteParams(p), local, prev, limit, false)
	h.attachRemoteCountries(page.Entries)
	return map[string]any{
		"source": "edge", "entries": page.Entries, "has_more": page.HasMore, "cursor": page.Cursor,
		"partial": page.Partial, "unreachable": nonNilUnreachable(page.Unreachable), "page_size": limit,
	}, nil
}

// listRemote : GET /api/v1/logs?source=edge — une page fusionnée des lignes de toutes les passerelles visées.
func (h *LogsHandler) listRemote(w http.ResponseWriter, r *http.Request) {
	out, err := h.ListEdges(r.Context(), r.URL.Query())
	var bad errRemoteBadRequest
	switch {
	case errors.As(err, &bad):
		http.Error(w, bad.Error(), http.StatusBadRequest)
	case err != nil:
		logsJSONErr(w, err, http.StatusInternalServerError)
	default:
		jsonOK(w, out)
	}
}

func nonNilUnreachable(u []unreachableNode) []unreachableNode {
	if u == nil {
		return []unreachableNode{}
	}
	return u
}

// histogramRemote additionne les histogrammes des passerelles. Les tranches sont calculées à l'heure locale de
// l'Admin (décalage actuel de son fuseau).
func (h *LogsHandler) histogramRemote(w http.ResponseWriter, r *http.Request, p logs.SearchParams, bucket string) {
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	_, offset := time.Now().Zone()
	base := remoteParams(p)
	base.Bucket, base.TZOffsetMin = bucket, offset/60
	client := h.edgeClient(false)
	resp, errs := fanOut(r.Context(), targets, remoteNodeTimeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.HistogramResponse, error) {
		return client.LogHistogram(ctx, t, base)
	})
	merged := map[string]*logs.HistPoint{}
	var unreachable []unreachableNode
	partial := false
	for i, t := range targets {
		if errs[i] != nil {
			unreachable = append(unreachable, unreachableNode{NodeID: t.ID, NodeName: t.NodeName, Error: errs[i].Error()})
			continue
		}
		partial = partial || resp[i].Partial
		for _, pt := range resp[i].Points {
			m := merged[pt.Bucket]
			if m == nil {
				m = &logs.HistPoint{Bucket: pt.Bucket}
				merged[pt.Bucket] = m
			}
			m.Total += pt.Total
			m.Warn += pt.Warn
			m.Error += pt.Error
		}
	}
	// Les lignes propres de l'Admin : ses tranches sont déjà à son heure locale.
	if lp, ok := h.localParams(p, r.URL.Query()); ok {
		if local, err := h.Store.Histogram(lp, bucket); err == nil {
			for _, pt := range local {
				m := merged[pt.Bucket]
				if m == nil {
					m = &logs.HistPoint{Bucket: pt.Bucket}
					merged[pt.Bucket] = m
				}
				m.Total += pt.Total
				m.Warn += pt.Warn
				m.Error += pt.Error
			}
		}
	}
	pts := make([]logs.HistPoint, 0, len(merged))
	for _, m := range merged {
		pts = append(pts, *m)
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].Bucket < pts[j].Bucket })
	jsonOK(w, map[string]any{"source": "edge", "bucket": bucket, "points": pts, "partial": partial, "unreachable": nonNilUnreachable(unreachable)})
}

// facetsRemote additionne les facettes des passerelles ; « node_name » est le nombre de lignes de chacune.
func (h *LogsHandler) facetsRemote(w http.ResponseWriter, r *http.Request, p logs.SearchParams, fields []string) {
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	var forwarded []string
	wantNode := false
	for _, f := range fields {
		if f == "node_name" {
			wantNode = true
		} else {
			forwarded = append(forwarded, f)
		}
	}
	base := remoteParams(p)
	base.Fields = strings.Join(forwarded, ",")
	client := h.edgeClient(false)
	resp, errs := fanOut(r.Context(), targets, remoteNodeTimeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.FacetsResponse, error) {
		return client.LogFacets(ctx, t, base)
	})
	counts := map[string]map[string]int64{}
	var unreachable []unreachableNode
	partial := false
	for i, t := range targets {
		if errs[i] != nil {
			unreachable = append(unreachable, unreachableNode{NodeID: t.ID, NodeName: t.NodeName, Error: errs[i].Error()})
			continue
		}
		partial = partial || resp[i].Partial
		for field, list := range resp[i].Facets {
			if counts[field] == nil {
				counts[field] = map[string]int64{}
			}
			for _, c := range list {
				counts[field][c.Value] += c.Count
			}
		}
		if wantNode && resp[i].Total > 0 {
			if counts["node_name"] == nil {
				counts["node_name"] = map[string]int64{}
			}
			counts["node_name"][t.NodeName] += resp[i].Total
		}
	}
	// Les lignes propres de l'Admin : leurs facettes, et leur nombre (somme des niveaux) pour « node_name ».
	if lp, ok := h.localParams(p, r.URL.Query()); ok {
		local := forwarded
		if len(local) == 0 || !slicesContains(local, "level") {
			local = append(append([]string(nil), local...), "level")
		}
		if lf, err := h.Store.Facets(lp, local); err == nil {
			for field, list := range lf {
				if field == "node_name" || (field == "level" && !slicesContains(forwarded, "level")) {
					continue
				}
				if counts[field] == nil {
					counts[field] = map[string]int64{}
				}
				for _, c := range list {
					counts[field][c.Value] += c.Count
				}
			}
			if wantNode {
				var total int64
				for _, c := range lf["level"] {
					total += c.Count
				}
				if total > 0 {
					if counts["node_name"] == nil {
						counts["node_name"] = map[string]int64{}
					}
					counts["node_name"][localNodeID] += total
				}
			}
		}
	}
	facets := map[string]any{}
	for field, m := range counts {
		list := make([]logs.FacetCount, 0, len(m))
		for v, c := range m {
			list = append(list, logs.FacetCount{Value: v, Count: c})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count == list[j].Count {
				return list[i].Value < list[j].Value
			}
			return list[i].Count > list[j].Count
		})
		if len(list) > 12 {
			list = list[:12]
		}
		facets[field] = list
	}
	jsonOK(w, map[string]any{"source": "edge", "facets": facets, "partial": partial, "unreachable": nonNilUnreachable(unreachable)})
}

// exportRemote : export des lignes de toutes les passerelles visées (au plus 100 000), au format de l'export local.
func (h *LogsHandler) exportRemote(w http.ResponseWriter, r *http.Request, p logs.SearchParams, format string) {
	if !validRemoteDates(p) {
		http.Error(w, "date_from / date_to : RFC3339 requis", http.StatusBadRequest)
		return
	}
	targets, err := h.remoteTargets(r.Context(), r.URL.Query())
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	var local *logs.SearchParams
	if lp, ok := h.localParams(p, r.URL.Query()); ok {
		local = &lp
	}
	page := h.searchRemote(r.Context(), targets, remoteParams(p), local, nil, remoteExportRows, true)
	ts := time.Now().Format("20060102-150405")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=logs-"+ts+".csv")
		if len(page.Unreachable) > 0 {
			w.Header().Set("X-Unreachable-Nodes", strconv.Itoa(len(page.Unreachable)))
		}
		cw := csv.NewWriter(w)
		cw.Write([]string{"id", "ts", "level", "component", "node_name", "node_id", "domain", "method", "path", "status", "ip", "latency_ms", "bytes", "message"}) //nolint:errcheck
		for _, e := range page.Entries {
			cw.Write([]string{e.ID, e.Ts, e.Level, e.Component, e.NodeName, e.NodeID, e.Domain, e.Method, e.Path, //nolint:errcheck
				strconv.Itoa(e.Status), e.IP, strconv.FormatInt(e.LatencyMs, 10), strconv.FormatInt(e.Bytes, 10), e.Message})
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=logs-"+ts+".json")
	if len(page.Unreachable) > 0 {
		w.Header().Set("X-Unreachable-Nodes", strconv.Itoa(len(page.Unreachable)))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(page.Entries) //nolint:errcheck
}

// revealRemote révèle l'IP réelle d'une ligne pseudonymisée chez sa passerelle.
func (h *LogsHandler) revealRemote(ctx context.Context, ref string) (string, error) {
	nodeID, kind, id, err := parseRemoteRef(ref)
	if err != nil {
		return "", err
	}
	if nodeID == localNodeID {
		return h.Store.RevealIP(id)
	}
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return "", err
	}
	for _, t := range targets {
		if t.ID != nodeID {
			continue
		}
		resp, err := h.edgeClient(false).LogReveal(ctx, t, logapi.RevealRequest{Kind: kind, ID: id})
		if err != nil {
			return "", err
		}
		return resp.IP, nil
	}
	return "", errors.New("passerelle inconnue")
}

// revealEdgeLine : POST /api/v1/logs/reveal-ip avec entry_ref. Le droit (gdpr:reveal) et le motif sont déjà
// contrôlés par l'appelant ; l'Admin garde sa trace d'audit comme pour une ligne locale, la passerelle la sienne.
func (h *LogsHandler) revealEdgeLine(w http.ResponseWriter, r *http.Request, ref, reason string) {
	if _, _, _, err := parseRemoteRef(ref); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), remoteNodeTimeout)
	defer cancel()
	ip, err := h.revealRemote(ctx, ref)
	var he *edgeproxy.HTTPError
	switch {
	case errors.Is(err, logs.ErrEntryNotFound) || (errors.As(err, &he) && he.Status == http.StatusNotFound):
		logsJSONErr(w, errors.New("ligne introuvable"), http.StatusNotFound)
		return
	case errors.Is(err, logs.ErrNotPseudonymized) || (errors.As(err, &he) && he.Status == http.StatusUnprocessableEntity):
		logsJSONErr(w, logs.ErrNotPseudonymized, http.StatusUnprocessableEntity)
		return
	case err != nil:
		logsJSONErr(w, err, http.StatusBadGateway)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "gdpr_reveal_ip", "logs", fmt.Sprintf("entry_ref=%s reason=%q", ref, reason))
	h.Store.Write(logs.Entry{
		Level: "warn", Component: "admin",
		Message: fmt.Sprintf("RGPD révélation IP ligne %s par %s — %s", ref, actor, reason),
	})
	jsonOK(w, map[string]any{
		"entry_ref": ref, "ip": ip, "requested_by": actor, "reason": reason, "ts": time.Now().UTC().Format(time.RFC3339),
	})
}

// localNodeID désigne l'Admin lui-même dans une fusion : son audit, les logs de son process et les requêtes de son
// API ne sont que dans sa base, pas dans celle d'une passerelle.
const localNodeID = "admin"

// localParams dit si les lignes propres de l'Admin entrent dans la recherche, et avec quels filtres : seulement
// celles de component=admin (la table contient aussi la copie des lignes des passerelles), et jamais quand une
// passerelle précise est visée.
func (h *LogsHandler) localParams(p logs.SearchParams, q url.Values) (logs.SearchParams, bool) {
	if h.Store == nil || (p.Component != "" && p.Component != "admin") {
		return p, false
	}
	if q.Get("node_id") != "" {
		return p, false
	}
	if n := q.Get("node_name"); n != "" && n != localNodeID {
		return p, false
	}
	p.Component, p.NodeID, p.NodeName = "admin", "", ""
	return p, true
}

// localPage lit une page des lignes propres de l'Admin, sous la même forme qu'une page de passerelle : la fusion
// et le jeton de page n'ont pas à distinguer les deux. La position d'une page est celle de la dernière ligne
// retenue, comme pour une passerelle ; ici l'ordre est celui des identifiants de la base de l'Admin.
func (h *LogsHandler) localPage(p logs.SearchParams, cursor string, limit int) nodeResult {
	res := nodeResult{T: edgeproxy.Target{ID: localNodeID, NodeName: localNodeID}}
	pos, err := logapi.DecodeCursor(cursor)
	if err != nil {
		res.Err = err
		return res
	}
	var before int64
	for _, ps := range pos {
		if before == 0 || ps.ID < before {
			before = ps.ID
		}
	}
	p.BeforeID, p.Page, p.PageSize = before, 0, limit+1
	entries, _, err := h.Store.Search(p)
	if err != nil {
		res.Err = err
		return res
	}
	resp := &logapi.SearchResponse{Entries: make([]logapi.Entry, 0, len(entries))}
	if len(entries) > limit {
		resp.HasMore = true
		entries = entries[:limit]
	}
	for _, e := range entries {
		kind := "access"
		if e.Status == 0 {
			kind = "system"
		}
		resp.Entries = append(resp.Entries, logapi.Entry{
			ID: e.ID, Kind: kind, Ts: e.Ts.UTC().Format(logapi.TsLayout), Level: e.Level, Component: e.Component,
			Domain: e.Domain, Method: e.Method, Path: e.Path, Status: e.Status, IP: e.IP, LatencyMs: e.LatencyMs,
			Bytes: e.Bytes, Message: e.Message, Referrer: e.Referrer, RequestID: e.RequestID, WAFMatches: e.WAFMatches,
			ThreatSignal: e.ThreatSignal, TLSJA3: e.TLSJA3, TLSJA4: e.TLSJA4, IPTruncated: e.IPTruncated,
		})
	}
	res.Resp = resp
	return res
}

func slicesContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// addGatewayLogs complète l'export RGPD d'une IP avec ses lignes dans la base de chaque passerelle (les lignes d'accès
// ne sont plus que là, ADR 0012). Les lignes propres de l'Admin restent celles de sa base ; celles des passerelles que
// sa copie contient encore sont remplacées par la lecture des passerelles. Une passerelle qui n'a pas répondu est
// nommée dans l'export : il est incomplet.
func (h *LogsHandler) addGatewayLogs(ctx context.Context, ip string, res *logs.IPExport) {
	src := &prismedge.Source{DB: h.DB}
	if !src.Available(ctx, analytics.Params{}) {
		return
	}
	lines, capped, meta, err := src.NewestLines(ctx, logapi.Params{IP: ip}, "", logs.SubjectExportMaxLogs)
	if err != nil {
		if !errors.Is(err, prismedge.ErrUnsupported) {
			for _, u := range meta.Unreachable {
				res.GatewaysMissing = append(res.GatewaysMissing, u.NodeName)
			}
			if len(res.GatewaysMissing) == 0 {
				res.GatewaysMissing = []string{err.Error()}
			}
		}
		return
	}
	canon := ipcrypt.CanonicalIP(ip)
	kept := res.Logs[:0]
	for _, e := range res.Logs {
		if e.Component == "admin" {
			kept = append(kept, e)
		}
	}
	for _, l := range lines {
		ts, _ := time.Parse(time.RFC3339Nano, l.Ts)
		e := logs.Entry{Ts: ts, Level: l.Level, Component: l.Component, NodeName: l.Node, Domain: l.Domain, Method: l.Method, Path: l.Path,
			Status: l.Status, IP: l.IP, LatencyMs: l.LatencyMs, Bytes: l.Bytes, Message: l.Message, Referrer: l.Referrer,
			RequestID: l.RequestID, WAFMatches: l.WAFMatches, ThreatSignal: l.ThreatSignal, TLSJA3: l.TLSJA3, TLSJA4: l.TLSJA4,
			IPTruncated: l.IPTruncated}
		if l.Pseudonymized {
			e.IP = canon
		}
		kept = append(kept, e)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Ts.After(kept[j].Ts) })
	res.Logs = kept
	res.LogsTruncated = res.LogsTruncated || capped
	for _, u := range meta.Unreachable {
		res.GatewaysMissing = append(res.GatewaysMissing, u.NodeName)
	}
}

// gatewayErasure dit ce qu'une passerelle a fait d'un ordre d'effacement. Status « erased » : elle a répondu avec ses
// comptes, c'est la preuve ; « pending » : elle n'a pas répondu, l'ordre lui est rejoué à sa connexion (et garde 365 jours).
type gatewayErasure struct {
	NodeName string `json:"node_name"`
	Status   string `json:"status"`
	LogLines int64  `json:"log_lines"`
	BanRows  int64  `json:"ban_rows"`
	Error    string `json:"error,omitempty"`
}

// eraseOnGateways efface l'IP de chaque passerelle joignable et rend le résultat de chacune. Une passerelle qui ne
// répond pas est « pending » : l'ordre mis en file (OnEraseIP) lui sera rejoué.
func (h *LogsHandler) eraseOnGateways(ctx context.Context, ip string) []gatewayErasure {
	if h.DB == nil {
		return []gatewayErasure{}
	}
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil || len(targets) == 0 {
		return []gatewayErasure{}
	}
	client := h.edgeClient(false)
	results, errs := fanOut(ctx, targets, remoteNodeTimeout, func(ctx context.Context, t edgeproxy.Target) (*logapi.EraseResponse, error) {
		return client.LogErase(ctx, t, ip)
	})
	out := make([]gatewayErasure, len(targets))
	for i, t := range targets {
		g := gatewayErasure{NodeName: t.NodeName, Status: "erased"}
		if errs[i] != nil {
			g.Status, g.Error = "pending", errs[i].Error()
		} else {
			g.LogLines, g.BanRows = results[i].LogLines, results[i].BanRows
		}
		out[i] = g
	}
	return out
}
