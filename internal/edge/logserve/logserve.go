// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logserve sert les lectures de logs de l'API interne (recherche, histogramme, facettes, classements, IP
// distinctes, révélation d'une IP) sur un store du moteur internal/edge/logstore. La passerelle l'applique à sa base ; l'Admin
// l'applique, sans réseau, au store qu'il garde pour chaque passerelle (ADR 0018) : même code, mêmes réponses.
package logserve

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// MaxIPRanges borne les intervalles d'IP d'une requête (profondeur d'expression de SQLite).
const MaxIPRanges = 400

const (
	searchTimeout     = 8 * time.Second
	bulkSearchTimeout = 60 * time.Second
	// Un classement exact demande jusqu'à trois lectures de la période (ADR 0012) : le délai est celui d'une lecture.
	topTimeout = 20 * time.Second
)

// Gate borne les recherches simultanées : elles lisent la base que le journal est en train d'écrire, et ne doivent pas se
// disputer le disque avec le trafic. Une page normale à deux, un export à un seul.
type Gate struct {
	normal chan struct{}
	bulk   chan struct{}
}

func NewGate() *Gate {
	return &Gate{normal: make(chan struct{}, 2), bulk: make(chan struct{}, 1)}
}

// Acquire rend la fonction de libération, ou false si le store est déjà occupé.
func (g *Gate) Acquire(bulk bool) (func(), bool) {
	ch := g.normal
	if bulk {
		ch = g.bulk
	}
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	default:
		return nil, false
	}
}

// Logger est ce dont le service a besoin pour signaler un échec : *slog.Logger et le journal dynamique de la passerelle.
type Logger interface {
	Warn(msg string, args ...any)
}

// Service répond aux lectures de logs d'un store.
type Service struct {
	Store *logstore.Store
	// Node est le nom de la passerelle, porté par les lignes rendues.
	Node string
	Log  Logger
	Gate *Gate
	// SourceIDs : les lignes rendues portent le numéro qu'elles ont chez la passerelle d'origine (store de l'Admin), et une
	// révélation d'IP désigne la ligne par ce numéro. Une référence de ligne reste ainsi valable chez la passerelle.
	SourceIDs bool
}

func (s *Service) log() Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func encodeCursor(next map[logstore.Kind]logstore.Position) string {
	m := map[string]logapi.Pos{}
	for k, p := range next {
		m[string(k)] = logapi.Pos{Ts: p.Ts, ID: p.ID}
	}
	return logapi.EncodeCursor(m)
}

func decodeCursor(c string) (map[logstore.Kind]logstore.Position, error) {
	m, err := logapi.DecodeCursor(c)
	if err != nil || m == nil {
		return nil, err
	}
	out := map[logstore.Kind]logstore.Position{}
	for k, p := range m {
		out[logstore.Kind(k)] = logstore.Position{Ts: p.Ts, ID: p.ID}
	}
	return out, nil
}

// Query traduit les paramètres de l'API en requête sur la base.
func Query(p logapi.Params) (logstore.Query, error) {
	q := logstore.Query{
		Level: p.Level, Component: p.Component, Domain: p.Domain, IP: p.IP, Method: p.Method, Status: p.Status,
		Path: p.Path, TLSJA3: p.TLSJA3, TLSJA4: p.TLSJA4, Search: p.Search, RequestID: p.RequestID, ExcludeInternal: p.ExcludeInternal,
		PathPrefix: p.PathPrefix, IPFrom: p.IPFrom, IPTo: p.IPTo, AttributableOnly: p.Attributable,
	}
	for _, r := range strings.Split(p.IPRanges, ",") {
		if lo, hi, ok := strings.Cut(r, "|"); ok && lo != "" && hi != "" && len(q.IPRanges) < MaxIPRanges {
			q.IPRanges = append(q.IPRanges, [2]string{lo, hi})
		}
	}
	for _, d := range strings.Split(p.Domains, ",") {
		if d = strings.TrimSpace(d); d != "" {
			q.Domains = append(q.Domains, d)
		}
	}
	switch strings.ToLower(p.Kind) {
	case "access":
		q.Kinds = []logstore.Kind{logstore.KindAccess}
	case "system":
		q.Kinds = []logstore.Kind{logstore.KindSystem}
	case "":
	default:
		return q, errors.New("kind inconnu")
	}
	var err error
	if p.DateFrom != "" {
		if q.From, err = time.Parse(time.RFC3339, p.DateFrom); err != nil {
			return q, errors.New("date_from illisible")
		}
	}
	if p.DateTo != "" {
		if q.To, err = time.Parse(time.RFC3339, p.DateTo); err != nil {
			return q, errors.New("date_to illisible")
		}
	}
	return q, nil
}

// WithGate applique le plafond de recherches simultanées et le délai de la requête.
func (s *Service) WithGate(w http.ResponseWriter, r *http.Request, bulk bool, timeout time.Duration, fn func(ctx context.Context)) {
	if s.Store == nil {
		http.Error(w, "base de logs indisponible", http.StatusServiceUnavailable)
		return
	}
	if s.Gate != nil {
		release, ok := s.Gate.Acquire(bulk)
		if !ok {
			w.Header().Set("Retry-After", "2")
			http.Error(w, "passerelle occupée à chercher dans ses logs, réessayer", http.StatusTooManyRequests)
			return
		}
		defer release()
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	fn(ctx)
}

func (s *Service) entry(row logstore.Row, kind logstore.Kind) logapi.Entry {
	se := edgelog.ShipEntryFromRow(row, kind, s.Node)
	id := row.ID
	if s.SourceIDs && row.SourceID > 0 {
		id = row.SourceID
	}
	return logapi.Entry{
		ID: id, Kind: string(kind), Ts: row.Ts.UTC().Format(logapi.TsLayout), Level: se.Level, Component: se.Component, Domain: se.Domain,
		Method: se.Method, Path: se.Path, Status: se.Status, IP: se.IP, LatencyMs: se.LatencyMs, Bytes: se.Bytes,
		Message: se.Message, Referrer: se.Referrer, RequestID: se.RequestID, WAFMatches: se.WAFMatches,
		ThreatSignal: se.ThreatSignal, TLSJA3: se.TLSJA3, TLSJA4: se.TLSJA4, IPTruncated: se.IPTruncated,
		Pseudonymized: row.Pseudonymized,
	}
}

// Search : GET /internal/v1/logs/search — une page de lignes, du plus récent au plus ancien.
func (s *Service) Search(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q, err := Query(p)
	if err == nil {
		q.After, err = decodeCursor(p.Cursor)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch {
	case p.Limit <= 0:
		q.Limit = logapi.DefaultLimit
	case p.Bulk:
		q.Limit = min(p.Limit, logapi.MaxBulkLimit)
	default:
		q.Limit = min(p.Limit, logapi.MaxLimit)
	}
	timeout := searchTimeout
	if p.Bulk {
		timeout = bulkSearchTimeout
	}
	s.WithGate(w, r, p.Bulk, timeout, func(ctx context.Context) {
		page, err := s.Store.Search(ctx, q)
		if err != nil {
			s.log().Warn("logs: recherche échouée", "err", err)
			http.Error(w, "recherche impossible", http.StatusInternalServerError)
			return
		}
		out := logapi.SearchResponse{Entries: make([]logapi.Entry, 0, len(page.Rows)), HasMore: page.HasMore, Partial: page.Partial}
		for _, row := range page.Rows {
			out.Entries = append(out.Entries, s.entry(row, row.Kind()))
		}
		out.Next = encodeCursor(page.Next)
		writeJSON(w, out)
	})
}

// Histogram : GET /internal/v1/logs/histogram.
func (s *Service) Histogram(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q, err := Query(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bucket := p.Bucket
	if bucket != "minute" && bucket != "day" {
		bucket = "hour"
	}
	s.WithGate(w, r, false, searchTimeout, func(ctx context.Context) {
		pts, partial, err := s.Store.Histogram(ctx, q, bucket, p.TZOffsetMin)
		if err != nil {
			s.log().Warn("logs: histogramme échoué", "err", err)
			http.Error(w, "histogramme impossible", http.StatusInternalServerError)
			return
		}
		out := logapi.HistogramResponse{Points: make([]logapi.HistPoint, len(pts)), Partial: partial}
		for i, h := range pts {
			out.Points[i] = logapi.HistPoint{Bucket: h.Bucket, Total: h.Total, Warn: h.Warn, Error: h.Error}
		}
		writeJSON(w, out)
	})
}

// Facets : GET /internal/v1/logs/facets.
func (s *Service) Facets(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q, err := Query(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fields := []string{"level", "component", "domain", "method"}
	if p.Fields != "" {
		fields = strings.Split(p.Fields, ",")
	}
	s.WithGate(w, r, false, searchTimeout, func(ctx context.Context) {
		facets, total, partial, err := s.Store.Facets(ctx, q, fields)
		if err != nil {
			s.log().Warn("logs: facettes échouées", "err", err)
			http.Error(w, "facettes impossibles", http.StatusInternalServerError)
			return
		}
		out := logapi.FacetsResponse{Total: total, Partial: partial, Facets: map[string][]logapi.FacetCount{}}
		for field, list := range facets {
			for _, c := range list {
				out.Facets[field] = append(out.Facets[field], logapi.FacetCount{Value: c.Value, Count: c.Count})
			}
		}
		writeJSON(w, out)
	})
}

// Reveal : POST /internal/v1/logs/reveal — l'IP réelle d'une ligne pseudonymisée. La demande vient de l'Admin, qui a déjà
// contrôlé le droit de l'utilisateur et le motif.
func (s *Service) Reveal(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		http.Error(w, "base de logs indisponible", http.StatusServiceUnavailable)
		return
	}
	var req logapi.RevealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	kind := logstore.Kind(req.Kind)
	if kind != logstore.KindAccess && kind != logstore.KindSystem {
		http.Error(w, "kind inconnu", http.StatusBadRequest)
		return
	}
	var ip string
	var err error
	if s.SourceIDs {
		ip, err = s.Store.RevealSourceIP(kind, req.ID)
	} else {
		ip, err = s.Store.RevealIP(kind, req.ID)
	}
	switch {
	case errors.Is(err, logstore.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, logstore.ErrNotPseudonymized):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, logstore.ErrNoKey):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		s.log().Warn("logs: révélation d'IP échouée", "err", err)
		http.Error(w, "révélation impossible", http.StatusInternalServerError)
	default:
		s.log().Warn("rgpd: IP réelle révélée", "kind", req.Kind, "id", req.ID, "node", s.Node)
		writeJSON(w, logapi.RevealResponse{IP: ip})
	}
}

// Top : POST /internal/v1/logs/top — un regroupement des accès par champ. Les filtres sont ceux de la recherche, passés en
// paramètres ; la demande (champ, mode, K, seuil, valeurs) est le corps JSON.
func (s *Service) Top(w http.ResponseWriter, r *http.Request) {
	q, err := Query(logapi.ParamsFromValues(r.URL.Query()))
	var req logapi.TopRequest
	if err == nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		err = json.NewDecoder(r.Body).Decode(&req)
	}
	if err == nil && !logstore.TopDimension(req.Dim) {
		err = errors.New("champ inconnu")
	}
	mode := logstore.TopMode(req.Mode)
	if err == nil && mode != logstore.TopBest && mode != logstore.TopAbove && mode != logstore.TopExact {
		err = errors.New("mode inconnu")
	}
	if err == nil && (req.K < 0 || req.K > 10000 || len(req.Values) > logstore.MaxTopValues) {
		err = errors.New("demande trop grande")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.WithGate(w, r, false, topTimeout, func(ctx context.Context) {
		res, err := s.Store.Top(ctx, q, logstore.TopRequest{Dim: req.Dim, Mode: mode, K: req.K, Min: req.Min, Values: req.Values, WithIPs: req.WithIPs})
		if err != nil {
			s.log().Warn("logs: regroupement échoué", "err", err)
			http.Error(w, "regroupement impossible", http.StatusInternalServerError)
			return
		}
		out := logapi.TopResponse{Items: make([]logapi.TopItem, len(res.Items)), Complete: res.Complete, Partial: res.Partial}
		for i, it := range res.Items {
			out.Items[i] = logapi.TopItem{Value: it.Value, Requests: it.Requests, Errors: it.Errors, Bytes: it.Bytes,
				LatencySum: it.LatencySum, Flagged: it.Flagged, Blocked: it.Blocked, Ok: it.Ok, Bots: it.Bots, FirstSeen: it.FirstSeen, LastSeen: it.LastSeen, Truncated: it.Truncated, JA3: it.JA3, IPs: it.IPs}
		}
		writeJSON(w, out)
	})
}

// UniqueIPs : GET /internal/v1/logs/unique-ips — l'ensemble des IP des accès, résumé pour être fusionné.
func (s *Service) UniqueIPs(w http.ResponseWriter, r *http.Request) {
	q, err := Query(logapi.ParamsFromValues(r.URL.Query()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.WithGate(w, r, false, topTimeout, func(ctx context.Context) {
		sum, partial, err := s.Store.UniqueIPs(ctx, q)
		if err != nil {
			s.log().Warn("logs: IP distinctes échouées", "err", err)
			http.Error(w, "calcul impossible", http.StatusInternalServerError)
			return
		}
		writeJSON(w, logapi.UniqueIPsResponse{IPs: sum, Partial: partial})
	})
}
