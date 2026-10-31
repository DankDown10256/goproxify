// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logapitest fournit aux tests de l'Admin une passerelle de logs : une vraie base (logstore) derrière les routes
// internes que l'Admin interroge (regroupement, IP uniques, recherche, simulation Ephor). Les routes de la vraie
// passerelle vivent dans le paquet edge, que l'Admin ne peut pas importer ; celles-ci en reprennent le contrat.
package logapitest

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// Gateway est une passerelle de test.
type Gateway struct {
	Store  *logstore.Store
	Server *httptest.Server
	Name   string
	// References est ce que la passerelle répond à GET /internal/v1/ephor/references.
	References logapi.EphorReferencesResponse
	// Surface et Reports sont ce que la passerelle répond à GET /internal/v1/surface et /surface/report (par route) ;
	// Resets garde les proxies dont l'Admin a demandé la remise à zéro.
	Surface logapi.SurfaceListResponse
	Reports map[string]surface.Report
	Resets  []string
	// Proposals : ce que la passerelle répond à GET /internal/v1/surface/proposals, par proxy.
	Proposals map[string]surface.Proposals
	// OpenAPI : ce que la passerelle répond à GET /internal/v1/surface/openapi, par proxy.
	OpenAPI map[string]surface.OpenAPIResult
	// Forgotten garde les clés de violation que l'Admin a demandé d'effacer.
	Forgotten []string
	// Inventory : ce que la passerelle répond à GET /internal/v1/inventory.
	Inventory []logapi.InventoryEntry
}

// New démarre une passerelle de test, arrêtée avec le test.
func New(t testing.TB, name string) *Gateway {
	t.Helper()
	store, err := logstore.Open(logstore.Options{Dir: filepath.Join(t.TempDir(), "logs")})
	if err != nil {
		t.Fatal(err)
	}
	g := &Gateway{Store: store, Name: name}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+logapi.PathTop, g.top)
	mux.HandleFunc("GET "+logapi.PathUniqueIPs, g.uniqueIPs)
	mux.HandleFunc("GET "+logapi.PathSearch, g.search)
	mux.HandleFunc("POST "+logapi.PathEphorSim, g.simulate)
	mux.HandleFunc("GET "+logapi.PathEphorReferences, func(w http.ResponseWriter, _ *http.Request) { write(w, g.References) })
	mux.HandleFunc("GET "+logapi.PathSurface, func(w http.ResponseWriter, _ *http.Request) { write(w, g.Surface) })
	mux.HandleFunc("GET "+logapi.PathSurfaceReport, func(w http.ResponseWriter, r *http.Request) {
		rep, ok := g.Reports[r.URL.Query().Get("route")]
		if !ok {
			http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
			return
		}
		write(w, rep)
	})
	mux.HandleFunc("POST "+logapi.PathSurfaceForget, func(w http.ResponseWriter, r *http.Request) {
		var req logapi.SurfaceForgetRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		g.Forgotten = append(g.Forgotten, req.Keys...)
		write(w, logapi.SurfaceForgetResponse{Forgotten: len(req.Keys)})
	})
	mux.HandleFunc("GET "+logapi.PathInventory, func(w http.ResponseWriter, r *http.Request) {
		out := logapi.InventoryResponse{Entries: []logapi.InventoryEntry{}}
		for _, e := range g.Inventory {
			if ref := r.URL.Query().Get("route"); ref == "" || ref == e.Route || ref == e.Host {
				out.Entries = append(out.Entries, e)
			}
		}
		write(w, out)
	})
	mux.HandleFunc("GET "+logapi.PathSurfaceOpenAPI, func(w http.ResponseWriter, r *http.Request) {
		res, ok := g.OpenAPI[r.URL.Query().Get("route")]
		if !ok {
			http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
			return
		}
		write(w, res)
	})
	mux.HandleFunc("GET "+logapi.PathSurfaceProposals, func(w http.ResponseWriter, r *http.Request) {
		p, ok := g.Proposals[r.URL.Query().Get("route")]
		if !ok {
			http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
			return
		}
		write(w, p)
	})
	mux.HandleFunc("POST "+logapi.PathSurfaceReset, func(w http.ResponseWriter, r *http.Request) {
		var req logapi.SurfaceResetRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, had := g.Reports[req.Route]
		g.Resets = append(g.Resets, req.Route)
		delete(g.Reports, req.Route)
		write(w, logapi.SurfaceResetResponse{Reset: had})
	})
	g.Server = httptest.NewServer(mux)
	t.Cleanup(func() {
		g.Server.Close()
		_ = store.Close()
	})
	return g
}

// Register déclare la passerelle dans la table des jetons de l'Admin, comme un appairage.
func (g *Gateway) Register(db *sql.DB) error {
	_, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'edge', ?, ?)`,
		"id-"+g.Name, "tok-"+g.Name, g.Name, g.Server.URL)
	return err
}

// Add écrit des accès dans la base.
func (g *Gateway) Add(entries ...logstore.Entry) {
	for _, e := range entries {
		g.Store.Add(logstore.KindAccess, e)
	}
	g.Store.Flush()
}

func query(p logapi.Params) logstore.Query {
	q := logstore.Query{
		Level: p.Level, Component: p.Component, Domain: p.Domain, IP: p.IP, Method: p.Method, Status: p.Status, Path: p.Path,
		PathPrefix: p.PathPrefix, IPFrom: p.IPFrom, IPTo: p.IPTo, AttributableOnly: p.Attributable, ExcludeInternal: p.ExcludeInternal,
	}
	for _, d := range strings.Split(p.Domains, ",") {
		if d != "" {
			q.Domains = append(q.Domains, d)
		}
	}
	for _, r := range strings.Split(p.IPRanges, ",") {
		if lo, hi, ok := strings.Cut(r, "|"); ok {
			q.IPRanges = append(q.IPRanges, [2]string{lo, hi})
		}
	}
	switch p.Kind {
	case "access":
		q.Kinds = []logstore.Kind{logstore.KindAccess}
	case "system":
		q.Kinds = []logstore.Kind{logstore.KindSystem}
	}
	if t, err := time.Parse(time.RFC3339, p.DateFrom); err == nil {
		q.From = t
	}
	if t, err := time.Parse(time.RFC3339, p.DateTo); err == nil {
		q.To = t
	}
	return q
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (g *Gateway) top(w http.ResponseWriter, r *http.Request) {
	var req logapi.TopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := g.Store.Top(r.Context(), query(logapi.ParamsFromValues(r.URL.Query())), logstore.TopRequest{
		Dim: req.Dim, Mode: logstore.TopMode(req.Mode), K: req.K, Min: req.Min, Values: req.Values, WithIPs: req.WithIPs})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := logapi.TopResponse{Items: make([]logapi.TopItem, len(res.Items)), Complete: res.Complete, Partial: res.Partial}
	for i, it := range res.Items {
		out.Items[i] = logapi.TopItem{Value: it.Value, Requests: it.Requests, Errors: it.Errors, Bytes: it.Bytes, LatencySum: it.LatencySum,
			Flagged: it.Flagged, Blocked: it.Blocked, Ok: it.Ok, Bots: it.Bots, FirstSeen: it.FirstSeen, LastSeen: it.LastSeen,
			Truncated: it.Truncated, JA3: it.JA3, IPs: it.IPs}
	}
	write(w, out)
}

func (g *Gateway) uniqueIPs(w http.ResponseWriter, r *http.Request) {
	sum, partial, err := g.Store.UniqueIPs(r.Context(), query(logapi.ParamsFromValues(r.URL.Query())))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	write(w, logapi.UniqueIPsResponse{IPs: sum, Partial: partial})
}

func (g *Gateway) search(w http.ResponseWriter, r *http.Request) {
	p := logapi.ParamsFromValues(r.URL.Query())
	q := query(p)
	q.Limit = min(max(p.Limit, 1), logapi.MaxBulkLimit)
	if cur, err := logapi.DecodeCursor(p.Cursor); err == nil && cur != nil {
		q.After = map[logstore.Kind]logstore.Position{}
		for k, pos := range cur {
			q.After[logstore.Kind(k)] = logstore.Position{Ts: pos.Ts, ID: pos.ID}
		}
	}
	page, err := g.Store.Search(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := logapi.SearchResponse{Entries: make([]logapi.Entry, 0, len(page.Rows)), HasMore: page.HasMore, Partial: page.Partial}
	for _, row := range page.Rows {
		out.Entries = append(out.Entries, logapi.Entry{
			ID: row.ID, Kind: string(row.Kind()), Ts: row.Ts.UTC().Format(logapi.TsLayout), Level: row.Level, Component: row.Component,
			Domain: row.Domain, Method: row.Method, Path: row.Path, Status: row.Status, IP: row.IP, LatencyMs: row.LatencyMs, Bytes: row.Bytes,
			Message: row.Message, Referrer: row.Referrer, RequestID: row.RequestID, WAFMatches: row.WAFMatches, ThreatSignal: row.ThreatSignal,
			TLSJA3: row.TLSJA3, TLSJA4: row.TLSJA4, IPTruncated: row.IPTruncated, Pseudonymized: row.Pseudonymized,
		})
	}
	next := map[string]logapi.Pos{}
	for k, pos := range page.Next {
		next[string(k)] = logapi.Pos{Ts: pos.Ts, ID: pos.ID}
	}
	out.Next = logapi.EncodeCursor(next)
	write(w, out)
}

func (g *Gateway) simulate(w http.ResponseWriter, r *http.Request) {
	var req logapi.EphorSimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var current, candidate threat.Config
	if json.Unmarshal(req.Current, &current) != nil || json.Unmarshal(req.Candidate, &candidate) != nil {
		http.Error(w, "configuration illisible", http.StatusBadRequest)
		return
	}
	q := logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Domain: req.Domain, From: time.Now().Add(-time.Duration(req.Hours) * time.Hour), Limit: 20000}
	var events []threat.SimEvent
	skipped := 0
	for {
		page, err := g.Store.Search(r.Context(), q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, row := range page.Rows {
			if row.Status <= 0 {
				continue
			}
			if _, err := netip.ParseAddr(row.IP); err != nil || row.IPTruncated {
				skipped++
				continue
			}
			events = append(events, threat.SimEvent{Time: row.Ts, IP: row.IP, UA: row.UserAgent, Path: row.Path, Status: row.Status})
		}
		if !page.HasMore {
			break
		}
		q.After = page.Next
	}
	write(w, logapi.EphorSimResponse{Current: threat.Simulate(current, events), Candidate: threat.Simulate(candidate, events), Events: len(events), Skipped: skipped})
}
