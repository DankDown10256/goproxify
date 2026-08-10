// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package vulnscan sonde les en-têtes HTTP des backends et interroge NVD pour détecter les CVEs.
package vulnscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BackendResult résume le scan d'un backend.
type BackendResult struct {
	URL       string   `json:"url"`
	Status    string   `json:"status"` // pending|probing|ok|unreachable|no_headers
	Headers   []string `json:"headers,omitempty"`
	CVEsFound int      `json:"cves_found"`
	Error     string   `json:"error,omitempty"`
}

// State persiste l'état du scanner (progression + résumé).
type State struct {
	LastScan     time.Time       `json:"last_scan"`
	StartedAt    time.Time       `json:"started_at,omitempty"`
	FinishedAt   time.Time       `json:"finished_at,omitempty"`
	Running      bool            `json:"running"`
	ScannedN     int             `json:"scanned_n"`
	TotalN       int             `json:"total_n"`
	CurrentURL   string          `json:"current_url,omitempty"`
	CurrentStep  string          `json:"current_step,omitempty"` // probing|nvd|saving|done
	ProgressPct  int             `json:"progress_pct"`
	FoundCVEs    int             `json:"found_cves"`
	ReachableN   int             `json:"reachable_n"`
	UnreachableN int             `json:"unreachable_n"`
	NoHeadersN   int             `json:"no_headers_n"`
	NVDQueries   int             `json:"nvd_queries"`
	LastError    string          `json:"last_error,omitempty"`
	Results      []BackendResult `json:"results,omitempty"`
}

// Scanner détecte les CVEs sur les backends enregistrés.
type Scanner struct {
	db      *sql.DB
	log     *slog.Logger
	client  *http.Client
	nvdKey  string // NVD API key optionnel
	mu      sync.Mutex
	running bool
}

// New crée un Scanner.
func New(db *sql.DB, log *slog.Logger, nvdKey string) *Scanner {
	return &Scanner{
		db:     db,
		log:    log,
		nvdKey: nvdKey,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Start lance le scanner en arrière-plan (toutes les 6h).
func (s *Scanner) Start(ctx context.Context) {
	go func() {
		s.run(ctx)
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.run(ctx)
			}
		}
	}()
}

// RunNow déclenche un scan immédiat (appelé par l'API).
func (s *Scanner) RunNow(ctx context.Context) {
	go s.run(ctx)
}

// GetState retourne l'état courant du scanner.
func (s *Scanner) GetState() State {
	var raw string
	s.db.QueryRow(`SELECT value FROM vulnscan_state WHERE key='state'`).Scan(&raw) //nolint:errcheck
	var st State
	json.Unmarshal([]byte(raw), &st) //nolint:errcheck
	return st
}

func (s *Scanner) saveState(st State) {
	b, _ := json.Marshal(st)
	s.db.Exec(`INSERT OR REPLACE INTO vulnscan_state (key, value) VALUES ('state', ?)`, string(b)) //nolint:errcheck
}

func (s *Scanner) run(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	now := time.Now().UTC()
	backends := s.loadBackends()
	results := make([]BackendResult, len(backends))
	for i, u := range backends {
		results[i] = BackendResult{URL: u, Status: "pending"}
	}

	st := State{
		LastScan:  now,
		StartedAt: now,
		Running:   true,
		TotalN:    len(backends),
		Results:   results,
	}
	s.saveState(st)

	found := 0
	nvdQueries := 0
	var lastErr string

backendsLoop:
	for i, url := range backends {
		select {
		case <-ctx.Done():
			lastErr = "scan interrompu"
			break backendsLoop
		default:
		}

		st.CurrentURL = url
		st.CurrentStep = "probing"
		st.ScannedN = i
		st.ProgressPct = progressPct(i, len(backends))
		st.Results[i].Status = "probing"
		s.saveState(st)

		tokens, probeErr := s.probeServer(url)
		if probeErr != "" {
			st.Results[i].Status = "unreachable"
			st.Results[i].Error = probeErr
			st.UnreachableN++
			if lastErr == "" {
				lastErr = probeErr
			}
			st.ScannedN = i + 1
			st.ProgressPct = progressPct(i+1, len(backends))
			s.saveState(st)
			continue
		}
		if len(tokens) == 0 {
			st.Results[i].Status = "no_headers"
			st.NoHeadersN++
			st.ScannedN = i + 1
			st.ProgressPct = progressPct(i+1, len(backends))
			s.saveState(st)
			continue
		}

		st.Results[i].Status = "ok"
		st.Results[i].Headers = tokens
		st.ReachableN++
		backendCVEs := 0

		for _, kw := range tokens {
			select {
			case <-ctx.Done():
				lastErr = "scan interrompu"
				break backendsLoop
			default:
			}
			st.CurrentStep = "nvd"
			st.CurrentURL = url + " · " + kw
			s.saveState(st)

			cves, qErr := s.queryCVEs(ctx, kw)
			nvdQueries++
			st.NVDQueries = nvdQueries
			if qErr != "" {
				lastErr = qErr
				st.LastError = qErr
				s.saveState(st)
				continue
			}
			for _, c := range cves {
				_, err := s.db.ExecContext(ctx,
					`INSERT OR IGNORE INTO security_cves (backend_url, cve_id, cvss_score, description)
					 VALUES (?,?,?,?)`,
					url, c.id, c.cvss, c.desc)
				if err == nil {
					found++
					backendCVEs++
				}
			}
			st.FoundCVEs = found
			st.Results[i].CVEsFound = backendCVEs
			s.saveState(st)
		}

		st.ScannedN = i + 1
		st.ProgressPct = progressPct(i+1, len(backends))
		s.saveState(st)
	}

	st.Running = false
	st.FinishedAt = time.Now().UTC()
	st.CurrentURL = ""
	st.CurrentStep = "done"
	st.ScannedN = len(backends)
	st.ProgressPct = 100
	st.FoundCVEs = found
	st.NVDQueries = nvdQueries
	st.LastError = lastErr
	s.saveState(st)
	s.log.Info("vulnscan: scan terminé",
		"backends", len(backends),
		"reachable", st.ReachableN,
		"unreachable", st.UnreachableN,
		"no_headers", st.NoHeadersN,
		"cves", found,
	)
}

func progressPct(done, total int) int {
	if total <= 0 {
		return 100
	}
	p := (done * 100) / total
	if p > 100 {
		return 100
	}
	return p
}

func (s *Scanner) loadBackends() []string {
	rows, err := s.db.Query(`SELECT config FROM proxies WHERE enabled=1`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	var urls []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || !strings.Contains(u, "://") {
			return // ignore backends L4 sans schéma (tcp/udp host:port)
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
	}
	for rows.Next() {
		var cfg string
		if rows.Scan(&cfg) != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(cfg), &m) != nil {
			continue
		}
		// Format historique éventuel
		if v, ok := m["backend"].(string); ok {
			add(v)
		}
		// Format réel des proxies : backends [{url}] ou ["http://..."]
		switch b := m["backends"].(type) {
		case []any:
			for _, item := range b {
				switch v := item.(type) {
				case string:
					add(v)
				case map[string]any:
					if u, ok := v["url"].(string); ok {
						add(u)
					}
				}
			}
		}
	}
	return urls
}

func (s *Scanner) probeServer(url string) (tokens []string, errMsg string) {
	if err := validateProbeURL(url); err != nil {
		return nil, err.Error()
	}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err.Error()
	}
	resp, err := s.client.Do(req)
	if err != nil {
		req2, err2 := http.NewRequest(http.MethodGet, url, nil)
		if err2 != nil {
			return nil, err2.Error()
		}
		resp, err = s.client.Do(req2)
		if err != nil {
			return nil, err.Error()
		}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		val := resp.Header.Get(h)
		if val == "" {
			continue
		}
		// "nginx/1.25.3" → "nginx 1.25.3"
		kw := strings.ReplaceAll(val, "/", " ")
		kw = strings.Split(kw, " (")[0]
		if kw != "" {
			tokens = append(tokens, kw)
		}
	}
	return tokens, ""
}

type cveResult struct {
	id   string
	cvss float64
	desc string
}

var nvdRateLimit = time.NewTicker(7 * time.Second) // ~5 req / 35s sans clé

func (s *Scanner) queryCVEs(ctx context.Context, keyword string) ([]cveResult, string) {
	<-nvdRateLimit.C

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=5",
		strings.ReplaceAll(keyword, " ", "+"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err.Error()
	}
	if s.nvdKey != "" {
		req.Header.Set("apiKey", s.nvdKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "NVD: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("NVD HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV2 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, "NVD: réponse invalide"
	}

	var out []cveResult
	for _, v := range payload.Vulnerabilities {
		c := v.CVE
		var desc string
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		var cvss float64
		if len(c.Metrics.CvssMetricV31) > 0 {
			cvss = c.Metrics.CvssMetricV31[0].CvssData.BaseScore
		} else if len(c.Metrics.CvssMetricV2) > 0 {
			cvss = c.Metrics.CvssMetricV2[0].CvssData.BaseScore
		}
		out = append(out, cveResult{id: c.ID, cvss: cvss, desc: desc})
	}
	return out, ""
}
