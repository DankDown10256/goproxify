// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// pathTestStep is one step result in the traffic-path diagnostic.
type pathTestStep struct {
	Step      string `json:"step"`
	Status    string `json:"status"`     // "ok" | "warning" | "error" | "skip"
	Message   string `json:"message"`
	LatencyMS int64  `json:"latency_ms"` // -1 if not measured
}

// pathTestResult is the response body for POST /api/v1/proxies/{id}/path-test.
type pathTestResult struct {
	Steps []pathTestStep `json:"steps"`
}

var pathTestHTTPClient = &http.Client{
	Timeout: 6 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives: true,
	},
}

// ProxyPathTestHandler handles POST /api/v1/proxies/{id}/path-test
// and POST /api/v1/proxies/path-test (inline config body).
type ProxyPathTestHandler struct {
	DB *sql.DB
}

func (h *ProxyPathTestHandler) handle(w http.ResponseWriter, r *http.Request, p *proxyRow) {
	if r.Method != http.MethodPost {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	var cfg map[string]any
	_ = json.Unmarshal(p.Config, &cfg)

	host := strVal(cfg, "host")
	if host == "" {
		host = p.Name
	}
	proxyType := strings.ToLower(strVal(cfg, "type"))
	if proxyType == "" {
		if listenPort, ok := cfg["listen_port"]; ok && listenPort != nil {
			proxyType = "tcp"
		} else {
			proxyType = "http"
		}
	}
	tlsEnabled := boolVal(cfg, "tls_enabled") || proxyType == "https"
	tlsPassthrough := boolVal(cfg, "tls_passthrough")
	backends := extractBackends(cfg)

	jsonOK(w, pathTestResult{Steps: runPathTest(r.Context(), host, proxyType, p.Enabled, tlsEnabled, tlsPassthrough, backends)})
}

// handleInline accepts a JSON body directly (no proxy ID) — used for discovered containers.
func (h *ProxyPathTestHandler) handleInline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	var body struct {
		Host           string   `json:"host"`
		Type           string   `json:"type"`
		Backends       []string `json:"backends"`
		TLSEnabled     bool     `json:"tls_enabled"`
		TLSPassthrough bool     `json:"tls_passthrough"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	proxyType := strings.ToLower(body.Type)
	if proxyType == "" {
		proxyType = "http"
	}
	jsonOK(w, pathTestResult{Steps: runPathTest(r.Context(), body.Host, proxyType, true, body.TLSEnabled, body.TLSPassthrough, body.Backends)})
}

func runPathTest(ctx context.Context, host, proxyType string, enabled, tlsEnabled, tlsPassthrough bool, backends []string) []pathTestStep {
	isStream := proxyType == "tcp" || proxyType == "udp" || proxyType == "both"
	steps := make([]pathTestStep, 0, 6)

	if !isStream && host != "" && host != "—" {
		steps = append(steps, testDNS(ctx, host))
	} else if isStream {
		steps = append(steps, pathTestStep{
			Step: "dns", Status: "skip",
			Message: "TCP/UDP stream — pas de résolution DNS requise.", LatencyMS: -1,
		})
	}

	steps = append(steps, testEdgeEnabled(enabled))

	if !isStream {
		steps = append(steps, testTLS(ctx, host, tlsEnabled, tlsPassthrough))
	}

	steps = append(steps, testRoute(host, backends))

	for i, b := range backends {
		steps = append(steps, testBackend(ctx, b, i))
	}
	if len(backends) == 0 {
		steps = append(steps, pathTestStep{
			Step: "backend", Status: "warning",
			Message: "Aucun backend configuré.", LatencyMS: -1,
		})
	}
	return steps
}

func extractBackends(cfg map[string]any) []string {
	var backends []string
	if raw, ok := cfg["backends"]; ok {
		if arr, ok := raw.([]any); ok {
			for _, b := range arr {
				switch v := b.(type) {
				case string:
					backends = append(backends, v)
				case map[string]any:
					if u, ok := v["url"].(string); ok && u != "" {
						backends = append(backends, u)
					}
				}
			}
		}
	}
	return backends
}

func testDNS(ctx context.Context, host string) pathTestStep {
	h := host
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	r := &net.Resolver{}
	start := time.Now()
	addrs, err := r.LookupHost(ctx, h)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return pathTestStep{Step: "dns", Status: "error",
			Message: "Résolution DNS échouée : " + err.Error(), LatencyMS: lat}
	}
	if len(addrs) == 0 {
		return pathTestStep{Step: "dns", Status: "warning",
			Message: "Aucune adresse retournée pour " + h, LatencyMS: lat}
	}
	return pathTestStep{Step: "dns", Status: "ok",
		Message: h + " → " + strings.Join(addrs, ", "), LatencyMS: lat}
}

func testEdgeEnabled(enabled bool) pathTestStep {
	if !enabled {
		return pathTestStep{Step: "edge", Status: "warning",
			Message: "La route est désactivée — le trafic ne sera pas routé.", LatencyMS: -1}
	}
	return pathTestStep{Step: "edge", Status: "ok",
		Message: "Route activée.", LatencyMS: -1}
}

func testTLS(ctx context.Context, host string, tlsEnabled, tlsPassthrough bool) pathTestStep {
	if tlsPassthrough {
		return pathTestStep{Step: "tls", Status: "ok",
			Message: "TLS passthrough (SNI) — le chiffrement est géré par le backend.", LatencyMS: -1}
	}
	if !tlsEnabled {
		return pathTestStep{Step: "tls", Status: "warning",
			Message: "Pas de TLS configuré — le trafic circule en clair.", LatencyMS: -1}
	}

	h := host
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	addr := h + ":443"
	start := time.Now()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{ServerName: h}, //nolint:gosec
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return pathTestStep{Step: "tls", Status: "error",
			Message: "Connexion TLS échouée vers " + addr + " : " + err.Error(), LatencyMS: lat}
	}
	conn.Close()
	return pathTestStep{Step: "tls", Status: "ok",
		Message: "Handshake TLS réussi vers " + addr + ".", LatencyMS: lat}
}

func testRoute(host string, backends []string) pathTestStep {
	if host == "" || host == "—" {
		return pathTestStep{Step: "route", Status: "error",
			Message: "Aucun hôte configuré sur cette route.", LatencyMS: -1}
	}
	if len(backends) == 0 {
		return pathTestStep{Step: "route", Status: "warning",
			Message: "Route sans backend défini.", LatencyMS: -1}
	}
	return pathTestStep{Step: "route", Status: "ok",
		Message: "Hôte et backends présents.", LatencyMS: -1}
}

func testBackend(ctx context.Context, rawURL string, idx int) pathTestStep {
	step := pathTestStep{Step: "backend", LatencyMS: -1}
	u := rawURL
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		step.Status = "error"
		step.Message = rawURL + " : URL invalide — " + err.Error()
		return step
	}
	start := time.Now()
	resp, err := pathTestHTTPClient.Do(req)
	lat := time.Since(start).Milliseconds()
	step.LatencyMS = lat
	if err != nil {
		step.Status = "error"
		step.Message = rawURL + " : injoignable — " + err.Error()
		return step
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		step.Status = "error"
		step.Message = rawURL + " → HTTP " + http.StatusText(resp.StatusCode)
		return step
	}
	step.Status = "ok"
	step.Message = rawURL + " → HTTP " + http.StatusText(resp.StatusCode)
	return step
}

func strVal(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolVal(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
