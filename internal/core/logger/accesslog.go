// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/lumberjack.v2"
)

// AccessLogger écrit les access logs JSON de façon asynchrone et les pousse
// vers l'Admin (via SetForwarder et/ou SetRemote).
type AccessLogger struct {
	ch     chan accessEntry
	shipCh chan accessEntry

	mu  sync.Mutex
	enc *json.Encoder

	remoteMu    sync.RWMutex
	remoteURL   string
	remoteToken string
	nodeName    string
	forwardFn   func([]ShipEntry) // prioritaire sur HTTP si défini
}

type accessEntry struct {
	Time       string `json:"time"`
	RequestID  string `json:"request_id,omitempty"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	BytesSent  int    `json:"bytes_sent"`
	DurationMs int64  `json:"duration_ms"`
	RemoteIP   string `json:"remote_ip"`
	UserAgent  string `json:"user_agent"`
	Referrer   string `json:"referrer,omitempty"`
}

// ShipEntry est le format attendu par l'Admin (WS access_log / POST /internal/v1/logs).
type ShipEntry struct {
	Ts        string `json:"ts"`
	Level     string `json:"level"`
	Component string `json:"component"`
	NodeName  string `json:"node_name,omitempty"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	IP        string `json:"ip"`
	LatencyMs int64  `json:"latency_ms"`
	Bytes     int64  `json:"bytes"`
	Message   string `json:"message"`
	Referrer  string `json:"referrer,omitempty"`
}

func NewAccessLogger(path string) *AccessLogger {
	var enc *json.Encoder
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
			w := &lumberjack.Logger{
				Filename:   path,
				MaxSize:    200,
				MaxBackups: 7,
				MaxAge:     90,
				Compress:   true,
			}
			enc = json.NewEncoder(w)
		}
	}
	if enc == nil {
		enc = json.NewEncoder(os.Stdout)
	}
	al := &AccessLogger{
		ch:     make(chan accessEntry, 8192),
		shipCh: make(chan accessEntry, 8192),
		enc:    enc,
	}
	go al.drain()
	go al.ship()
	return al
}

func (a *AccessLogger) drain() {
	for e := range a.ch {
		a.mu.Lock()
		a.enc.Encode(e) //nolint:errcheck
		a.mu.Unlock()

		// Transfert non-bloquant vers le shipper Admin.
		select {
		case a.shipCh <- e:
		default:
		}
	}
}

// ship regroupe les entrées en batches et les envoie périodiquement à l'Admin.
func (a *AccessLogger) ship() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	batch := make([]accessEntry, 0, 100)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		a.remoteMu.RLock()
		url, token, forwardFn, nodeName := a.remoteURL, a.remoteToken, a.forwardFn, a.nodeName
		a.remoteMu.RUnlock()
		if forwardFn == nil && url == "" {
			batch = batch[:0]
			return
		}

		payload := make([]ShipEntry, len(batch))
		for i, e := range batch {
			lvl := "info"
			if e.Status >= 500 {
				lvl = "error"
			} else if e.Status >= 400 {
				lvl = "warn"
			}
			payload[i] = ShipEntry{
				Ts:        e.Time,
				Level:     lvl,
				Component: "core",
				NodeName:  nodeName,
				Domain:    stripHostPort(e.Host),
				Method:    e.Method,
				Path:      e.Path,
				Status:    e.Status,
				IP:        e.RemoteIP,
				LatencyMs: e.DurationMs,
				Bytes:     int64(e.BytesSent),
				Message:   shipMessage(e),
				Referrer:  e.Referrer,
			}
		}
		batch = batch[:0]

		if forwardFn != nil {
			forwardFn(payload)
			return
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return
		}
		req, err := http.NewRequest(http.MethodPost, url+"/internal/v1/logs", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}

	for {
		select {
		case e := <-a.shipCh:
			batch = append(batch, e)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// SetForwarder enregistre un callback pour pousser les batches (ex. WS → Admin).
// Prioritaire sur SetRemote. Passer nil pour désactiver.
func (a *AccessLogger) SetForwarder(fn func([]ShipEntry)) {
	a.remoteMu.Lock()
	a.forwardFn = fn
	a.remoteMu.Unlock()
}

// SetNodeName associe le nom du nœud Core aux access logs expédiés vers l'Admin.
func (a *AccessLogger) SetNodeName(name string) {
	a.remoteMu.Lock()
	a.nodeName = name
	a.remoteMu.Unlock()
}

// SetRemote configure (ou désactive si url == "") l'envoi HTTP vers l'Admin.
// Utilisé en secours si aucun SetForwarder n'est défini.
func (a *AccessLogger) SetRemote(adminURL, token string) {
	a.remoteMu.Lock()
	a.remoteURL = adminURL
	a.remoteToken = token
	a.remoteMu.Unlock()
}

// Reopen recrée le writer vers un nouveau chemin (hot-reload).
// Si path est vide, bascule vers stdout.
func (a *AccessLogger) Reopen(path string) {
	var enc *json.Encoder
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
			w := &lumberjack.Logger{
				Filename:   path,
				MaxSize:    200,
				MaxBackups: 7,
				MaxAge:     90,
				Compress:   true,
			}
			enc = json.NewEncoder(w)
		}
	}
	if enc == nil {
		enc = json.NewEncoder(os.Stdout)
	}
	a.mu.Lock()
	a.enc = enc
	a.mu.Unlock()
}

// Middleware wraps un http.Handler pour loguer chaque requête.
func (a *AccessLogger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)

		// Plan de contrôle : pas d'access log (bruit pour Prism / Logs).
		path := r.URL.Path
		if strings.HasPrefix(path, "/internal/") || strings.HasPrefix(path, "/ws/") {
			return
		}

		ip := RealIP(r)
		select {
		case a.ch <- accessEntry{
			Time:       start.UTC().Format(time.RFC3339Nano),
			RequestID:  r.Header.Get("X-Request-ID"),
			Method:     r.Method,
			Host:       r.Host,
			Path:       path,
			Status:     rw.status,
			BytesSent:  rw.written,
			DurationMs: time.Since(start).Milliseconds(),
			RemoteIP:   ip,
			UserAgent:  r.UserAgent(),
			Referrer:   r.Referer(),
		}:
		default:
		}
	})
}

func shipMessage(e accessEntry) string {
	if e.RequestID != "" {
		return fmt.Sprintf("request_id=%s", e.RequestID)
	}
	return ""
}

// stripHostPort retire le port de host:port pour aligner domain Prism / proxies.host.
func stripHostPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// IPv6 sans port entre crochets : [2001:db8::1]
	if len(host) > 1 && host[0] == '[' {
		if i := strings.IndexByte(host, ']'); i > 0 {
			return host[1:i]
		}
	}
	return host
}

// RealIP retourne l'IP réelle du client en respectant les headers Cloudflare/proxy.
func RealIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Prend la première IP (la plus proche du client)
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.written += n
	return n, err
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }
