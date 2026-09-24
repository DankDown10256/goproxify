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

// WAFMatchExtractor extrait les catégories WAF déclenchées depuis la requête (après traitement).
// Registré via SetWAFExtractor pour éviter les cycles d'import.
type WAFMatchExtractor func(r *http.Request) []string

// ThreatSignalExtractor extrait le signal Sentinel (raison) depuis la requête.
// Registré via SetThreatExtractor pour éviter les cycles d'import.
type ThreatSignalExtractor func(r *http.Request) string

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

	wafExtMu sync.RWMutex
	wafExt   WAFMatchExtractor

	threatExtMu sync.RWMutex
	threatExt   ThreatSignalExtractor

	f2bTapMu sync.RWMutex
	f2bTap   func(ip string, status int)

	proxyTapMu sync.RWMutex
	proxyTap   func(domain string, status int)

	anonymizeMu    sync.RWMutex
	anonymize      bool
	pseudonymize   bool
}

type accessEntry struct {
	Time          string   `json:"time"`
	RequestID     string   `json:"request_id,omitempty"`
	Method        string   `json:"method"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	Status        int      `json:"status"`
	BytesSent     int      `json:"bytes_sent"`
	DurationMs    int64    `json:"duration_ms"`
	RemoteIP      string   `json:"remote_ip"`
	// ShipIP est l'IP réelle à envoyer à l'Admin pour pseudonymisation (non loguée dans le fichier Core).
	ShipIP        string   `json:"-"`
	UserAgent     string   `json:"user_agent"`
	Referrer      string   `json:"referrer,omitempty"`
	WAFMatches    []string `json:"waf_matches,omitempty"`
	ThreatSignal  string   `json:"threat_signal,omitempty"`
}

// ShipEntry est le format attendu par l'Admin (WS access_log / POST /internal/v1/logs).
type ShipEntry struct {
	Ts            string   `json:"ts"`
	Level         string   `json:"level"`
	Component     string   `json:"component"`
	NodeName      string   `json:"node_name,omitempty"`
	Domain        string   `json:"domain"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Status        int      `json:"status"`
	IP            string   `json:"ip"`
	// RealIP est présent uniquement en mode pseudonymisation (non loggé, chiffré côté Admin).
	RealIP        string   `json:"real_ip,omitempty"`
	LatencyMs     int64    `json:"latency_ms"`
	Bytes         int64    `json:"bytes"`
	Message       string   `json:"message"`
	Referrer      string   `json:"referrer,omitempty"`
	RequestID     string   `json:"request_id,omitempty"`
	WAFMatches    []string `json:"waf_matches,omitempty"`
	ThreatSignal  string   `json:"threat_signal,omitempty"`
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

		// Tap Fail2Ban Core (non-bloquant).
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
			se := ShipEntry{
				Ts:           e.Time,
				Level:        lvl,
				Component:    "core",
				NodeName:     nodeName,
				Domain:       stripHostPort(e.Host),
				Method:       e.Method,
				Path:         e.Path,
				Status:       e.Status,
				IP:           e.RemoteIP,
				RealIP:       e.ShipIP,
				LatencyMs:    e.DurationMs,
				Bytes:        int64(e.BytesSent),
				Message:      shipMessage(e),
				Referrer:     e.Referrer,
				RequestID:    e.RequestID,
				WAFMatches:   e.WAFMatches,
				ThreatSignal: e.ThreatSignal,
			}
			payload[i] = se
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

// SetWAFExtractor enregistre la fonction d'extraction des matches WAF (évite le cycle logger↔waf).
func (a *AccessLogger) SetWAFExtractor(fn WAFMatchExtractor) {
	a.wafExtMu.Lock()
	a.wafExt = fn
	a.wafExtMu.Unlock()
}

// SetThreatExtractor enregistre la fonction d'extraction du signal Sentinel.
func (a *AccessLogger) SetThreatExtractor(fn ThreatSignalExtractor) {
	a.threatExtMu.Lock()
	a.threatExt = fn
	a.threatExtMu.Unlock()
}

// SetProxyTap enregistre un callback appelé pour chaque requête loguée (domain, status).
// Permet au moteur de règles de calculer les taux d'erreurs par proxy.
func (a *AccessLogger) SetProxyTap(fn func(domain string, status int)) {
	a.proxyTapMu.Lock()
	a.proxyTap = fn
	a.proxyTapMu.Unlock()
}

// SetF2BTap enregistre un callback appelé pour chaque requête loguée (ip, status).
// Utilisé par le moteur Fail2Ban Core pour alimenter sa fenêtre glissante.
// Passer nil pour désactiver.
func (a *AccessLogger) SetF2BTap(fn func(ip string, status int)) {
	a.f2bTapMu.Lock()
	a.f2bTap = fn
	a.f2bTapMu.Unlock()
}

// SetIPPseudonymize active le mode pseudonymisation : le fichier Core reçoit une IP tronquée,
// mais l'Admin reçoit l'IP réelle pour la chiffrer (AES-GCM) côté Admin.
// Mutuellement exclusif avec SetIPAnonymize — les deux ne doivent pas être activés simultanément.
func (a *AccessLogger) SetIPPseudonymize(enabled bool) {
	a.anonymizeMu.Lock()
	a.pseudonymize = enabled
	a.anonymizeMu.Unlock()
}

// SetIPAnonymize active ou désactive l'anonymisation des IPs dans les logs.
// IPv4 : dernier octet remplacé par 0 (x.x.x.0).
// IPv6 : 80 derniers bits masqués (préfixe /48 conservé).
// Les taps Fail2Ban/Sentinel reçoivent toujours l'IP réelle avant anonymisation.
func (a *AccessLogger) SetIPAnonymize(enabled bool) {
	a.anonymizeMu.Lock()
	a.anonymize = enabled
	a.anonymizeMu.Unlock()
}

// anonymizeIP tronque une IP pour la conformité RGPD.
func anonymizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		v4[3] = 0
		return v4.String()
	}
	// IPv6 : conserver les 48 premiers bits, zéroïser les 80 suivants.
	v6 := parsed.To16()
	for i := 6; i < 16; i++ {
		v6[i] = 0
	}
	return v6.String()
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

		a.wafExtMu.RLock()
		ext := a.wafExt
		a.wafExtMu.RUnlock()
		var wafMatches []string
		if ext != nil {
			wafMatches = ext(r)
		}
		a.threatExtMu.RLock()
		tExt := a.threatExt
		a.threatExtMu.RUnlock()
		var threatSignal string
		if tExt != nil {
			threatSignal = tExt(r)
		}

		// Les taps sécurité reçoivent l'IP réelle avant toute anonymisation.
		a.f2bTapMu.RLock()
		tap := a.f2bTap
		a.f2bTapMu.RUnlock()
		if tap != nil {
			tap(ip, rw.status)
		}
		a.proxyTapMu.RLock()
		ptap := a.proxyTap
		a.proxyTapMu.RUnlock()
		if ptap != nil {
			ptap(stripHostPort(r.Host), rw.status)
		}

		a.anonymizeMu.RLock()
		anon := a.anonymize
		pseudo := a.pseudonymize
		a.anonymizeMu.RUnlock()

		logIP := ip
		shipIP := ""
		if pseudo {
			// Mode pseudonymisation : fichier Core = IP tronquée, Admin = IP réelle chiffrée.
			logIP = anonymizeIP(ip)
			shipIP = ip
		} else if anon {
			logIP = anonymizeIP(ip)
		}

		select {
		case a.ch <- accessEntry{
			Time:         start.UTC().Format(time.RFC3339Nano),
			RequestID:    r.Header.Get("X-Request-ID"),
			Method:       r.Method,
			Host:         r.Host,
			Path:         path,
			Status:       rw.status,
			BytesSent:    rw.written,
			DurationMs:   time.Since(start).Milliseconds(),
			RemoteIP:     logIP,
			ShipIP:       shipIP,
			UserAgent:    r.UserAgent(),
			Referrer:     r.Referer(),
			WAFMatches:   wafMatches,
			ThreatSignal: threatSignal,
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

// RealIP retourne l'IP réelle du client. Les headers CF-Connecting-IP / X-Forwarded-For /
// X-Real-IP ne sont lus que si la connexion directe vient d'un proxy de confiance
// (voir SetTrustedProxies) ; sinon n'importe quel client pourrait forger son IP.
func RealIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !isTrustedPeer(peer) {
		return peer
	}
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(cf) != nil {
		return cf
	}
	if ip := clientFromXFF(strings.Join(r.Header.Values("X-Forwarded-For"), ",")); ip != "" {
		return ip
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xri) != nil {
		return xri
	}
	return peer
}

// clientFromXFF lit la chaîne X-Forwarded-For de droite à gauche et retourne la première IP
// qui n'est pas un proxy de confiance : les entrées de gauche sont fournies par le client
// (un proxy ajoute à la valeur existante) et ne sont donc pas fiables.
func clientFromXFF(xff string) string {
	parts := strings.Split(xff, ",")
	first := ""
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if net.ParseIP(p) == nil {
			continue
		}
		first = p
		if !isTrustedPeer(p) {
			return p
		}
	}
	return first
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
