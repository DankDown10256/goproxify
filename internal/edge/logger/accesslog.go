// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/edge/tlsfp"
)

type notesKey struct{}

// requestNotes porte jusqu'au journal d'accès ce que les étapes de sécurité apprennent d'une requête. Le journal
// enveloppe tout le reste et chaque étape travaille sur une copie de la requête : un contexte posé en aval ne
// lui remonte jamais, d'où ce support partagé, placé dans le contexte avant les étapes.
type requestNotes struct {
	mu     sync.Mutex
	waf    []string
	threat string
}

func notesOf(ctx context.Context) *requestNotes {
	n, _ := ctx.Value(notesKey{}).(*requestNotes)
	return n
}

// NoteWAF signale au journal d'accès les catégories d'un refus ou d'une détection (WAF, plugin de détection).
func NoteWAF(ctx context.Context, categories ...string) {
	n := notesOf(ctx)
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range categories {
		if c != "" && !slices.Contains(n.waf, c) {
			n.waf = append(n.waf, c)
		}
	}
}

// NoteThreat signale au journal d'accès le signal Ephor d'une requête.
func NoteThreat(ctx context.Context, signal string) {
	if n := notesOf(ctx); n != nil {
		n.mu.Lock()
		n.threat = signal
		n.mu.Unlock()
	}
}

// AccessLogger enregistre les accès dans la base de logs locale de la passerelle (SetStore) de façon asynchrone
// et les pousse vers l'Admin (via SetForwarder et/ou SetRemote).
type AccessLogger struct {
	disabled atomic.Bool
	ch       chan accessEntry
	shipCh   chan accessEntry
	store    atomic.Pointer[logstore.Store]

	remoteMu    sync.RWMutex
	remoteURL   string
	remoteToken string
	nodeName    string
	forwardFn   func([]ShipEntry) // prioritaire sur HTTP si défini

	proxyTapMu sync.RWMutex
	proxyTap   func(domain string, status int)

	anonymizeMu  sync.RWMutex
	anonymize    bool
	pseudonymize bool
}

type accessEntry struct {
	Start      time.Time
	Time       string // Start en RFC3339Nano UTC, le format de ShipEntry.Ts
	RequestID  string
	Method     string
	Host       string
	Path       string
	Status     int
	BytesSent  int
	DurationMs int64
	RemoteIP   string
	// ShipIP est l'IP réelle en mode pseudonymisation : chiffrée dans la base locale, envoyée à l'Admin, jamais
	// écrite en clair avec l'IP tronquée.
	ShipIP       string
	IPTruncated  bool
	UserAgent    string
	Referrer     string
	WAFMatches   []string
	ThreatSignal string
	TLSJA3       string
	TLSJA4       string
}

// accessLevel est le niveau d'un accès d'après son code de statut.
func accessLevel(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status >= 400:
		return "warn"
	}
	return "info"
}

// storeEntry convertit l'accès en ligne de la base locale.
func (e accessEntry) storeEntry() logstore.Entry {
	return logstore.Entry{
		Ts: e.Start, Level: accessLevel(e.Status), Component: "edge", Domain: stripHostPort(e.Host),
		Method: e.Method, Path: e.Path, Status: e.Status, Bytes: int64(e.BytesSent), LatencyMs: e.DurationMs,
		IP: e.RemoteIP, RealIP: e.ShipIP, IPTruncated: e.IPTruncated, UserAgent: e.UserAgent, Referrer: e.Referrer,
		RequestID: e.RequestID, WAFMatches: e.WAFMatches, ThreatSignal: e.ThreatSignal, TLSJA3: e.TLSJA3, TLSJA4: e.TLSJA4,
	}
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
	// RealIP est présent uniquement en mode pseudonymisation (non loggé, chiffré côté Admin).
	RealIP string `json:"real_ip,omitempty"`
	// IPTruncated signale que IP est tronquée (anonymisation ou pseudonymisation) : la valeur ne
	// le dit pas, et l'Admin ne voit pas un ip_anonymize posé dans edge.json.
	IPTruncated  bool     `json:"ip_truncated,omitempty"`
	LatencyMs    int64    `json:"latency_ms"`
	Bytes        int64    `json:"bytes"`
	Message      string   `json:"message"`
	Referrer     string   `json:"referrer,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
	RequestID    string   `json:"request_id,omitempty"`
	WAFMatches   []string `json:"waf_matches,omitempty"`
	ThreatSignal string   `json:"threat_signal,omitempty"`
	TLSJA3       string   `json:"tls_ja3,omitempty"`
	TLSJA4       string   `json:"tls_ja4,omitempty"`
	// Seq : identifiant de la ligne dans la base de logs locale, le curseur du flux vers l'Admin.
	Seq int64 `json:"seq,omitempty"`
}

func NewAccessLogger() *AccessLogger {
	al := &AccessLogger{
		ch:     make(chan accessEntry, 8192),
		shipCh: make(chan accessEntry, 8192),
	}
	go al.drain()
	go al.ship()
	return al
}

// SetStore branche la base de logs locale. Sans elle, les accès ne sont que expédiés à l'Admin.
func (a *AccessLogger) SetStore(s *logstore.Store) { a.store.Store(s) }

func (a *AccessLogger) drain() {
	for e := range a.ch {
		if s := a.store.Load(); s != nil {
			s.Add(logstore.KindAccess, e.storeEntry())
		}
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
			se := ShipEntry{
				Ts:           e.Time,
				Level:        accessLevel(e.Status),
				Component:    "edge",
				NodeName:     nodeName,
				Domain:       stripHostPort(e.Host),
				Method:       e.Method,
				Path:         e.Path,
				Status:       e.Status,
				IP:           e.RemoteIP,
				RealIP:       e.ShipIP,
				IPTruncated:  e.IPTruncated,
				LatencyMs:    e.DurationMs,
				Bytes:        int64(e.BytesSent),
				Message:      shipMessage(e),
				Referrer:     e.Referrer,
				RequestID:    e.RequestID,
				WAFMatches:   e.WAFMatches,
				ThreatSignal: e.ThreatSignal,
				TLSJA3:       e.TLSJA3,
				TLSJA4:       e.TLSJA4,
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

// SetNodeName associe le nom du nœud passerelle aux access logs expédiés vers l'Admin.
func (a *AccessLogger) SetNodeName(name string) {
	a.remoteMu.Lock()
	a.nodeName = name
	a.remoteMu.Unlock()
}

// SetProxyTap enregistre un callback appelé pour chaque requête loguée (domain, status).
// Permet au moteur de règles de calculer les taux d'erreurs par proxy.
func (a *AccessLogger) SetProxyTap(fn func(domain string, status int)) {
	a.proxyTapMu.Lock()
	a.proxyTap = fn
	a.proxyTapMu.Unlock()
}

// SetIPProtection règle les deux modes d'un coup, sans état intermédiaire non protégé.
// Pseudonymisation : le fichier passerelle reçoit une IP tronquée, l'Admin l'IP réelle qu'il
// chiffre ; sans effet tant que l'anonymisation est active (voir ipFields).
func (a *AccessLogger) SetIPProtection(anonymize, pseudonymize bool) {
	a.anonymizeMu.Lock()
	a.anonymize, a.pseudonymize = anonymize, pseudonymize
	a.anonymizeMu.Unlock()
}

// IPProtection retourne l'état de l'anonymisation et de la pseudonymisation.
func (a *AccessLogger) IPProtection() (anonymize, pseudonymize bool) {
	a.anonymizeMu.RLock()
	defer a.anonymizeMu.RUnlock()
	return a.anonymize, a.pseudonymize
}

// SetIPAnonymize active ou désactive l'anonymisation des IPs dans les logs.
// IPv4 : dernier octet remplacé par 0 (x.x.x.0).
// IPv6 : 80 derniers bits masqués (préfixe /48 conservé).
// Les taps Ephor reçoivent toujours l'IP réelle avant anonymisation.
func (a *AccessLogger) SetIPAnonymize(enabled bool) {
	a.anonymizeMu.Lock()
	a.anonymize = enabled
	a.anonymizeMu.Unlock()
}

// ipFields retourne l'IP écrite dans le fichier local et l'IP réelle à envoyer à l'Admin
// (vide hors pseudonymisation). L'anonymisation l'emporte : elle peut venir de edge.json,
// et un opérateur qui l'a choisie localement ne doit jamais voir l'IP réelle quitter la passerelle.
func ipFields(ip string, anon, pseudo bool) (logIP, shipIP string) {
	switch {
	case anon:
		return anonymizeIP(ip), ""
	case pseudo:
		return anonymizeIP(ip), ip
	default:
		return ip, ""
	}
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

// Middleware wraps un http.Handler pour loguer chaque requête.
func (a *AccessLogger) Middleware(next http.Handler) http.Handler {
	if a.disabled.Load() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		notes := &requestNotes{}
		r = r.WithContext(context.WithValue(r.Context(), notesKey{}, notes))
		next.ServeHTTP(rw, r)

		// Plan de contrôle : pas d'access log (bruit pour Prism / Logs).
		path := r.URL.Path
		if strings.HasPrefix(path, "/internal/") || strings.HasPrefix(path, "/ws/") {
			return
		}

		ip := RealIP(r)

		notes.mu.Lock()
		wafMatches, threatSignal := notes.waf, notes.threat
		notes.mu.Unlock()

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
		logIP, shipIP := ipFields(ip, anon, pseudo)

		var fp tlsfp.Fingerprint
		if f := tlsfp.FromContext(r.Context()); f != nil {
			fp = *f
		}
		select {
		case a.ch <- accessEntry{
			Start:        start,
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
			IPTruncated:  anon || pseudo,
			UserAgent:    r.UserAgent(),
			Referrer:     r.Referer(),
			WAFMatches:   wafMatches,
			ThreatSignal: threatSignal,
			TLSJA3:       fp.JA3Hash,
			TLSJA4:       fp.JA4,
		}:
		default:
		}
	})
}

// shipMessage construit une ligne façon "combined log format" (Apache/nginx) — tout ce
// qu'un œil habitué à lire des access logs attend d'y trouver en un coup d'œil, plutôt que
// le seul User-Agent. RequestID, WAFMatches et ThreatSignal voyagent par ailleurs comme
// leurs propres champs structurés (ShipEntry), pas besoin de les dupliquer ici.
func shipMessage(e accessEntry) string {
	ts := e.Time
	if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
		ts = t.Format("02/Jan/2006:15:04:05 -0700")
	}
	ref := e.Referrer
	if ref == "" {
		ref = "-"
	}
	ua := e.UserAgent
	if ua == "" {
		ua = "-"
	}
	return fmt.Sprintf(`%s - [%s] "%s %s" %d %d "%s" "%s"`,
		e.RemoteIP, ts, e.Method, e.Path, e.Status, e.BytesSent, ref, ua)
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

// SetDisabled court-circuite le middleware (benchmark) : aucun log, aucun tap proxy.
func (a *AccessLogger) SetDisabled(off bool) { a.disabled.Store(off) }

// ShipEntryFromRow reconstitue l'entrée expédiée à l'Admin à partir d'une ligne de la base de logs locale.
// Seq porte l'identifiant de la ligne : le curseur du flux. RealIP n'est présente que pour une ligne lue avec
// logstore.Store.ReadAfterRevealed.
func ShipEntryFromRow(r logstore.Row, kind logstore.Kind, nodeName string) ShipEntry {
	e := ShipEntry{
		Ts: r.Ts.UTC().Format(time.RFC3339Nano), Level: r.Level, Component: r.Component, NodeName: nodeName,
		Domain: r.Domain, Method: r.Method, Path: r.Path, Status: r.Status, IP: r.IP, RealIP: r.RealIP,
		IPTruncated: r.IPTruncated, LatencyMs: r.LatencyMs, Bytes: r.Bytes, Message: r.Message, Referrer: r.Referrer,
		UserAgent: r.UserAgent, RequestID: r.RequestID, WAFMatches: r.WAFMatches, ThreatSignal: r.ThreatSignal, TLSJA3: r.TLSJA3,
		TLSJA4: r.TLSJA4, Seq: r.ID,
	}
	if kind == logstore.KindAccess {
		e.Message = shipMessage(accessEntry{
			Time: e.Ts, Method: r.Method, Path: r.Path, Status: r.Status, BytesSent: int(r.Bytes), RemoteIP: r.IP,
			UserAgent: r.UserAgent, Referrer: r.Referrer,
		})
	}
	return e
}
