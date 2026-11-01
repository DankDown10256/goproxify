// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logthrottle"
	"github.com/vincamok/goproxify/internal/edge/seasonal"
	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// recordUnknownHost compte une requête HTTP dont l'hôte n'a aucune route.
func (s *Server) recordUnknownHost(r *http.Request, ip string) {
	unknownHostTotal.Inc()
	ja4 := ""
	if fp := tlsfp.FromContext(r.Context()); fp != nil {
		ja4 = fp.JA4
	}
	s.rejects.Record(RejectUnknownHost, ip, r.Host, ja4)
}

// Raisons d'un rejet à l'entrée (ADR 0020, étape 1.c). Ensemble fermé : une raison est une étiquette de métrique.
const (
	RejectTimeout        = "timeout"          // ClientHello jamais reçu
	RejectTooManyPending = "too_many_pending" // trop de lectures de ClientHello en cours
	RejectBadClientHello = "bad_clienthello"  // connexion coupée ou ClientHello illisible avant tout TLS
	RejectNotTLS         = "not_tls"          // pas du TLS sur le port TLS (HTTP en clair, scanner de protocole)
	RejectNoSNI          = "no_sni"           // poignée de main sans nom : accès par l'IP
	RejectIPLiteral      = "ip_literal"       // le nom demandé est une adresse IP
	RejectUnknownSNI     = "unknown_sni"      // nom sans certificat
	RejectHandshake      = "handshake_failed" // nom connu, poignée de main interrompue ou refusée
	RejectUnknownHost    = "unknown_host"     // requête HTTP dont l'hôte n'a aucune route
)

const (
	rejectNameCap    = 256 // noms distincts suivis
	rejectSourceCap  = 256 // IP distinctes suivies
	rejectJA4Cap     = 128 // empreintes distinctes suivies
	rejectIPsPerName = 64  // IP distinctes retenues par nom, pour savoir si beaucoup de clients le demandent
	rejectNameMaxLen = 64
	rejectSnapshotN  = 50
	rejectEvictScan  = 16 // entrées examinées pour en évincer une quand une table est pleine
	rejectLogWindow  = 5 * time.Second
)

var unknownHostTotal = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "gpx",
	Subsystem: "edge",
	Name:      "unknown_host_total",
	Help:      "Requêtes HTTP dont l'hôte n'a aucune route (aucune étiquette d'hôte : le nom est choisi par le client).",
})

// rejectionLog garde, en mémoire et à taille fixe, ce que l'entrée de la passerelle refuse : combien par raison, quels noms sont
// demandés, par quelles IP et quelles empreintes. Rien n'en survit à un redémarrage et rien n'en dépend (c'est de la visibilité).
// Une valeur choisie par le client (nom demandé) est tronquée et assainie avant d'être gardée ou journalisée.
type rejectionLog struct {
	mu      sync.Mutex
	since   time.Time
	reasons map[string]int64
	names   map[string]*nameStat
	sources map[string]*sourceStat
	ja4     map[string]int64
	log     *slog.Logger
	logGate *logthrottle.Limiter
}

type nameStat struct {
	count int64
	ips   map[uint32]struct{} // IP distinctes, plafonnées à rejectIPsPerName
	capd  bool
}

type sourceStat struct {
	count      int64
	lastReason string
	lastJA4    string
}

func newRejectionLog(log *slog.Logger) *rejectionLog {
	return &rejectionLog{
		since:   time.Now(),
		reasons: map[string]int64{},
		names:   map[string]*nameStat{},
		sources: map[string]*sourceStat{},
		ja4:     map[string]int64{},
		log:     log,
		logGate: logthrottle.New(rejectLogWindow),
	}
}

// cleanName ramène un nom choisi par le client à une forme sûre à garder et à écrire : minuscules, ASCII imprimable, 64 caractères.
func cleanName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= rejectNameMaxLen {
			break
		}
		if r < 0x21 || r > 0x7e {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Record compte un rejet. name est le nom demandé (SNI ou Host), ja4 l'empreinte du client, vides si inconnus. Sans effet sur un
// journal nil.
func (l *rejectionLog) Record(reason, ip, name, ja4 string) {
	if l == nil {
		return
	}
	name = cleanName(name)
	ja4 = cleanName(ja4)
	l.mu.Lock()
	l.reasons[reason]++
	if name != "" {
		l.recordName(name, ip)
	}
	if ip != "" {
		l.recordSource(ip, reason, ja4)
	}
	if ja4 != "" {
		l.recordJA4(ja4)
	}
	l.mu.Unlock()

	// Une ligne par raison et par fenêtre : un scan de plusieurs milliers d'IP ne remplit pas les logs système.
	if ok, repeats := l.logGate.Allow("reject|" + reason); ok && l.log != nil {
		args := []any{"reason", reason, "ip", ip, "ja4", ja4, "name", name}
		if repeats > 0 {
			args = append(args, "repeats", repeats)
		}
		l.log.Info("entrée: connexion rejetée", args...)
	}
}

func (l *rejectionLog) recordName(name, ip string) {
	st := l.names[name]
	if st == nil {
		if len(l.names) >= rejectNameCap {
			evictSampled(l.names, func(s *nameStat) int64 { return s.count })
		}
		st = &nameStat{ips: map[uint32]struct{}{}}
		l.names[name] = st
	}
	st.count++
	if ip == "" {
		return
	}
	if _, seen := st.ips[hash32(ip)]; seen {
		return
	}
	if len(st.ips) >= rejectIPsPerName {
		st.capd = true
		return
	}
	st.ips[hash32(ip)] = struct{}{}
}

func (l *rejectionLog) recordSource(ip, reason, ja4 string) {
	st := l.sources[ip]
	if st == nil {
		if len(l.sources) >= rejectSourceCap {
			evictSampled(l.sources, func(s *sourceStat) int64 { return s.count })
		}
		st = &sourceStat{}
		l.sources[ip] = st
	}
	st.count++
	st.lastReason = reason
	if ja4 != "" {
		st.lastJA4 = ja4
	}
}

func (l *rejectionLog) recordJA4(ja4 string) {
	if _, ok := l.ja4[ja4]; !ok && len(l.ja4) >= rejectJA4Cap {
		evictSampledInt(l.ja4)
	}
	l.ja4[ja4]++
}

// evictSampled retire, parmi quelques entrées, celle qui a le plus petit compte (algorithme « space-saving » approché : une table
// pleine coûte une poignée d'accès, pas un parcours complet).
func evictSampled[T any](m map[string]*T, count func(*T) int64) {
	var victim string
	min, n := int64(-1), 0
	for k, v := range m {
		if c := count(v); min < 0 || c < min {
			victim, min = k, c
		}
		if n++; n >= rejectEvictScan {
			break
		}
	}
	delete(m, victim)
}

func evictSampledInt(m map[string]int64) {
	var victim string
	min, n := int64(-1), 0
	for k, c := range m {
		if min < 0 || c < min {
			victim, min = k, c
		}
		if n++; n >= rejectEvictScan {
			break
		}
	}
	delete(m, victim)
}

func hash32(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s)) //nolint:errcheck
	return h.Sum32()
}

// Forget retire une IP du classement (ordre d'effacement RGPD).
func (l *rejectionLog) Forget(ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.sources, ip)
	l.mu.Unlock()
}

// Les formes servies par GET /internal/v1/rejections sont celles de logapi, que l'Admin lit aussi.
type (
	RejectionName     = logapi.RejectionName
	RejectionSource   = logapi.RejectionSource
	RejectionJA4      = logapi.RejectionJA4
	RejectionSnapshot = logapi.RejectionsResponse
)

// Snapshot rend les totaux par raison et les premiers noms, IP et empreintes. Les classements sont approchés : une table pleine
// évince ses petites entrées.
func (l *rejectionLog) Snapshot() RejectionSnapshot {
	snap := RejectionSnapshot{Reasons: map[string]int64{}, Names: []RejectionName{}, Sources: []RejectionSource{}, JA4: []RejectionJA4{}, Probes: []logapi.RejectionProbe{}}
	if l == nil {
		return snap
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	snap.Since = l.since.UTC().Format(time.RFC3339)
	for r, n := range l.reasons {
		snap.Reasons[r] = n
	}
	for name, st := range l.names {
		snap.Names = append(snap.Names, RejectionName{Name: name, Count: st.count, Sources: len(st.ips), SourcesCapped: st.capd})
	}
	for ip, st := range l.sources {
		snap.Sources = append(snap.Sources, RejectionSource{IP: ip, Count: st.count, LastReason: st.lastReason, JA4: st.lastJA4})
	}
	for j, n := range l.ja4 {
		snap.JA4 = append(snap.JA4, RejectionJA4{JA4: j, Count: n})
	}
	sort.Slice(snap.Names, func(i, j int) bool { return snap.Names[i].Count > snap.Names[j].Count })
	sort.Slice(snap.Sources, func(i, j int) bool { return snap.Sources[i].Count > snap.Sources[j].Count })
	sort.Slice(snap.JA4, func(i, j int) bool { return snap.JA4[i].Count > snap.JA4[j].Count })
	if len(snap.Names) > rejectSnapshotN {
		snap.Names = snap.Names[:rejectSnapshotN]
	}
	if len(snap.Sources) > rejectSnapshotN {
		snap.Sources = snap.Sources[:rejectSnapshotN]
	}
	if len(snap.JA4) > rejectSnapshotN {
		snap.JA4 = snap.JA4[:rejectSnapshotN]
	}
	return snap
}

// handleRejections : GET /internal/v1/rejections — ce que l'entrée de la passerelle a refusé depuis son démarrage.
func (s *Server) handleRejections(w http.ResponseWriter, r *http.Request) {
	snap := s.rejects.Snapshot()
	if s.threatEngine != nil {
		for _, p := range s.threatEngine.UnknownHostProbes() {
			snap.Probes = append(snap.Probes, logapi.RejectionProbe{IP: p.IP, Hits: p.Hits, IntervalSeconds: p.IntervalSeconds})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap) //nolint:errcheck
}

// handleSeasonal : GET /internal/v1/seasonal — la référence saisonnière du trafic et ses alertes.
func (s *Server) handleSeasonal(w http.ResponseWriter, r *http.Request) {
	out := logapi.SeasonalResponse{Mode: "off", Routes: []seasonal.RouteStatus{}, Active: []seasonal.Event{}, Events: []seasonal.Event{}}
	if s.threatEngine != nil {
		out.Mode = s.threatEngine.SeasonalMode()
		out.Routes, out.Active, out.Events = s.threatEngine.SeasonalStatus(), s.threatEngine.SeasonalActive(), s.threatEngine.SeasonalEvents()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// notifyTrafficDeviation dit à l'Admin quelles alertes de trafic sont en cours (ADR 0020, étape 3.b). Sans Admin connecté le message
// se perd : l'alerte reste visible sur la passerelle et le message suivant rattrape l'Admin.
func (s *Server) notifyTrafficDeviation(active []seasonal.Event) {
	p := edgews.TrafficDeviationPayload{NodeName: s.cfg.Identity.NodeName, Alerts: make([]edgews.TrafficAlertPayload, 0, len(active))}
	for _, a := range active {
		p.Alerts = append(p.Alerts, edgews.TrafficAlertPayload{Route: a.Route, Level: a.Level, Since: a.At, RPS: a.RPS, Expected: a.Expected, Natures: a.Natures, Hardened: a.Hardened})
	}
	if msg, err := edgews.NewMessage(0, edgews.TypeTrafficDeviation, p); err == nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}
