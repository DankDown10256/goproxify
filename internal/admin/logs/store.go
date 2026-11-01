// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logs fournit le stockage et la diffusion en temps réel des logs.
package logs

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/gdpr"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// edgeLogMaxAgeDays est la conservation maximale des accès dans la base de logs d'une passerelle (365 jours par défaut, ADR 0012) :
// un ordre d'effacement doit durer autant, pour être rejoué à une passerelle absente tant qu'elle garde la ligne.
const edgeLogMaxAgeDays = 365

// Durées de rétention par défaut — modifiables via settings DB (clés logs.retention_access_days,
// logs.retention_system_days, logs.retention_ban_days).
const (
	DefaultRetentionAccessDays = 90  // logs HTTP (RGPD : durée courte par défaut, CNIL : 13 mois au plus)
	DefaultRetentionSystemDays = 90  // logs système/agent
	DefaultRetentionBanDays    = 365 // historique et bans expirés (1 an)
)

// Entry représente une ligne de log.
type Entry struct {
	ID        int64     `json:"id"`
	Ts        time.Time `json:"ts"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	NodeName  string    `json:"node_name,omitempty"`
	// NodeID est l'identifiant stable du nœud (edgeID/token), écrasé côté
	// Admin sur chaque entrée — voir stampLogBatchNode dans
	// internal/admin/edgews/manager.go. Contrairement à NodeName, il ne
	// change pas si le nœud est renommé, ce qui permet de filtrer
	// l'historique complet d'un nœud malgré un renommage.
	NodeID    string `json:"node_id,omitempty"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	IP        string `json:"ip"`
	LatencyMs int64  `json:"latency_ms"`
	Bytes     int64  `json:"bytes"`
	Message   string `json:"message"`
	Referrer  string `json:"referrer,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// WAFMatches (catégories WAF déclenchées) et ThreatSignal (signal Ephor) sont le
	// contexte de sécurité calculé par la passerelle pour la requête d'origine — vides
	// pour l'immense majorité des requêtes propres (200 OK), renseignés seulement quand
	// une protection s'est déclenchée.
	WAFMatches   []string `json:"waf_matches,omitempty"`
	ThreatSignal string   `json:"threat_signal,omitempty"`
	// TLSJA3/TLSJA4 : empreintes TLS du ClientHello calculées par la passerelle (vides en HTTP clair ou sans TLS terminé).
	TLSJA3        string     `json:"tls_ja3,omitempty"`
	TLSJA4        string     `json:"tls_ja4,omitempty"`
	RetainedUntil *time.Time `json:"retained_until,omitempty"`
	// Country est le code pays ISO résolu depuis geoip_cache — renseigné à la volée
	// par le handler API (LogsHandler.list), jamais persisté ici.
	Country string `json:"country,omitempty"`
	// RealIP est l'IP réelle fournie par la passerelle en mode pseudonymisation.
	// Elle n'est JAMAIS renvoyée dans les réponses API — uniquement chiffrée en DB.
	RealIP string `json:"-"`
	// IPTruncated : IP tronquée par la passerelle (anonymisation ou pseudonymisation). Les Seuils multi-passerelles, la
	// simulation Ephor et les actions de l'interface (ban, analyse d'IP) écartent ces lignes :
	// x.x.x.0 ou un /48 ne désignent aucun client.
	IPTruncated bool `json:"ip_truncated,omitempty"`
}

// SearchParams filtre les entrées de log.
type SearchParams struct {
	Level     string
	Component string
	NodeName  string
	// NodeID filtre par identifiant stable de nœud (préféré à NodeName quand
	// disponible : insensible aux renommages). Voir Entry.NodeID.
	NodeID   string
	Domain   string
	IP       string
	Method   string
	Status   string
	Path     string
	TLSJA3   string
	TLSJA4   string
	// RequestID : corrélation exacte avec la requête HTTP d'origine.
	RequestID string
	Search   string
	DateFrom string
	DateTo   string
	// Kind : "access" (status>0, requêtes HTTP) | "system" (status=0, événements process) | "" (tous).
	Kind string
	// ExcludeInternal exclut les IP de réseau privé/loopback (bruit d'auto-supervision,
	// ex. l'Admin qui s'interroge lui-même en 192.168.x) — appliqué en SQL, avant LIMIT,
	// pour que la pagination reste cohérente (page pleine ou hasMore correct), plutôt
	// qu'un filtrage après coup côté client qui peut rendre une page vide ou clairsemée.
	ExcludeInternal bool
	Page            int
	PageSize        int
	// BeforeID active la pagination par curseur (keyset) : retourne les entrées avec id < BeforeID.
	// Quand > 0, Page est ignoré et aucun COUNT n'est exécuté.
	BeforeID int64
}

// Store gère la persistance et la diffusion des logs.
type Store struct {
	db          *sql.DB
	mu          sync.RWMutex
	subscribers map[int64]chan Entry
	nextID      int64

	// Dernière position reçue de chaque passerelle par flux (cache de edge_log_cursors).
	cursorMu sync.Mutex
	cursors  map[string]int64

	// Durées de rétention actives (modifiables sans redémarrage).
	retentionMu         sync.RWMutex
	retentionAccessDays int
	retentionBanDays    int
	retentionSystemDays int

	// Pseudonymisation RGPD (AES-GCM). La clé reste chargée mode désactivé : les entrées
	// déjà pseudonymisées doivent rester révélables pendant leur rétention.
	pseudoMu     sync.RWMutex
	gdprKey      []byte
	pseudonymize bool
}

// PseudonymizedIP remplace l'IP d'une entrée pseudonymisée dans la colonne ip. Volontairement
// pas une IP : les Seuils multi-passerelles et la simulation Ephor, qui lisent cette colonne, l'ignorent.
const PseudonymizedIP = "[pseudonymisé]"

// Erreurs de RevealIP.
var (
	ErrEntryNotFound    = errors.New("entrée de log introuvable")
	ErrNotPseudonymized = errors.New("cette entrée n'est pas pseudonymisée")
	ErrNoGDPRKey        = errors.New("clé de pseudonymisation non chargée")
)

// New crée un Store avec les durées de rétention par défaut.
func New(db *sql.DB) *Store {
	return &Store{
		db:                  db,
		subscribers:         make(map[int64]chan Entry),
		retentionAccessDays: DefaultRetentionAccessDays,
		retentionSystemDays: DefaultRetentionSystemDays,
		retentionBanDays:    DefaultRetentionBanDays,
	}
}

// SetBanRetention met à jour la durée de conservation de l'historique des bans (0 = inchangée).
func (s *Store) SetBanRetention(days int) {
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	if days > 0 {
		s.retentionBanDays = days
	}
}

// BanRetentionDays retourne la durée de conservation active de l'historique des bans.
func (s *Store) BanRetentionDays() int {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	return s.retentionBanDays
}

// SetRetention met à jour les durées de rétention sans redémarrage.
// accessDays : logs HTTP (status > 0) ; systemDays : logs système/agent.
// Passer 0 pour laisser la valeur inchangée.
func (s *Store) SetRetention(accessDays, systemDays int) {
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	if accessDays > 0 {
		s.retentionAccessDays = accessDays
	}
	if systemDays > 0 {
		s.retentionSystemDays = systemDays
	}
}

// SetGDPRKey charge la clé AES-GCM de pseudonymisation (gdpr.EnsureKey).
func (s *Store) SetGDPRKey(key []byte) {
	s.pseudoMu.Lock()
	s.gdprKey = key
	s.pseudoMu.Unlock()
}

// SetPseudonymize active ou désactive le chiffrement de l'IP réelle reçue des passerelles.
func (s *Store) SetPseudonymize(enabled bool) {
	s.pseudoMu.Lock()
	s.pseudonymize = enabled
	s.pseudoMu.Unlock()
}

// RevealIP retourne l'IP réelle d'une entrée pseudonymisée, que le mode soit encore actif ou non.
func (s *Store) RevealIP(entryID int64) (string, error) {
	var enc string
	err := s.db.QueryRow(`SELECT ip_enc FROM logs WHERE id = ?`, entryID).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrEntryNotFound
	}
	if err != nil {
		return "", err
	}
	if enc == "" {
		return "", ErrNotPseudonymized
	}
	s.pseudoMu.RLock()
	key := s.gdprKey
	s.pseudoMu.RUnlock()
	if key == nil {
		return "", ErrNoGDPRKey
	}
	return ipcrypt.Decrypt(key, enc)
}

func (s *Store) retainedUntil(isAccess bool) time.Time {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	days := s.retentionSystemDays
	if isAccess {
		days = s.retentionAccessDays
	}
	return time.Now().UTC().AddDate(0, 0, days)
}

const insertLogSQL = `INSERT INTO logs (ts, level, component, node_name, node_id, domain, method, path, status, ip, latency_ms, bytes, message, referrer, user_id, request_id, waf_matches, threat_signal, tls_ja3, tls_ja4, retained_until, ip_enc, ip_hmac, ip_truncated)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// insertArgs complète l'entrée (date, rétention, pseudonymisation de l'IP) et retourne les paramètres de
// l'INSERT. L'entrée est modifiée : elle est ensuite diffusée telle qu'écrite.
func (s *Store) insertArgs(e *Entry) []any {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	retained := s.retainedUntil(e.Status > 0)
	e.RetainedUntil = &retained

	// Pseudonymisation : chiffrer l'IP réelle si disponible et clé chargée.
	var ipEnc, ipHmac string
	s.pseudoMu.RLock()
	key := s.gdprKey
	if !s.pseudonymize {
		key = nil
	}
	s.pseudoMu.RUnlock()
	if key != nil && e.RealIP != "" {
		if enc, err := ipcrypt.Encrypt(key, e.RealIP); err == nil {
			ipEnc = enc
			ipHmac = ipcrypt.IPIndex(key, e.RealIP)
			e.IP = PseudonymizedIP
		}
	}

	return []any{
		e.Ts.UTC().Format(time.RFC3339Nano),
		nvl(e.Level, "info"), nvl(e.Component, "admin"), e.NodeName, e.NodeID,
		e.Domain, e.Method, e.Path, e.Status, e.IP, e.LatencyMs, e.Bytes, e.Message, e.Referrer,
		e.UserID, e.RequestID, encodeWAFMatches(e.WAFMatches), e.ThreatSignal, e.TLSJA3, e.TLSJA4, retained.Format(time.RFC3339), ipEnc, ipHmac, e.IPTruncated,
	}
}

// Write insère une entrée et la diffuse aux abonnés SSE.
func (s *Store) Write(e Entry) {
	res, err := s.db.Exec(insertLogSQL, s.insertArgs(&e)...)
	if err == nil {
		if id, err2 := res.LastInsertId(); err2 == nil {
			e.ID = id
		}
	}
	s.broadcast(e)
}

// writeBatchSize borne le nombre d'entrées d'une transaction : le verrou d'écriture n'est tenu que le temps
// d'un lot, les autres écritures (battements, agrégation) passent entre deux.
const writeBatchSize = 500

// WriteBatch insère les entrées par transactions de writeBatchSize au plus, puis les diffuse. Une
// transaction par entrée coûtait un commit et une dizaine de mises à jour d'index par ligne (29 Ko écrits
// par ligne mesurés) : en lot, une page modifiée plusieurs fois n'est écrite qu'une fois par commit.
func (s *Store) WriteBatch(entries []Entry) {
	for len(entries) > 0 {
		n := min(len(entries), writeBatchSize)
		s.writeChunk(entries[:n])
		entries = entries[n:]
	}
}

func (s *Store) writeChunk(entries []Entry) {
	tx, err := s.db.Begin()
	if err != nil {
		s.writeEach(entries)
		return
	}
	stmt, err := tx.Prepare(insertLogSQL)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		s.writeEach(entries)
		return
	}
	for i := range entries {
		res, err := stmt.Exec(s.insertArgs(&entries[i])...)
		if err == nil {
			if id, err2 := res.LastInsertId(); err2 == nil {
				entries[i].ID = id
			}
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		// Rien n'est écrit : on réessaie entrée par entrée plutôt que de perdre le lot.
		s.writeEach(entries)
		return
	}
	for _, e := range entries {
		s.broadcast(e)
	}
}

func (s *Store) writeEach(entries []Entry) {
	for _, e := range entries {
		s.Write(e)
	}
}

// encodeWAFMatches/decodeWAFMatches sérialisent WAFMatches en JSON pour la colonne TEXT
// waf_matches — vide (chaîne "") pour l'immense majorité des lignes (aucun match).
func encodeWAFMatches(m []string) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

func decodeWAFMatches(s string) []string {
	if s == "" {
		return nil
	}
	var m []string
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil
	}
	return m
}

// Publish diffuse une entrée aux vues Live sans l'enregistrer : une passerelle qui n'envoie plus ses accès ordinaires
// les fait passer ainsi, à la demande.
func (s *Store) Publish(e Entry) { s.broadcast(e) }

func (s *Store) broadcast(e Entry) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe retourne un canal qui recevra les nouvelles entrées en temps réel.
// Appeler cancel pour se désabonner.
func (s *Store) Subscribe() (id int64, ch <-chan Entry, cancel func()) {
	buf := make(chan Entry, 128)
	s.mu.Lock()
	s.nextID++
	id = s.nextID
	s.subscribers[id] = buf
	s.mu.Unlock()
	return id, buf, func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		close(buf)
	}
}

// Search retourne les entrées paginées selon les filtres.
// Quand p.BeforeID > 0, la pagination est par curseur (keyset) : pas de COUNT, résultat O(1).
// Sinon, un COUNT plafonné à 10 001 est exécuté pour la première page.
// Retourne (entries, hasMore, error).
func (s *Store) Search(p SearchParams) ([]Entry, bool, error) {
	if p.PageSize <= 0 {
		p.PageSize = 50
	}
	where, args := buildWhere(p)

	var q string
	var qArgs []any
	if p.BeforeID > 0 {
		// Keyset : pas d'OFFSET, on filtre directement sur l'id.
		cursorClause := " AND id < ?"
		if where == "" {
			cursorClause = " WHERE id < ?"
		}
		q = "SELECT id, ts, level, component, COALESCE(node_name,''), COALESCE(node_id,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,''), COALESCE(waf_matches,''), COALESCE(threat_signal,''), COALESCE(tls_ja3,''), COALESCE(tls_ja4,''), ip_truncated FROM logs" +
			where + cursorClause + " ORDER BY id DESC LIMIT ?"
		qArgs = append(args, p.BeforeID, p.PageSize)
	} else {
		if p.Page <= 0 {
			p.Page = 1
		}
		offset := (p.Page - 1) * p.PageSize
		q = "SELECT id, ts, level, component, COALESCE(node_name,''), COALESCE(node_id,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,''), COALESCE(waf_matches,''), COALESCE(threat_signal,''), COALESCE(tls_ja3,''), COALESCE(tls_ja4,''), ip_truncated FROM logs" +
			where + " ORDER BY id DESC LIMIT ? OFFSET ?"
		qArgs = append(args, p.PageSize, offset)
	}

	rows, err := s.db.Query(q, qArgs...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts, wafMatches string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.NodeID, &e.Domain, &e.Method, &e.Path,
			&e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message, &e.RequestID, &wafMatches, &e.ThreatSignal, &e.TLSJA3, &e.TLSJA4, &e.IPTruncated); err != nil {
			continue
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		e.WAFMatches = decodeWAFMatches(wafMatches)
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	hasMore := len(out) == p.PageSize
	return out, hasMore, nil
}

// Export retourne les logs au format csv ou json.
func (s *Store) Export(p SearchParams, format string) ([]byte, string, error) {
	p.Page = 1
	p.PageSize = 100000
	p.BeforeID = 0
	entries, _, err := s.Search(p)
	if err != nil {
		return nil, "", err
	}
	if format == "csv" {
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"id", "ts", "level", "component", "node_name", "node_id", "domain", "method", "path", "status", "ip", "latency_ms", "bytes", "message"}) //nolint:errcheck
		for _, e := range entries {
			w.Write([]string{ //nolint:errcheck
				strconv.FormatInt(e.ID, 10),
				e.Ts.Format(time.RFC3339),
				e.Level, e.Component, e.NodeName, e.NodeID, e.Domain, e.Method, e.Path,
				strconv.Itoa(e.Status), e.IP,
				strconv.FormatInt(e.LatencyMs, 10),
				strconv.FormatInt(e.Bytes, 10),
				e.Message,
			})
		}
		w.Flush()
		return []byte(sb.String()), "text/csv", nil
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	return b, "application/json", err
}

// StreamSSE diffuse les nouvelles entrées en SSE jusqu'à la fermeture de r.Context.
func (s *Store) StreamSSE(w http.ResponseWriter, r *http.Request, filter SearchParams) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE non supporté", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	_, ch, cancel := s.Subscribe()
	defer cancel()

	// Keep-alive : évite les coupures proxy / load-balancer sur flux silencieux.
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !matchesFilter(e, filter) {
				continue
			}
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func buildWhere(p SearchParams) (string, []any) {
	var clauses []string
	var args []any
	if p.Level != "" {
		clauses = append(clauses, "level=?")
		args = append(args, p.Level)
	}
	if p.Component != "" {
		clauses = append(clauses, "component=?")
		args = append(args, p.Component)
	}
	if p.NodeID != "" {
		// NodeID est stable face à un renommage : quand il est fourni, il
		// prime sur NodeName (qui reste utilisable seul pour retrouver
		// l'historique d'un nœud renommé/disparu, cf. p.Search ci-dessous).
		if p.NodeName != "" {
			// Les logs sans node_id (ingestion HTTP, historique antérieur) restent
			// rattachés au nœud via node_name.
			clauses = append(clauses, "(node_id=? OR (node_id='' AND node_name=?))")
			args = append(args, p.NodeID, p.NodeName)
		} else {
			clauses = append(clauses, "node_id=?")
			args = append(args, p.NodeID)
		}
	} else if p.NodeName != "" {
		clauses = append(clauses, "node_name=?")
		args = append(args, p.NodeName)
	}
	if p.Domain != "" {
		clauses = append(clauses, "domain=?")
		args = append(args, p.Domain)
	}
	if p.IP != "" {
		clauses = append(clauses, "ip=?")
		args = append(args, p.IP)
	}
	if p.Method != "" {
		clauses = append(clauses, "method=?")
		args = append(args, p.Method)
	}
	if p.Status != "" {
		if lo, hi, ok := statusRange(p.Status); ok {
			clauses = append(clauses, "status >= ? AND status < ?")
			args = append(args, lo, hi)
		} else {
			clauses = append(clauses, "status=?")
			args = append(args, p.Status)
		}
	}
	// Le `!= ''` redondant prouve à SQLite que le filtre implique le WHERE de l'index partiel :
	// avec un paramètre lié il ne peut pas le déduire seul et parcourait tout idx_logs_access_id.
	if p.TLSJA3 != "" {
		clauses = append(clauses, "tls_ja3=? AND tls_ja3 != ''")
		args = append(args, p.TLSJA3)
	}
	if p.TLSJA4 != "" {
		clauses = append(clauses, "tls_ja4=? AND tls_ja4 != ''")
		args = append(args, p.TLSJA4)
	}
	if p.RequestID != "" {
		clauses = append(clauses, "request_id=?")
		args = append(args, p.RequestID)
	}
	if p.Path != "" {
		clauses = append(clauses, "path LIKE ?")
		args = append(args, "%"+p.Path+"%")
	}
	if p.Search != "" {
		// node_name est inclus pour permettre de retrouver l'historique d'un
		// nœud renommé ou disparu (le filtre dédié NodeName/NodeID exige une
		// égalité exacte sur le nœud sélectionné, alors que Search est une
		// recherche libre indépendante de tout nœud "actuel"). method/status
		// couverts aussi : la recherche libre remplace les filtres avancés
		// dédiés côté UI (une seule zone de recherche pour tout).
		clauses = append(clauses, "(message LIKE ? OR path LIKE ? OR ip LIKE ? OR domain LIKE ? OR node_name LIKE ? OR method LIKE ? OR level LIKE ? OR CAST(status AS TEXT) LIKE ?)")
		q := "%" + p.Search + "%"
		args = append(args, q, q, q, q, q, q, q, q)
	}
	if p.DateFrom != "" {
		clauses = append(clauses, "ts >= ?")
		args = append(args, p.DateFrom)
	}
	if p.DateTo != "" {
		clauses = append(clauses, "ts <= ?")
		args = append(args, p.DateTo)
	}
	switch strings.ToLower(p.Kind) {
	case "access":
		clauses = append(clauses, "status > 0")
	case "system":
		clauses = append(clauses, "status = 0")
	}
	if p.ExcludeInternal {
		clauses = append(clauses, internalIPExclusionSQL())
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// internalIPExclusionSQL exclut les plages d'IP privées/loopback (RFC 1918 + loopback +
// link-local IPv4/IPv6) par préfixe texte — pas besoin de paramètres, les préfixes sont
// des littéraux fixes, non dérivés d'une entrée utilisateur.
func internalIPExclusionSQL() string {
	prefixes := []string{"10.", "192.168.", "127.", "169.254.", "fe80:", "fc", "fd"}
	for i := 16; i <= 31; i++ {
		prefixes = append(prefixes, fmt.Sprintf("172.%d.", i))
	}
	conds := make([]string, 0, len(prefixes)+1)
	conds = append(conds, "ip != '::1'")
	for _, p := range prefixes {
		conds = append(conds, "ip NOT LIKE '"+p+"%'")
	}
	return "(" + strings.Join(conds, " AND ") + ")"
}

func matchesFilter(e Entry, p SearchParams) bool {
	if p.Level != "" && e.Level != p.Level {
		return false
	}
	if p.Component != "" && e.Component != p.Component {
		return false
	}
	if p.NodeID != "" {
		if e.NodeID != p.NodeID && !(e.NodeID == "" && p.NodeName != "" && e.NodeName == p.NodeName) {
			return false
		}
	} else if p.NodeName != "" && e.NodeName != p.NodeName {
		return false
	}
	if p.Domain != "" && e.Domain != p.Domain {
		return false
	}
	if p.IP != "" && e.IP != p.IP {
		return false
	}
	if p.Method != "" && e.Method != p.Method {
		return false
	}
	if p.Status != "" && !statusMatches(e.Status, p.Status) {
		return false
	}
	if p.Path != "" && !strings.Contains(e.Path, p.Path) {
		return false
	}
	switch strings.ToLower(p.Kind) {
	case "access":
		if e.Status <= 0 {
			return false
		}
	case "system":
		if e.Status != 0 {
			return false
		}
	}
	if p.Search != "" {
		q := strings.ToLower(p.Search)
		if !strings.Contains(strings.ToLower(e.Message), q) &&
			!strings.Contains(strings.ToLower(e.Path), q) &&
			!strings.Contains(e.IP, q) &&
			!strings.Contains(e.Domain, q) &&
			!strings.Contains(strings.ToLower(e.NodeName), q) {
			return false
		}
	}
	if p.ExcludeInternal && isInternalIP(e.IP) {
		return false
	}
	return true
}

// isInternalIP reprend les mêmes plages que internalIPExclusionSQL, pour le filtrage en
// mémoire du flux Live (StreamSSE ne repasse pas par le SQL de Search).
func isInternalIP(ip string) bool {
	if ip == "" {
		return false
	}
	if ip == "::1" {
		return true
	}
	prefixes := []string{"10.", "192.168.", "127.", "169.254.", "fe80:", "fc", "fd"}
	for i := 16; i <= 31; i++ {
		prefixes = append(prefixes, fmt.Sprintf("172.%d.", i))
	}
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

// CorrelateByRequestID retourne tous les logs portant le même request_id.
// C'est la corrélation exacte : une requête HTTP → ses logs système associés.
func (s *Store) CorrelateByRequestID(requestID string) []Entry {
	if requestID == "" {
		return []Entry{}
	}
	rows, err := s.db.Query(
		`SELECT id, ts, level, component, COALESCE(node_name,''), COALESCE(node_id,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,''), COALESCE(waf_matches,''), COALESCE(threat_signal,''), COALESCE(tls_ja3,''), COALESCE(tls_ja4,'')
		 FROM logs
		 WHERE request_id = ?
		 ORDER BY ts ASC LIMIT 200`,
		requestID)
	if err != nil {
		return []Entry{}
	}
	defer rows.Close()
	return scanEntries(rows)
}

// Correlate retourne les logs système/agent proches dans le temps pour un domaine.
// Fallback temporel utilisé quand aucun request_id n'est disponible.
// Les logs Agent stockent le nom du conteneur dans domain (pas le host proxy) :
// on matche aussi le message et des variantes du nom (dots → tirets).
func (s *Store) Correlate(domain string, at time.Time, windowSec int) []Entry {
	if windowSec <= 0 {
		windowSec = 30
	}
	from := at.Add(-time.Duration(windowSec) * time.Second).UTC().Format(time.RFC3339Nano)
	to := at.Add(time.Duration(windowSec) * time.Second).UTC().Format(time.RFC3339Nano)
	domainDash := strings.ReplaceAll(domain, ".", "-")
	domainFlat := strings.ReplaceAll(domain, ".", "")
	rows, err := s.db.Query(
		`SELECT id, ts, level, component, COALESCE(node_name,''), COALESCE(node_id,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,''), COALESCE(waf_matches,''), COALESCE(threat_signal,''), COALESCE(tls_ja3,''), COALESCE(tls_ja4,'')
		 FROM logs
		 WHERE ts BETWEEN ? AND ?
		   AND status = 0
		   AND (
		     domain = ? OR domain = '/' || ?
		     OR instr(lower(coalesce(message,'')), lower(?)) > 0
		     OR instr(lower(replace(coalesce(domain,''), '/', '')), lower(?)) > 0
		     OR instr(lower(replace(coalesce(domain,''), '/', '')), lower(?)) > 0
		     OR instr(lower(replace(coalesce(domain,''), '/', '')), lower(?)) > 0
		   )
		 ORDER BY ts DESC LIMIT 100`,
		from, to, domain, domain, domain, domain, domainDash, domainFlat)
	if err != nil {
		return []Entry{}
	}
	defer rows.Close()
	return scanEntries(rows)
}

func scanEntries(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
}) []Entry {
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts, wafMatches string
		if rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.NodeID, &e.Domain, &e.Method,
			&e.Path, &e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message, &e.RequestID, &wafMatches, &e.ThreatSignal, &e.TLSJA3, &e.TLSJA4) != nil {
			continue
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		e.WAFMatches = decodeWAFMatches(wafMatches)
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	return out
}

// StartRetentionLoop lance un nettoyage quotidien basé sur retained_until (RGPD).
// onUpdate est appelé à chaque cycle pour récupérer les durées de rétention courantes
// (accessDays, systemDays, banDays) depuis les settings — 0 = conserver la valeur actuelle.
func (s *Store) StartRetentionLoop(ctx context.Context, onUpdate func() (accessDays, systemDays, banDays int)) {
	go func() {
		purge := func() {
			if onUpdate != nil {
				a, sys, ban := onUpdate()
				s.SetRetention(a, sys)
				s.SetBanRetention(ban)
			}
			s.purgeRetained()
		}
		purge()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				purge()
			}
		}
	}()
}

// purgeRetained supprime les entrées dont la date de rétention est dépassée.
// retained_until est en RFC3339 : la borne doit l'être aussi (datetime('now') compare mal, 'T' > ' ').
func (s *Store) purgeRetained() {
	s.db.Exec(`DELETE FROM logs WHERE retained_until IS NOT NULL AND retained_until < ?`, //nolint:errcheck
		time.Now().UTC().Format(time.RFC3339))
	s.purgeIPTraces()
	s.purgeAggregates(DefaultRetentionAggDays)
	s.PurgeIPErrors(time.Now())
}

// purgeIPTraces applique la rétention aux tables qui gardent une IP hors de `logs` : l'historique
// et les bans expirés suivent la durée des bans, le cache GeoIP (IP, ville, coordonnées) celle des
// logs d'accès. Les bans encore actifs ne sont jamais purgés. security_bans.expires_at est en
// RFC3339 : sa borne doit l'être aussi ; les autres colonnes suivent CURRENT_TIMESTAMP.
func (s *Store) purgeIPTraces() {
	s.retentionMu.RLock()
	banDays, accessDays := s.retentionBanDays, s.retentionAccessDays
	s.retentionMu.RUnlock()
	s.db.Exec(`DELETE FROM security_ban_history WHERE created_at < datetime('now', ?)`, //nolint:errcheck
		fmt.Sprintf("-%d days", banDays))
	s.db.Exec(`DELETE FROM security_bans WHERE expires_at IS NOT NULL AND expires_at < ?`, //nolint:errcheck
		time.Now().UTC().AddDate(0, 0, -banDays).Format(time.RFC3339))
	s.db.Exec(`DELETE FROM geoip_cache WHERE cached_at < datetime('now', ?)`, //nolint:errcheck
		fmt.Sprintf("-%d days", accessDays))
	gdpr.PurgeEdgeErasures(s.db, edgeErasureAgeDays(s.db)) //nolint:errcheck
}

// edgeErasureAgeDays est la durée pendant laquelle un ordre d'effacement reste rejouable : la plus longue conservation
// d'accès que l'Admin impose à une passerelle (réglage commun ou exception), jamais moins que le défaut. Une passerelle
// qui garde plus longtemps par son seul edge.json n'est pas connue de l'Admin.
func edgeErasureAgeDays(db *sql.DB) int {
	days := edgeLogMaxAgeDays
	var raw string
	if db.QueryRow(`SELECT value FROM settings WHERE key = 'logs.edge_retention'`).Scan(&raw) != nil {
		return days
	}
	var r struct {
		AccessDays int `json:"access_days"`
		Nodes      map[string]struct {
			AccessDays int `json:"access_days"`
		} `json:"nodes"`
	}
	if json.Unmarshal([]byte(raw), &r) != nil {
		return days
	}
	days = max(days, r.AccessDays)
	for _, o := range r.Nodes {
		days = max(days, o.AccessDays)
	}
	return days
}

// IPErasure détaille ce qu'un effacement par IP a supprimé.
type IPErasure struct {
	Logs       int64 `json:"deleted"`
	BanHistory int64 `json:"ban_history_deleted"`
	Bans       int64 `json:"bans_deleted"`
	GeoCache   int64 `json:"geoip_cache_deleted"`
	// IPCounters compte les compteurs d'erreurs par IP que les passerelles ont envoyés pour les Seuils multi-passerelles.
	IPCounters int64 `json:"ip_counters_deleted"`
	// AuditIP compte les entrées d'audit dont l'adresse a été vidée : l'entrée (qui a fait quoi, quand)
	// reste, seule l'IP de l'acteur disparaît.
	AuditIP int64 `json:"audit_ip_cleared"`
}

// EraseIP supprime d'une IP tout ce que l'Admin en garde : logs (pseudonymisés compris), bans,
// historique des bans et cache GeoIP. Ces trois dernières tables stockent l'IP en clair.
func (s *Store) EraseIP(ip string) (IPErasure, error) {
	var out IPErasure
	var err error
	if out.Logs, err = s.DeleteByIP(ip); err != nil {
		return out, err
	}
	canon := ipcrypt.CanonicalIP(ip)
	for _, t := range []struct {
		table string
		n     *int64
	}{
		{"security_ban_history", &out.BanHistory},
		{"security_bans", &out.Bans},
		{"geoip_cache", &out.GeoCache},
		{"edge_ip_errors", &out.IPCounters},
	} {
		res, err := s.db.Exec(`DELETE FROM `+t.table+` WHERE ip IN (?, ?)`, ip, canon)
		if err != nil {
			return out, err
		}
		if *t.n, err = res.RowsAffected(); err != nil {
			return out, err
		}
	}
	res, err := s.db.Exec(`UPDATE audit_log SET ip = '' WHERE ip IN (?, ?)`, ip, canon)
	if err != nil {
		return out, err
	}
	out.AuditIP, err = res.RowsAffected()
	return out, err
}

// DeleteByIP supprime tous les logs d'une IP (droit à l'effacement RGPD), entrées
// pseudonymisées comprises. Retourne le nombre de lignes supprimées.
func (s *Store) DeleteByIP(ip string) (int64, error) {
	canon := ipcrypt.CanonicalIP(ip)
	s.pseudoMu.RLock()
	key := s.gdprKey
	s.pseudoMu.RUnlock()
	q, args := `DELETE FROM logs WHERE ip IN (?, ?)`, []any{ip, canon}
	if key != nil {
		q += ` OR ip_hmac = ?`
		args = append(args, ipcrypt.IPIndex(key, canon))
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// IPReference désigne une IP sans la révéler, pour tracer son effacement : empreinte
// ip_hmac (« hmac:… », comparable à la colonne) si la clé RGPD est chargée, sinon
// l'IP tronquée (x.x.x.0, /48 en IPv6).
func (s *Store) IPReference(ip string) string {
	s.pseudoMu.RLock()
	key := s.gdprKey
	s.pseudoMu.RUnlock()
	if key != nil {
		return "hmac:" + ipcrypt.IPIndex(key, ip)
	}
	a, err := netip.ParseAddr(ipcrypt.CanonicalIP(ip))
	if err != nil {
		return "?"
	}
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p.Addr().String()
}

// BackfillIPIndex calcule ip_hmac pour les entrées pseudonymisées avant son introduction,
// en déchiffrant ip_enc par lots. Retourne le nombre d'entrées complétées.
func (s *Store) BackfillIPIndex(ctx context.Context) (int, error) {
	s.pseudoMu.RLock()
	key := s.gdprKey
	s.pseudoMu.RUnlock()
	if key == nil {
		return 0, ErrNoGDPRKey
	}
	type row struct {
		id  int64
		enc string
	}
	var done int
	var lastID int64
	for ctx.Err() == nil {
		rows, err := s.db.QueryContext(ctx,
			`SELECT id, ip_enc FROM logs WHERE ip_enc != '' AND ip_hmac = '' AND id > ? ORDER BY id LIMIT 500`, lastID)
		if err != nil {
			return done, err
		}
		var batch []row
		for rows.Next() {
			var r row
			if rows.Scan(&r.id, &r.enc) == nil {
				batch = append(batch, r)
			}
		}
		rows.Close()
		if len(batch) == 0 {
			return done, nil
		}
		for _, r := range batch {
			lastID = r.id
			ip, err := ipcrypt.Decrypt(key, r.enc)
			if err != nil {
				continue
			}
			if _, err := s.db.ExecContext(ctx, `UPDATE logs SET ip_hmac = ? WHERE id = ?`, ipcrypt.IPIndex(key, ip), r.id); err != nil {
				return done, err
			}
			done++
		}
	}
	return done, ctx.Err()
}

// DeleteByUserID supprime tous les logs d'un utilisateur (droit à l'effacement RGPD).
// Retourne le nombre de lignes supprimées.
func (s *Store) DeleteByUserID(userID string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM logs WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RetentionInfo retourne les durées de rétention actives.
func (s *Store) RetentionInfo() (accessDays, systemDays int) {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	return s.retentionAccessDays, s.retentionSystemDays
}

func nvl(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// statusRange interprète "5xx", "5" ou "502" → [lo, hi).
func statusRange(s string) (lo, hi int, ok bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		base, err := strconv.Atoi(string(s[0]) + "00")
		if err != nil {
			return 0, 0, false
		}
		return base, base + 100, true
	}
	if len(s) == 1 && s[0] >= '1' && s[0] <= '5' {
		base := int(s[0]-'0') * 100
		return base, base + 100, true
	}
	return 0, 0, false
}

func statusMatches(code int, filter string) bool {
	if lo, hi, ok := statusRange(filter); ok {
		return code >= lo && code < hi
	}
	return strconv.Itoa(code) == filter
}

// StreamCursor retourne la dernière position reçue de la passerelle nodeID pour un flux de logs (0 : rien reçu).
func (s *Store) StreamCursor(nodeID, stream string) (int64, error) {
	key := nodeID + "\x00" + stream
	s.cursorMu.Lock()
	defer s.cursorMu.Unlock()
	if v, ok := s.cursors[key]; ok {
		return v, nil
	}
	var seq int64
	err := s.db.QueryRow(`SELECT last_seq FROM edge_log_cursors WHERE node_id = ? AND stream = ?`, nodeID, stream).Scan(&seq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if s.cursors == nil {
		s.cursors = map[string]int64{}
	}
	s.cursors[key] = seq
	return seq, nil
}

// WriteStream écrit des lignes envoyées par une passerelle et avance la position du flux jusqu'à lastSeq dans
// la même transaction : ou bien les deux sont enregistrées, ou bien aucune, et la passerelle renvoie alors les
// mêmes lignes. Les lignes sont ensuite diffusées au mode Live.
func (s *Store) WriteStream(nodeID, stream string, entries []Entry, lastSeq int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(insertLogSQL)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	defer stmt.Close()
	for i := range entries {
		res, err := stmt.Exec(s.insertArgs(&entries[i])...)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return err
		}
		if id, err2 := res.LastInsertId(); err2 == nil {
			entries[i].ID = id
		}
	}
	if err := advanceCursor(tx, nodeID, stream, lastSeq); err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.cacheCursor(nodeID, stream, lastSeq)
	for _, e := range entries {
		s.broadcast(e)
	}
	return nil
}

// ResetStreamCursor ramène à 0 la position d'un flux : la passerelle, dont la base a été remplacée, renverra tout ce que
// contient la nouvelle. C'est la seule fois qu'une position recule.
func (s *Store) ResetStreamCursor(nodeID, stream string) error {
	if _, err := s.db.Exec(`UPDATE edge_log_cursors SET last_seq = 0, updated_at = CURRENT_TIMESTAMP WHERE node_id = ? AND stream = ?`, nodeID, stream); err != nil {
		return err
	}
	s.cursorMu.Lock()
	defer s.cursorMu.Unlock()
	if s.cursors == nil {
		s.cursors = map[string]int64{}
	}
	s.cursors[nodeID+"\x00"+stream] = 0
	return nil
}

// advanceCursor fait avancer, dans la transaction du lot, la position d'un flux ; elle ne recule jamais.
func advanceCursor(tx *sql.Tx, nodeID, stream string, seq int64) error {
	_, err := tx.Exec(`INSERT INTO edge_log_cursors (node_id, stream, last_seq) VALUES (?, ?, ?)
		ON CONFLICT (node_id, stream) DO UPDATE SET last_seq = excluded.last_seq, updated_at = CURRENT_TIMESTAMP
		WHERE excluded.last_seq > last_seq`, nodeID, stream, seq)
	return err
}

func (s *Store) cacheCursor(nodeID, stream string, seq int64) {
	s.cursorMu.Lock()
	defer s.cursorMu.Unlock()
	if s.cursors == nil {
		s.cursors = map[string]int64{}
	}
	if key := nodeID + "\x00" + stream; seq > s.cursors[key] {
		s.cursors[key] = seq
	}
}

// MinuteRow est un cumul par minute reçu d'une passerelle : les colonnes de logs_minute.
type MinuteRow struct {
	Minute       string
	NodeName     string
	Domain       string
	Status       int
	Requests     int64
	Bytes        int64
	LatencyMsSum int64
	Bots         int64
}

// WriteMinutes enregistre des cumuls reçus d'une passerelle et avance la position du flux « minute » dans la même
// transaction. Un cumul remplace la valeur de sa minute au lieu de s'y ajouter : la passerelle renvoie la valeur
// à jour chaque fois qu'elle change, donc un renvoi est sans effet.
func (s *Store) WriteMinutes(nodeID string, rows []MinuteRow, lastSeq int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO logs_minute (minute, node_name, domain, status, requests, bytes, latency_ms_sum, bots)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET
			requests = excluded.requests, bytes = excluded.bytes,
			latency_ms_sum = excluded.latency_ms_sum, bots = excluded.bots`)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Minute, r.NodeName, r.Domain, r.Status, r.Requests, r.Bytes, r.LatencyMsSum, r.Bots); err != nil {
			tx.Rollback() //nolint:errcheck
			return err
		}
	}
	if err := advanceCursor(tx, nodeID, "minute", lastSeq); err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.cacheCursor(nodeID, "minute", lastSeq)
	return nil
}

// IPErrorRow est le nombre d'erreurs client d'une IP pendant une minute, reçu d'une passerelle.
type IPErrorRow struct {
	Minute string // AAAA-MM-JJTHH:MM, UTC
	IP     string
	Errors int64
}

// IPErrorsRetention : les compteurs d'erreurs par IP servent une fenêtre de quelques minutes ; une IP en clair
// ne reste pas au-delà d'un jour.
const IPErrorsRetention = 24 * time.Hour

// WriteIPErrors enregistre des compteurs d'erreurs par IP reçus d'une passerelle et avance la position du flux
// dans la même transaction. Un compteur remplace la valeur de sa minute, comme les cumuls.
func (s *Store) WriteIPErrors(nodeID string, rows []IPErrorRow, lastSeq int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO edge_ip_errors (node_id, minute, ip, errors) VALUES (?, ?, ?, ?)
		ON CONFLICT (node_id, minute, ip) DO UPDATE SET errors = excluded.errors`)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(nodeID, r.Minute, r.IP, r.Errors); err != nil {
			tx.Rollback() //nolint:errcheck
			return err
		}
	}
	if err := advanceCursor(tx, nodeID, "iperr", lastSeq); err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.cacheCursor(nodeID, "iperr", lastSeq)
	return nil
}

// PurgeIPErrors supprime les compteurs plus vieux que IPErrorsRetention.
func (s *Store) PurgeIPErrors(now time.Time) {
	cut := now.UTC().Add(-IPErrorsRetention).Format("2006-01-02T15:04")
	s.db.Exec(`DELETE FROM edge_ip_errors WHERE minute < ?`, cut) //nolint:errcheck
}
