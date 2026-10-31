// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logstore est la base de logs locale de la passerelle (ADR 0012) : elle possède les lignes brutes de
// ses requêtes. Un fichier SQLite par période (semaine pour les accès, mois pour le système), écriture par lots
// sur une goroutine dédiée, rétention par suppression de fichier.
//
// Le journal ne ralentit jamais le trafic : Add ne bloque pas, et une base illisible ou un disque plein font
// perdre des lignes (comptées dans Dropped) au lieu de retarder une requête.
package logstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"

	_ "modernc.org/sqlite"
)

// Kind sépare les accès HTTP (status > 0) des logs système de la passerelle : durées de période et de
// rétention différentes.
type Kind string

const (
	KindAccess Kind = "access"
	KindSystem Kind = "system"
)

const (
	// DefaultAccessRetention : durée de conservation des données de connexion (ADR 0012).
	DefaultAccessRetention = 365 * 24 * time.Hour
	DefaultSystemRetention = 90 * 24 * time.Hour

	defaultBatchSize  = 500
	defaultFlushEvery = 250 * time.Millisecond
	defaultQueueSize  = 8192

	// tsLayout est à largeur fixe : les dates se comparent en texte, et RFC3339Nano retire les zéros finaux
	// (« .1Z » passerait pour plus tardif que « .12Z »).
	tsLayout = "2006-01-02T15:04:05.000000Z"

	idShift  = 40
	idMask   = (int64(1) << idShift) - 1
	errEvery = time.Minute
	idleFor  = 5 * time.Minute
)

var (
	ErrNotPseudonymized = errors.New("cette ligne n'est pas pseudonymisée")
	ErrNoKey            = errors.New("clé de pseudonymisation non chargée")
	ErrNotFound         = errors.New("ligne introuvable")
	ErrClosed           = errors.New("base de logs fermée")
)

// Entry est une ligne de log. Les champs d'un log système (status 0) sont surtout Level, Component, Domain et
// Message.
type Entry struct {
	Ts        time.Time
	Level     string
	Component string
	Domain    string
	Method    string
	Path      string
	Status    int
	Bytes     int64
	LatencyMs int64
	// IP est l'IP telle qu'elle doit être lisible dans la base : réelle, ou tronquée en anonymisation et en
	// pseudonymisation.
	IP string
	// RealIP est l'IP réelle à chiffrer en pseudonymisation. Elle n'est jamais écrite en clair, et ignorée si
	// la base n'a pas de clé.
	RealIP       string
	IPTruncated  bool
	UserAgent    string
	Referrer     string
	RequestID    string
	WAFMatches   []string
	ThreatSignal string
	TLSJA3       string
	TLSJA4       string
	Message      string
}

// Row est une ligne relue : ID est l'identifiant global croissant (numéro de période << 40 | rowid), le curseur
// des consommateurs.
type Row struct {
	ID int64
	Entry
	// Pseudonymized : l'IP réelle est chiffrée dans la ligne (voir RevealIP).
	Pseudonymized bool
	// SourceID : numéro de la ligne chez la passerelle qui l'a envoyée, pour une ligne reçue (store de l'Admin, ADR 0018) ; 0 sinon.
	SourceID int64
	kind   Kind // renseigné par Search, pour fusionner les types
}

// Options règle la base.
type Options struct {
	Dir string
	// IPKey chiffre l'IP réelle (ipcrypt.KeySize octets). Vide : une IP réelle fournie en plus de IP est ignorée.
	IPKey      []byte
	Retention  map[Kind]time.Duration
	BatchSize  int
	FlushEvery time.Duration
	QueueSize  int
	// OnError reçoit les échecs d'écriture, au plus un par minute.
	OnError func(error)
	Now     func() time.Time
	// HoldsPath : registre des gels légaux, quand plusieurs stores en partagent un (l'Admin en a un par passerelle, ADR 0018).
	// Vide : legal-holds.json dans Dir.
	HoldsPath string
	// ReadOnly : ouvre pour lire seulement (export local), sans goroutine d'écriture ni purge.
	ReadOnly bool
}

type item struct {
	kind Kind
	e    Entry
}

type handle struct {
	db   *sql.DB
	last time.Time
}

// Store est la base de logs de la passerelle.
type Store struct {
	opts    Options
	key     []byte
	ch      chan item
	flushCh chan chan struct{}
	stop    chan struct{}
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Uint64

	buf     bufferState // tampon (voir buffer.go)
	shipMu  sync.Mutex // sérialise la réception des lignes d'une passerelle (voir shipped.go)
	ship    shipState
	retMu   sync.RWMutex // protège opts.Retention, que SetRetention change
	mu      sync.Mutex
	handles map[string]*handle
	shut    bool // Close a fermé les fichiers : plus aucun n'est rouvert

	errMu   sync.Mutex
	lastErr time.Time

	changeMu sync.Mutex
	changed  chan struct{} // fermé à la prochaine écriture réussie, puis remplacé

	seqMu      sync.Mutex
	minuteLast int64            // dernier numéro de mise à jour de cumul attribué (voir minute.go)
	fileMax    map[string]int64 // dernier numéro de cumul de chaque fichier d'accès
	ipFileMax  map[string]int64 // idem pour les compteurs d'erreurs par IP
	ipPruned   map[string]bool  // fichiers finis dont les compteurs ont déjà été vidés
}

// Open ouvre la base dans opts.Dir et démarre l'écriture en arrière-plan.
func Open(opts Options) (*Store, error) {
	if opts.Dir == "" {
		return nil, errors.New("logstore: dossier requis")
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("logstore: mkdir: %w", err)
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = defaultFlushEvery
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	ret := map[Kind]time.Duration{KindAccess: DefaultAccessRetention, KindSystem: DefaultSystemRetention}
	for k, d := range opts.Retention {
		if d > 0 {
			ret[k] = d
		}
	}
	opts.Retention = ret

	s := &Store{
		opts:    opts,
		ch:      make(chan item, opts.QueueSize),
		flushCh: make(chan chan struct{}),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		handles: make(map[string]*handle),
		changed: make(chan struct{}),
	}
	if len(opts.IPKey) == ipcrypt.KeySize {
		s.key = opts.IPKey
	}
	if opts.ReadOnly {
		// Ni écriture, ni purge, ni cumuls : une commande locale peut lire la base d'une passerelle en marche sans
		// appliquer une rétention qui serait celle de sa propre configuration.
		close(s.done)
		return s, nil
	}
	s.loadAcks()
	s.scanMinuteMax()
	go s.run()
	return s, nil
}

// Add met une ligne en file d'écriture sans bloquer. false : la ligne est perdue (file pleine, base fermée).
func (s *Store) Add(kind Kind, e Entry) bool {
	if s.closed.Load() || s.opts.ReadOnly {
		return false
	}
	select {
	case s.ch <- item{kind: kind, e: e}:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

// Dropped compte les lignes perdues depuis l'ouverture.
func (s *Store) Dropped() uint64 { return s.dropped.Load() }

// Changed retourne un canal fermé à la prochaine écriture réussie. Un consommateur le demande avant de lire :
// une écriture survenue pendant sa lecture ferme alors le canal déjà obtenu, et il relit sans rien manquer.
func (s *Store) Changed() <-chan struct{} {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	return s.changed
}

func (s *Store) signalChange() {
	s.changeMu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.changeMu.Unlock()
}

// Flush écrit ce qui est en attente et rend la main une fois les lignes sur disque.
func (s *Store) Flush() {
	if s.closed.Load() {
		return
	}
	ack := make(chan struct{})
	select {
	case s.flushCh <- ack:
		<-ack
	case <-s.done:
	}
}

// Close écrit ce qui reste et ferme les fichiers.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shut = true
	var first error
	for name, h := range s.handles {
		if err := closeHandle(h); err != nil && first == nil {
			first = err
		}
		delete(s.handles, name)
	}
	return first
}

func (s *Store) run() {
	defer close(s.done)
	batch := make([]item, 0, s.opts.BatchSize)
	tick := time.NewTicker(s.opts.FlushEvery)
	defer tick.Stop()
	maint := time.NewTicker(time.Minute)
	defer maint.Stop()
	lastPurge := time.Time{}

	flush := func() {
		if len(batch) > 0 {
			s.write(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case it := <-s.ch:
			batch = append(batch, it)
			if len(batch) >= s.opts.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case ack := <-s.flushCh:
			s.drain(&batch)
			flush()
			close(ack)
		case <-maint.C:
			now := s.opts.Now()
			s.closeIdle(now)
			if now.Sub(lastPurge) >= time.Hour {
				lastPurge = now
				s.Purge(now)
			}
		case <-s.stop:
			s.drain(&batch)
			flush()
			return
		}
	}
}

// drain reprend sans attendre ce qui est déjà dans la file.
func (s *Store) drain(batch *[]item) {
	for {
		select {
		case it := <-s.ch:
			*batch = append(*batch, it)
		default:
			return
		}
	}
}

type groupKey struct {
	kind  Kind
	start time.Time
}

// write répartit un lot sur les fichiers de période de ses lignes et l'écrit, une transaction par fichier.
func (s *Store) write(batch []item) {
	now := s.opts.Now()
	groups := map[groupKey][]Entry{}
	var order []groupKey
	for _, it := range batch {
		if it.e.Ts.IsZero() {
			it.e.Ts = now
		}
		k := groupKey{it.kind, it.kind.periodStart(it.e.Ts)}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], it.e)
	}
	for _, k := range order {
		entries := groups[k]
		if err := s.insert(k.kind, k.start, entries); err != nil {
			s.dropped.Add(uint64(len(entries)))
			s.report(err)
			continue
		}
		s.signalChange()
	}
}

const insertSQL = `INSERT INTO entries (ts, level, component, domain, method, path, status, bytes, latency_ms,
	ip, ip_enc, ip_hmac, ip_truncated, user_agent, referrer, request_id, waf_matches, threat_signal, tls_ja3, tls_ja4, message)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func (s *Store) insert(kind Kind, start time.Time, entries []Entry) error {
	db, err := s.open(kind, start)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(s.entryArgs(e)...); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	var minuteMax, ipMax int64
	if kind == KindAccess {
		var err error
		if minuteMax, err = upsertMinutes(tx, s, entries); err != nil {
			_ = tx.Rollback()
			return err
		}
		if ipMax, err = upsertIPErrors(tx, s, entries); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	path := filepath.Join(s.opts.Dir, kind.fileName(start))
	if minuteMax > 0 {
		s.noteMinuteMax(path, minuteMax)
	}
	if ipMax > 0 {
		s.noteIPErrorsMax(path, ipMax)
	}
	return nil
}

// entryArgs rend les valeurs d'une ligne dans l'ordre d'insertSQL. L'IP réelle est chiffrée avec la clé de cette
// passerelle, jamais écrite en clair.
func (s *Store) entryArgs(e Entry) []any {
	var enc, mac string
	if e.RealIP != "" && s.key != nil {
		if c, err := ipcrypt.Encrypt(s.key, ipcrypt.CanonicalIP(e.RealIP)); err == nil {
			enc, mac = c, ipcrypt.IPIndex(s.key, e.RealIP)
		}
	}
	waf := ""
	if len(e.WAFMatches) > 0 {
		if b, err := json.Marshal(e.WAFMatches); err == nil {
			waf = string(b)
		}
	}
	return []any{e.Ts.UTC().Format(tsLayout), e.Level, e.Component, e.Domain, e.Method, e.Path,
		e.Status, e.Bytes, e.LatencyMs, ipcrypt.CanonicalIP(e.IP), enc, mac, boolInt(e.IPTruncated),
		e.UserAgent, e.Referrer, e.RequestID, waf, e.ThreatSignal, e.TLSJA3, e.TLSJA4, e.Message}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// report remonte une erreur d'écriture, au plus une par minute : un disque plein échouerait à chaque lot.
func (s *Store) report(err error) {
	if s.opts.OnError == nil {
		return
	}
	s.errMu.Lock()
	now := s.opts.Now()
	if now.Sub(s.lastErr) < errEvery {
		s.errMu.Unlock()
		return
	}
	s.lastErr = now
	s.errMu.Unlock()
	s.opts.OnError(err)
}

// --- Fichiers de période -------------------------------------------------------------------------------

// periodStart retourne le début (UTC) de la période de t : lundi 00:00 pour les accès, le 1er du mois pour le
// système.
func (k Kind) periodStart(t time.Time) time.Time {
	t = t.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if k == KindSystem {
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
}

func (k Kind) periodEnd(start time.Time) time.Time {
	if k == KindSystem {
		return start.AddDate(0, 1, 0)
	}
	return start.AddDate(0, 0, 7)
}

// periodIndex numérote les périodes de façon croissante : c'est la partie haute de l'identifiant global.
func (k Kind) periodIndex(start time.Time) int64 {
	if k == KindSystem {
		return int64(start.Year()-1970)*12 + int64(start.Month()) - 1
	}
	// L'époque Unix est un jeudi : +3 jours aligne les semaines sur le lundi.
	return (start.Unix()/86400 + 3) / 7
}

func (k Kind) fileName(start time.Time) string {
	if k == KindSystem {
		return "system-" + start.Format("2006-01") + ".db"
	}
	return "access-" + start.Format("2006-01-02") + ".db"
}

// parseFileName reconnaît un fichier de période de la base.
func parseFileName(name string) (Kind, time.Time, bool) {
	if !strings.HasSuffix(name, ".db") {
		return "", time.Time{}, false
	}
	base := strings.TrimSuffix(name, ".db")
	switch {
	case strings.HasPrefix(base, "access-"):
		t, err := time.Parse("2006-01-02", strings.TrimPrefix(base, "access-"))
		if err == nil && KindAccess.periodStart(t).Equal(t) {
			return KindAccess, t, true
		}
	case strings.HasPrefix(base, "system-"):
		t, err := time.Parse("2006-01", strings.TrimPrefix(base, "system-"))
		if err == nil {
			return KindSystem, t, true
		}
	}
	return "", time.Time{}, false
}

type periodFile struct {
	kind  Kind
	start time.Time
	index int64
	path  string
}

// files liste les fichiers de période d'un type, du plus ancien au plus récent.
func (s *Store) files(kind Kind) []periodFile {
	dirEntries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return nil
	}
	var out []periodFile
	for _, de := range dirEntries {
		k, start, ok := parseFileName(de.Name())
		if !ok || k != kind {
			continue
		}
		out = append(out, periodFile{kind: k, start: start, index: k.periodIndex(start), path: filepath.Join(s.opts.Dir, de.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].index < out[j].index })
	return out
}

// AUTOINCREMENT : un identifiant n'est jamais réattribué après une suppression (effacement RGPD d'une ligne de queue,
// purge) ; sans cela un consommateur dont le curseur a dépassé la ligne supprimée sauterait la ligne qui la remplace.
const schema = `CREATE TABLE IF NOT EXISTS entries (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ts           TEXT NOT NULL,
	level        TEXT NOT NULL DEFAULT '',
	component    TEXT NOT NULL DEFAULT '',
	domain       TEXT NOT NULL DEFAULT '',
	method       TEXT NOT NULL DEFAULT '',
	path         TEXT NOT NULL DEFAULT '',
	status       INTEGER NOT NULL DEFAULT 0,
	bytes        INTEGER NOT NULL DEFAULT 0,
	latency_ms   INTEGER NOT NULL DEFAULT 0,
	ip           TEXT NOT NULL DEFAULT '',
	ip_enc       TEXT NOT NULL DEFAULT '',
	ip_hmac      TEXT NOT NULL DEFAULT '',
	ip_truncated INTEGER NOT NULL DEFAULT 0,
	user_agent   TEXT NOT NULL DEFAULT '',
	referrer     TEXT NOT NULL DEFAULT '',
	request_id   TEXT NOT NULL DEFAULT '',
	waf_matches  TEXT NOT NULL DEFAULT '',
	threat_signal TEXT NOT NULL DEFAULT '',
	tls_ja3      TEXT NOT NULL DEFAULT '',
	tls_ja4      TEXT NOT NULL DEFAULT '',
	message      TEXT NOT NULL DEFAULT '',
	origin       TEXT NOT NULL DEFAULT '',
	origin_id    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries (ts);
CREATE INDEX IF NOT EXISTS idx_entries_domain_ts ON entries (domain, ts);
CREATE INDEX IF NOT EXISTS idx_entries_ip ON entries (ip) WHERE ip != '';
CREATE INDEX IF NOT EXISTS idx_entries_ip_hmac ON entries (ip_hmac) WHERE ip_hmac != '';
CREATE INDEX IF NOT EXISTS idx_entries_request_id ON entries (request_id) WHERE request_id != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_shipped ON entries (origin_id, ts) WHERE origin = '' AND origin_id > 0;
CREATE TABLE IF NOT EXISTS ship_cursor (
	kind       TEXT    PRIMARY KEY,
	seq        INTEGER NOT NULL,
	updated_us INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS minute (
	minute         TEXT    NOT NULL,
	domain         TEXT    NOT NULL DEFAULT '',
	status         INTEGER NOT NULL,
	requests       INTEGER NOT NULL,
	bytes          INTEGER NOT NULL DEFAULT 0,
	latency_ms_sum INTEGER NOT NULL DEFAULT 0,
	bots           INTEGER NOT NULL DEFAULT 0,
	updated_us     INTEGER NOT NULL,
	PRIMARY KEY (minute, domain, status)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_minute_updated ON minute (updated_us);
CREATE TABLE IF NOT EXISTS ip_errors (
	minute     TEXT    NOT NULL,
	ip         TEXT    NOT NULL,
	errors     INTEGER NOT NULL,
	updated_us INTEGER NOT NULL,
	PRIMARY KEY (minute, ip)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ip_errors_updated ON ip_errors (updated_us);`

// open retourne la base d'une période, créée au besoin. secure_delete efface le contenu des pages supprimées
// (effacement RGPD, purge d'un fichier à cheval sur la limite).
func (s *Store) open(kind Kind, start time.Time) (*sql.DB, error) {
	path := filepath.Join(s.opts.Dir, kind.fileName(start))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shut {
		return nil, ErrClosed
	}
	if h, ok := s.handles[path]; ok {
		h.last = s.opts.Now()
		return h.db, nil
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=secure_delete(ON)")
	if err != nil {
		return nil, fmt.Errorf("logstore: open %s: %w", filepath.Base(path), err)
	}
	db.SetMaxOpenConns(4)
	if err := prepareSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("logstore: schéma %s: %w", filepath.Base(path), err)
	}
	s.handles[path] = &handle{db: db, last: s.opts.Now()}
	return db, nil
}

// prepareSchema crée le schéma d'un fichier de période. Un fichier écrit avant la réplication entre pairs n'a pas les
// colonnes d'origine : elles sont ajoutées avant les index qui s'en servent.
func prepareSchema(db *sql.DB) error {
	var cols, hasOrigin int
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(name = 'origin'), 0) FROM pragma_table_info('entries')`).Scan(&cols, &hasOrigin); err != nil {
		return err
	}
	if cols > 0 && hasOrigin == 0 {
		if _, err := db.Exec(`ALTER TABLE entries ADD COLUMN origin TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		if _, err := db.Exec(`ALTER TABLE entries ADD COLUMN origin_id INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	_, err := db.Exec(schema)
	return err
}

func closeHandle(h *handle) error {
	_, _ = h.db.Exec(`PRAGMA optimize`)
	return h.db.Close()
}

// closeIdle ferme les fichiers que personne n'a utilisés depuis un moment : seul le fichier courant reste ouvert.
func (s *Store) closeIdle(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, h := range s.handles {
		if now.Sub(h.last) > idleFor {
			_ = closeHandle(h)
			delete(s.handles, name)
		}
	}
}

// --- Lecture --------------------------------------------------------------------------------------------

const selectCols = `id, ts, level, component, domain, method, path, status, bytes, latency_ms, ip, ip_enc, ip_truncated,
	user_agent, referrer, request_id, waf_matches, threat_signal, tls_ja3, tls_ja4, message, origin_id`

// ReadAfter retourne jusqu'à limit lignes d'identifiant supérieur à after, dans l'ordre : le curseur d'un
// consommateur (rejeu vers l'Admin, SIEM). after = 0 : depuis le début.
func (s *Store) ReadAfter(kind Kind, after int64, limit int) ([]Row, error) {
	rows, _, err := s.readAfter(kind, after, limit, false, false)
	return rows, err
}

// LastID rend le dernier identifiant attribué pour un type de logs (0 : aucune ligne n'a jamais été écrite). C'est le
// compteur d'AUTOINCREMENT du dernier fichier qui en a écrit, donc il ne recule pas quand des lignes sont supprimées :
// un consommateur dont le curseur le dépasse a été servi par une autre base que celle-ci (remplacée ou restaurée).
// Un fichier créé avant l'AUTOINCREMENT n'a pas même la table sqlite_sequence : MAX(id) le remplace, sinon sa fin
// passerait pour 0.
func (s *Store) LastID(kind Kind) int64 {
	files := s.files(kind)
	for i := len(files) - 1; i >= 0; i-- {
		f := files[i]
		db, err := s.open(kind, f.start)
		if err != nil {
			continue
		}
		var local, counter int64
		if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM entries`).Scan(&local); err != nil {
			continue
		}
		if db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'entries'`).Scan(&counter) == nil {
			local = max(local, counter)
		}
		if local == 0 {
			continue
		}
		return f.index<<idShift | local
	}
	return 0
}

// ReadSecurityAfter lit comme ReadAfterRevealed mais ne rend que les événements de sécurité (accès signalés par le
// WAF ou Ephor). through est la position jusqu'où l'on a regardé : la dernière ligne rendue si le lot est plein,
// sinon la fin de la base au début de la lecture. Le consommateur y avance son curseur, ce qui lui évite de relire
// les lignes ordinaires qu'on a écartées.
func (s *Store) ReadSecurityAfter(kind Kind, after int64, limit int) (rows []Row, through int64, err error) {
	return s.readAfter(kind, after, limit, true, true)
}

// ReadAfterRevealed lit comme ReadAfter et déchiffre l'IP réelle des lignes pseudonymisées dans Entry.RealIP :
// pour le flux vers l'Admin, qui la chiffre encore de son côté tant qu'il garde les accès.
func (s *Store) ReadAfterRevealed(kind Kind, after int64, limit int) ([]Row, error) {
	rows, _, err := s.readAfter(kind, after, limit, true, false)
	return rows, err
}

func (s *Store) readAfter(kind Kind, after int64, limit int, reveal, securityOnly bool) ([]Row, int64, error) {
	if limit <= 0 {
		return nil, after, nil
	}
	// En mode sécurité, la lecture s'arrête à la fin de la base telle qu'elle était au début : through peut alors
	// dire sans risque que tout ce qui précède a été examiné, même si des lignes arrivent pendant la lecture.
	var upTo int64
	if securityOnly {
		upTo = s.LastID(kind)
	}
	startIdx, localAfter := after>>idShift, after&idMask
	var out []Row
	for _, f := range s.files(kind) {
		if f.index < startIdx {
			continue
		}
		if securityOnly && f.index > upTo>>idShift {
			break
		}
		la := int64(0)
		if f.index == startIdx {
			la = localAfter
		}
		db, err := s.open(kind, f.start)
		if err != nil {
			return out, after, err
		}
		// Les lignes répliquées d'un pair ne sortent pas d'ici : l'Admin, le SIEM et les pairs lisent ce que cette
		// passerelle a écrit, sans quoi une ligne serait comptée et exportée une fois par membre du groupe.
		query, args := `SELECT `+selectCols+` FROM entries WHERE origin = '' AND id > ?`, []any{la}
		if securityOnly {
			if f.index == upTo>>idShift {
				query += ` AND id <= ?`
				args = append(args, upTo&idMask)
			}
			query += ` AND (waf_matches != '' OR threat_signal != '')`
		}
		rows, err := db.Query(query+` ORDER BY id LIMIT ?`, append(args, limit-len(out))...)
		if err != nil {
			return out, after, err
		}
		for rows.Next() {
			r, enc, err := scanRow(rows, f.index)
			if err != nil {
				rows.Close()
				return out, after, err
			}
			if reveal && enc != "" && s.key != nil {
				if ip, err := ipcrypt.Decrypt(s.key, enc); err == nil {
					r.RealIP = ip
				}
			}
			out = append(out, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, after, err
		}
		if len(out) >= limit {
			break
		}
	}
	through := after
	switch {
	case len(out) >= limit:
		through = out[len(out)-1].ID
	case securityOnly && upTo > after:
		through = upTo
	case len(out) > 0:
		through = out[len(out)-1].ID
	}
	return out, through, nil
}

func scanRow(rows *sql.Rows, index int64) (Row, string, error) {
	var r Row
	var ts, enc, waf string
	var local int64
	var trunc int
	if err := rows.Scan(&local, &ts, &r.Level, &r.Component, &r.Domain, &r.Method, &r.Path, &r.Status, &r.Bytes,
		&r.LatencyMs, &r.IP, &enc, &trunc, &r.UserAgent, &r.Referrer, &r.RequestID, &waf, &r.ThreatSignal,
		&r.TLSJA3, &r.TLSJA4, &r.Message, &r.SourceID); err != nil {
		return r, "", err
	}
	r.ID = index<<idShift | local
	r.Ts, _ = time.Parse(tsLayout, ts)
	r.IPTruncated = trunc != 0
	r.Pseudonymized = enc != ""
	if waf != "" {
		_ = json.Unmarshal([]byte(waf), &r.WAFMatches)
	}
	return r, enc, nil
}

// RevealIP retourne l'IP réelle d'une ligne pseudonymisée.
func (s *Store) RevealIP(kind Kind, id int64) (string, error) {
	idx, local := id>>idShift, id&idMask
	for _, f := range s.files(kind) {
		if f.index != idx {
			continue
		}
		db, err := s.open(kind, f.start)
		if err != nil {
			return "", err
		}
		var enc string
		if err := db.QueryRow(`SELECT ip_enc FROM entries WHERE id = ?`, local).Scan(&enc); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", ErrNotFound
			}
			return "", err
		}
		if enc == "" {
			return "", ErrNotPseudonymized
		}
		if s.key == nil {
			return "", ErrNoKey
		}
		return ipcrypt.Decrypt(s.key, enc)
	}
	return "", ErrNotFound
}

// --- Effacement et rétention ----------------------------------------------------------------------------

// EraseIP supprime des accès et des logs système les lignes d'une IP, qu'elle soit en clair ou pseudonymisée (droit
// à l'effacement RGPD), et retourne leur nombre. Le contenu supprimé est effacé des pages (secure_delete) et du journal WAL.
func (s *Store) EraseIP(ip string) (int64, error) {
	canon := ipcrypt.CanonicalIP(ip)
	if canon == "" {
		return 0, nil
	}
	mac := ""
	if s.key != nil {
		mac = ipcrypt.IPIndex(s.key, canon)
	}
	var total int64
	var files []periodFile
	files = append(files, s.files(KindAccess)...)
	files = append(files, s.files(KindSystem)...)
	for _, f := range files {
		db, err := s.open(f.kind, f.start)
		if err != nil {
			return total, err
		}
		res, err := db.Exec(`DELETE FROM entries WHERE (ip = ? AND ip != '') OR (ip_hmac = ? AND ip_hmac != '')`, canon, mac)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		m, err := db.Exec(`DELETE FROM ip_errors WHERE ip = ?`, canon)
		if err != nil {
			return total, err
		}
		k, _ := m.RowsAffected()
		if n+k > 0 {
			_, _ = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		}
	}
	// Un ordre d'effacement vaut aussi pour les lignes qu'un gel filtré a gardées.
	n, err := s.eraseHeld(canon, mac)
	return total + n, err
}

// Purge applique la rétention : un fichier dont la période est finie depuis plus que la durée est supprimé ;
// dans le fichier à cheval sur la limite, les lignes plus anciennes sont supprimées une à une.
func (s *Store) Purge(now time.Time) {
	s.pruneIPErrors(now)
	holds, err := s.Holds()
	if err != nil {
		// Un registre de gels illisible ne doit jamais valoir « aucun gel » : rien n'est purgé tant qu'il l'est.
		s.report(err)
		return
	}
	for _, kind := range []Kind{KindAccess, KindSystem} {
		if s.BufferActive() {
			s.purgeBuffer(now, kind, holds)
			continue
		}
		cutoff := now.Add(-s.Retention(kind))
		for _, f := range s.files(kind) {
			if frozen(holds, kind, f.start) {
				continue
			}
			// Un fichier qui va être supprimé ou entamé : les lignes qu'un gel filtré vise sont d'abord gardées. Si la copie
			// échoue, le fichier reste : mieux vaut garder trop que perdre ce qu'une procédure réclame.
			if end := kind.periodEnd(f.start); !end.After(cutoff) || f.start.Before(cutoff) {
				kept := true
				for _, h := range holds {
					if h.filtered() {
						if err := s.preserveFile(h, kind, f.start); err != nil {
							s.report(err)
							kept = false
							break
						}
					}
				}
				if !kept {
					continue
				}
			}
			switch end := kind.periodEnd(f.start); {
			case !end.After(cutoff):
				s.removeFile(f.path)
			case f.start.Before(cutoff):
				db, err := s.open(kind, f.start)
				if err != nil {
					s.report(err)
					continue
				}
				if _, err := db.Exec(`DELETE FROM entries WHERE ts < ?`, cutoff.UTC().Format(tsLayout)); err != nil {
					s.report(err)
				}
			}
		}
	}
}

func (s *Store) removeFile(path string) {
	s.mu.Lock()
	if h, ok := s.handles[path]; ok {
		_ = closeHandle(h)
		delete(s.handles, path)
	}
	s.mu.Unlock()
	s.seqMu.Lock()
	delete(s.fileMax, path)
	delete(s.ipFileMax, path)
	delete(s.ipPruned, path)
	s.seqMu.Unlock()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			s.report(err)
		}
	}
}

// Retention rend la durée de conservation d'un type de logs.
func (s *Store) Retention(kind Kind) time.Duration {
	s.retMu.RLock()
	defer s.retMu.RUnlock()
	return s.opts.Retention[kind]
}

// SetRetention change la durée de conservation d'un type de logs ; la prochaine purge (toutes les heures) l'applique.
// Une durée nulle ou négative est ignorée.
func (s *Store) SetRetention(kind Kind, d time.Duration) {
	if d <= 0 {
		return
	}
	s.retMu.Lock()
	defer s.retMu.Unlock()
	s.opts.Retention[kind] = d
}

// PositionAt rend la position juste avant la première ligne d'un type dont la date est t ou plus : un consommateur
// qui y part lit tout ce qui date de t ou après. 0 : depuis le début. À la fin de la base (rien d'aussi récent),
// la dernière position.
func (s *Store) PositionAt(kind Kind, t time.Time) int64 {
	cut := t.UTC().Format(tsLayout)
	for _, f := range s.files(kind) {
		db, err := s.open(kind, f.start)
		if err != nil {
			continue
		}
		var first sql.NullInt64
		if db.QueryRow(`SELECT MIN(id) FROM entries WHERE ts >= ?`, cut).Scan(&first) != nil || !first.Valid {
			continue
		}
		return f.index<<idShift | (first.Int64 - 1)
	}
	return s.LastID(kind)
}
