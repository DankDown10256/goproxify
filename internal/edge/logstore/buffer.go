// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Tampon (ADR 0018) : quand l'Admin range les lignes de la passerelle et les acquitte, la base de la passerelle n'est plus
// qu'un tampon qui couvre ses coupures. Un fichier de période dont toutes les lignes sont acquittées est supprimé une fois sa
// période finie depuis Buffer.Acked ; un fichier que l'Admin n'a pas tout acquitté est gardé jusqu'à Buffer.Max, puis supprimé
// quand même (le disque d'une passerelle n'est pas celui de l'Admin).
//
// Le mode tampon ne s'applique qu'à partir du premier acquittement reçu : sans Admin qui acquitte, la rétention ordinaire
// (365 jours) reste la règle, et aucune ligne n'est supprimée plus tôt que d'habitude.

const acksFile = "acks.json"

// Buffer règle le tampon.
type Buffer struct {
	// Acked : durée de conservation d'une période dont toutes les lignes sont acquittées, comptée depuis sa fin.
	Acked time.Duration
	// Max : durée au-delà de laquelle une période est supprimée même si l'Admin n'a pas tout acquitté.
	Max time.Duration
}

type bufferState struct {
	mu   sync.Mutex
	cfg  Buffer
	acks map[string]int64
	seen bool
}

type acksDoc struct {
	Seen bool             `json:"seen"`
	Acks map[string]int64 `json:"acks"`
}

// SetBuffer règle le tampon ; une durée nulle ou négative désactive le mode.
func (s *Store) SetBuffer(b Buffer) {
	s.buf.mu.Lock()
	defer s.buf.mu.Unlock()
	if b.Acked <= 0 || b.Max <= 0 {
		s.buf.cfg = Buffer{}
		return
	}
	s.buf.cfg = b
}

// BufferActive dit si la base se comporte en tampon : réglé, et l'Admin a déjà acquitté des lignes.
func (s *Store) BufferActive() bool {
	s.buf.mu.Lock()
	defer s.buf.mu.Unlock()
	return s.buf.cfg.Acked > 0 && s.buf.seen
}

// BufferMax rend la durée maximale de conservation d'une ligne non acquittée (0 : mode non réglé).
func (s *Store) BufferMax() time.Duration {
	s.buf.mu.Lock()
	defer s.buf.mu.Unlock()
	return s.buf.cfg.Max
}

// Acked rend la position que l'Admin a acquittée pour un flux (« access », « system », « minute », « iperr »).
func (s *Store) Acked(stream string) int64 {
	s.buf.mu.Lock()
	defer s.buf.mu.Unlock()
	return s.buf.acks[stream]
}

// SetAck fixe la position acquittée d'un flux. L'Admin la donne à chaque connexion (log_resume) : elle peut reculer, quand
// son volume de logs a été remplacé, et les lignes qu'il n'a plus ne sont alors plus protégées par l'acquittement.
func (s *Store) SetAck(stream string, pos int64) { s.setAck(stream, pos, true) }

// AdvanceAck fait avancer la position acquittée d'un flux ; elle ne recule pas.
func (s *Store) AdvanceAck(stream string, pos int64) { s.setAck(stream, pos, false) }

func (s *Store) setAck(stream string, pos int64, exact bool) {
	if s.opts.ReadOnly {
		return
	}
	s.buf.mu.Lock()
	defer s.buf.mu.Unlock()
	if s.buf.acks == nil {
		s.buf.acks = map[string]int64{}
	}
	cur, had := s.buf.acks[stream]
	if had && cur == pos && s.buf.seen {
		return
	}
	if !exact && pos < cur {
		return
	}
	s.buf.acks[stream] = pos
	s.buf.seen = true
	s.saveAcksLocked()
}

// saveAcksLocked écrit les positions (buf.mu tenu) : un fichier perdu ramène au mode ordinaire, sans suppression plus tôt.
func (s *Store) saveAcksLocked() {
	raw, err := json.Marshal(acksDoc{Seen: s.buf.seen, Acks: s.buf.acks})
	if err != nil {
		return
	}
	path := filepath.Join(s.opts.Dir, acksFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		s.report(err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.report(err)
	}
}

func (s *Store) loadAcks() {
	raw, err := os.ReadFile(filepath.Join(s.opts.Dir, acksFile))
	if err != nil {
		return
	}
	var d acksDoc
	if json.Unmarshal(raw, &d) != nil {
		return
	}
	s.buf.mu.Lock()
	defer s.buf.mu.Unlock()
	s.buf.acks, s.buf.seen = d.Acks, d.Seen
	if s.buf.acks == nil {
		s.buf.acks = map[string]int64{}
	}
}

// fileLastID rend le dernier identifiant attribué dans un fichier de période (0 : aucun).
func (s *Store) fileLastID(f periodFile) int64 {
	db, err := s.open(f.kind, f.start)
	if err != nil {
		return -1
	}
	var local, counter int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM entries`).Scan(&local); err != nil {
		return -1
	}
	if db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'entries'`).Scan(&counter) == nil {
		local = max(local, counter)
	}
	if local == 0 {
		return 0
	}
	return f.index<<idShift | local
}

// fileAcked dit si l'Admin a acquitté tout ce que contient un fichier : ses lignes, et pour un fichier d'accès ses cumuls
// par minute et ses compteurs d'erreurs par IP.
func (s *Store) fileAcked(f periodFile) bool {
	last := s.fileLastID(f)
	if last < 0 || last > s.Acked(string(f.kind)) {
		return false
	}
	if f.kind != KindAccess {
		return true
	}
	s.seqMu.Lock()
	minuteMax, ipMax := s.fileMax[f.path], s.ipFileMax[f.path]
	s.seqMu.Unlock()
	return minuteMax <= s.Acked("minute") && ipMax <= s.Acked("iperr")
}

// purgeBuffer applique le tampon à un type de logs (voir le commentaire du fichier).
func (s *Store) purgeBuffer(now time.Time, kind Kind, holds []Hold) {
	s.buf.mu.Lock()
	b := s.buf.cfg
	s.buf.mu.Unlock()
	maxCutoff, ackCutoff := now.Add(-b.Max), now.Add(-b.Acked)
	for _, f := range s.files(kind) {
		if frozen(holds, kind, f.start) {
			continue
		}
		end := kind.periodEnd(f.start)
		hard := !end.After(maxCutoff)
		drop := hard || (!end.After(ackCutoff) && s.fileAcked(f))
		partial := !drop && f.start.Before(maxCutoff)
		if !drop && !partial {
			continue
		}
		// Un fichier qui va être supprimé ou entamé : les lignes qu'un gel filtré vise sont d'abord gardées. Si la copie
		// échoue, le fichier reste : mieux vaut garder trop que perdre ce qu'une procédure réclame.
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
		if drop {
			s.removeFile(f.path)
			continue
		}
		db, err := s.open(kind, f.start)
		if err != nil {
			s.report(err)
			continue
		}
		if _, err := db.Exec(`DELETE FROM entries WHERE ts < ?`, maxCutoff.UTC().Format(tsLayout)); err != nil {
			s.report(err)
		}
	}
}

// OldestUnacked rend la date de la plus ancienne ligne que l'Admin n'a pas acquittée, tous types confondus (zéro : tout est
// acquitté, ou le mode tampon n'est pas actif).
func (s *Store) OldestUnacked() time.Time {
	if !s.BufferActive() {
		return time.Time{}
	}
	var oldest time.Time
	for _, kind := range []Kind{KindAccess, KindSystem} {
		if t := s.oldestUnackedOf(kind); !t.IsZero() && (oldest.IsZero() || t.Before(oldest)) {
			oldest = t
		}
	}
	return oldest
}

func (s *Store) oldestUnackedOf(kind Kind) time.Time {
	acked := s.Acked(string(kind))
	idx, local := acked>>idShift, acked&idMask
	for _, f := range s.files(kind) {
		if f.index < idx {
			continue
		}
		db, err := s.open(kind, f.start)
		if err != nil {
			continue
		}
		var ts sql.NullString
		var qerr error
		if f.index == idx {
			qerr = db.QueryRow(`SELECT MIN(ts) FROM entries WHERE origin = '' AND id > ?`, local).Scan(&ts)
		} else {
			qerr = db.QueryRow(`SELECT MIN(ts) FROM entries WHERE origin = ''`).Scan(&ts)
		}
		if qerr != nil && !errors.Is(qerr, sql.ErrNoRows) {
			continue
		}
		if ts.Valid {
			if t, err := time.Parse(tsLayout, ts.String); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// EffectiveRetention rend la durée après laquelle des lignes peuvent disparaître : celle du tampon quand l'Admin acquitte
// les lignes (un consommateur en retard, le SIEM par exemple, doit la prendre pour repère), sinon la rétention ordinaire.
func (s *Store) EffectiveRetention(kind Kind) time.Duration {
	s.buf.mu.Lock()
	acked, active := s.buf.cfg.Acked, s.buf.cfg.Acked > 0 && s.buf.seen
	s.buf.mu.Unlock()
	if active {
		return min(acked, s.Retention(kind))
	}
	return s.Retention(kind)
}
