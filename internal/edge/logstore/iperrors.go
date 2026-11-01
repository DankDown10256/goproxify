// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"database/sql"
	"sort"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// IPErrorsRetention : durée de conservation des compteurs d'erreurs par IP. Ils servent les Seuils multi-passerelles de
// l'Admin, dont la fenêtre se compte en minutes : au-delà de quelques heures ce serait de l'IP gardée pour rien.
const IPErrorsRetention = 48 * time.Hour

// IPErrorRow est le nombre d'erreurs client (4xx hors 404) d'une IP pendant une minute.
type IPErrorRow struct {
	Minute string // AAAA-MM-JJTHH:MM, UTC
	IP     string
	Errors int64
	// Seq croît à chaque mise à jour de la ligne : le curseur du flux, comme pour MinuteRow.
	Seq int64
}

type ipErrorKey struct{ minute, ip string }

// isClientError dit si un accès compte pour les Seuils multi-passerelles : une erreur CLIENT (4xx hors 404). Les 5xx sont des
// erreurs de backend, pas un abus ; une IP tronquée ne désigne personne.
func isClientError(e *Entry) bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != 404 && e.IP != "" && !e.IPTruncated
}

// upsertIPErrors ajoute les erreurs client du lot aux compteurs de leur minute, dans la transaction des lignes.
func upsertIPErrors(tx *sql.Tx, s *Store, entries []Entry) (maxSeq int64, err error) {
	agg := map[ipErrorKey]int64{}
	for i := range entries {
		e := &entries[i]
		if !isClientError(e) {
			continue
		}
		agg[ipErrorKey{e.Ts.UTC().Format(minuteLayout), ipcrypt.CanonicalIP(e.IP)}]++
	}
	if len(agg) == 0 {
		return 0, nil
	}
	keys := make([]ipErrorKey, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].minute < keys[j].minute })
	seq := s.nextMinuteSeqs(len(keys))
	stmt, err := tx.Prepare(`INSERT INTO ip_errors (minute, ip, errors, updated_us) VALUES (?, ?, ?, ?)
		ON CONFLICT (minute, ip) DO UPDATE SET errors = errors + excluded.errors, updated_us = excluded.updated_us`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for i, k := range keys {
		if _, err := stmt.Exec(k.minute, k.ip, agg[k], seq+int64(i)); err != nil {
			return 0, err
		}
	}
	return seq + int64(len(keys)) - 1, nil
}

// ReadIPErrorsAfter retourne jusqu'à limit compteurs mis à jour après after, dans l'ordre des mises à jour : même
// contrat que ReadMinutesAfter.
func (s *Store) ReadIPErrorsAfter(after int64, limit int) ([]IPErrorRow, error) {
	if limit <= 0 {
		return nil, nil
	}
	var all []IPErrorRow
	for _, f := range s.files(KindAccess) {
		s.seqMu.Lock()
		changed := s.ipFileMax[f.path] > after
		s.seqMu.Unlock()
		if !changed {
			continue
		}
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			return nil, err
		}
		rows, err := db.Query(`SELECT minute, ip, errors, updated_us FROM ip_errors WHERE updated_us > ? ORDER BY updated_us LIMIT ?`, after, limit)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r IPErrorRow
			if err := rows.Scan(&r.Minute, &r.IP, &r.Errors, &r.Seq); err != nil {
				rows.Close()
				return nil, err
			}
			all = append(all, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (s *Store) noteIPErrorsMax(path string, seq int64) {
	s.seqMu.Lock()
	if s.ipFileMax != nil && seq > s.ipFileMax[path] {
		s.ipFileMax[path] = seq
	}
	s.seqMu.Unlock()
}

// pruneIPErrors supprime les compteurs plus vieux que IPErrorsRetention. Un fichier dont la période est finie
// depuis plus longtemps n'est plus alimenté : il n'est vidé qu'une fois par exécution.
func (s *Store) pruneIPErrors(now time.Time) {
	cutoff := now.Add(-IPErrorsRetention)
	cut := cutoff.UTC().Format(minuteLayout)
	for _, f := range s.files(KindAccess) {
		over := !KindAccess.periodEnd(f.start).After(cutoff)
		s.seqMu.Lock()
		done := s.ipPruned[f.path]
		s.seqMu.Unlock()
		if over && done {
			continue
		}
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			s.report(err)
			continue
		}
		if _, err := db.Exec(`DELETE FROM ip_errors WHERE minute < ?`, cut); err != nil {
			s.report(err)
			continue
		}
		if over {
			s.seqMu.Lock()
			s.ipPruned[f.path] = true
			s.seqMu.Unlock()
		}
	}
}
