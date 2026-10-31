// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// Lignes reçues d'une passerelle (ADR 0018) : l'Admin garde, pour chaque passerelle, un store de ce même moteur et
// y range les lignes qu'elle lui envoie. Une ligne reçue porte son numéro chez la passerelle (origin_id) et reste « propre »
// à ce store (origin vide) : les lectures, les classements et les exports s'appliquent donc sans changement.
//
// La position du flux (le dernier numéro reçu) est écrite dans le fichier de période qui reçoit les lignes, dans la même
// transaction : un volume restauré ne peut avoir ni trou ni doublon. La réception est de plus idempotente (index unique
// sur le numéro et la date) : un lot rejoué après une coupure n'écrit rien deux fois.

// ShippedRow est une ligne reçue : Seq est son identifiant dans la base de la passerelle, le curseur du flux.
type ShippedRow struct {
	Seq int64
	Entry
}

const insertShippedSQL = `INSERT OR IGNORE INTO entries (ts, level, component, domain, method, path, status, bytes, latency_ms,
	ip, ip_enc, ip_hmac, ip_truncated, user_agent, referrer, request_id, waf_matches, threat_signal, tls_ja3, tls_ja4, message, origin_id)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const upsertShipCursorSQL = `INSERT INTO ship_cursor (kind, seq, updated_us) VALUES (?, ?, ?)
	ON CONFLICT (kind) DO UPDATE SET seq = excluded.seq, updated_us = excluded.updated_us`

// shipState retient la position de chaque flux. updated est strictement croissant : entre deux fichiers qui portent
// chacun une position, la plus récemment écrite est la bonne (une remise à zéro, après une base remplacée, doit
// l'emporter sur la position plus haute d'un fichier plus ancien).
type shipState struct {
	loaded  map[Kind]bool
	seq     map[Kind]int64
	updated int64
}

// AddShipped range des lignes reçues d'une passerelle et fait avancer la position du flux jusqu'à last. Il rend le
// nombre de lignes nouvelles. Appelé de façon synchrone : la passerelle ne reçoit son accusé que si tout est écrit.
func (s *Store) AddShipped(kind Kind, rows []ShippedRow, last int64) (int, error) {
	if s.closed.Load() || s.opts.ReadOnly {
		return 0, ErrClosed
	}
	s.shipMu.Lock()
	defer s.shipMu.Unlock()
	if err := s.loadShipState(kind); err != nil {
		return 0, err
	}
	now := s.opts.Now()
	groups := map[time.Time][]ShippedRow{}
	for _, r := range rows {
		if r.Seq <= 0 {
			continue
		}
		if r.Ts.IsZero() {
			r.Ts = now
		}
		start := kind.periodStart(r.Ts)
		groups[start] = append(groups[start], r)
	}
	newest := kind.periodStart(now)
	starts := make([]time.Time, 0, len(groups)+1)
	for start := range groups {
		starts = append(starts, start)
		if start.After(newest) {
			newest = start
		}
	}
	if _, ok := groups[newest]; !ok {
		starts = append(starts, newest)
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].Before(starts[j]) })

	next := max(s.ship.seq[kind], last)
	var added int
	for _, start := range starts {
		n, err := s.insertShipped(kind, start, groups[start], start.Equal(newest), next)
		added += n
		if err != nil {
			return added, err
		}
	}
	s.ship.seq[kind] = next
	if added > 0 {
		s.signalChange()
	}
	return added, nil
}

// insertShipped écrit les lignes d'une période ; withCursor ajoute la position à la transaction. Seul le fichier de la
// période la plus récente la porte : si le lot en touche deux, les lignes de l'ancienne sont déjà écrites quand la
// position avance, et un échec entre les deux ne fait que rejouer des lignes que l'index unique écarte.
func (s *Store) insertShipped(kind Kind, start time.Time, rows []ShippedRow, withCursor bool, cursor int64) (int, error) {
	db, err := s.open(kind, start)
	if err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	var added int
	if len(rows) > 0 {
		stmt, err := tx.Prepare(insertShippedSQL)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		defer stmt.Close()
		for _, r := range rows {
			res, err := stmt.Exec(append(s.entryArgs(r.Entry), r.Seq)...)
			if err != nil {
				_ = tx.Rollback()
				return 0, err
			}
			n, _ := res.RowsAffected()
			added += int(n)
		}
	}
	var stamp int64
	if withCursor {
		stamp = s.nextShipStamp()
		if _, err := tx.Exec(upsertShipCursorSQL, string(kind), cursor, stamp); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, nil
}

func (s *Store) nextShipStamp() int64 {
	s.ship.updated = max(s.opts.Now().UnixMicro(), s.ship.updated+1)
	return s.ship.updated
}

// ShipCursor rend la position du flux d'un type de logs : le dernier numéro reçu de la passerelle (0 : rien reçu).
func (s *Store) ShipCursor(kind Kind) (int64, error) {
	s.shipMu.Lock()
	defer s.shipMu.Unlock()
	if err := s.loadShipState(kind); err != nil {
		return 0, err
	}
	return s.ship.seq[kind], nil
}

// ResetShipCursor ramène la position à 0 : la passerelle, dont la base a été remplacée, renvoie tout ce que contient la
// nouvelle. C'est la seule fois qu'une position recule ; les lignes de l'ancienne base restent.
func (s *Store) ResetShipCursor(kind Kind) error {
	if s.closed.Load() || s.opts.ReadOnly {
		return ErrClosed
	}
	s.shipMu.Lock()
	defer s.shipMu.Unlock()
	if err := s.loadShipState(kind); err != nil {
		return err
	}
	db, err := s.open(kind, kind.periodStart(s.opts.Now()))
	if err != nil {
		return err
	}
	if _, err := db.Exec(upsertShipCursorSQL, string(kind), 0, s.nextShipStamp()); err != nil {
		return err
	}
	s.ship.seq[kind] = 0
	return nil
}

// loadShipState lit la position de chaque fichier, la première fois (shipMu tenu). Le fichier dont la position a été
// écrite le plus récemment fait foi.
func (s *Store) loadShipState(kind Kind) error {
	if s.ship.loaded[kind] {
		return nil
	}
	if s.ship.loaded == nil {
		s.ship.loaded, s.ship.seq = map[Kind]bool{}, map[Kind]int64{}
	}
	var best, bestStamp int64
	for _, f := range s.files(kind) {
		db, err := s.open(kind, f.start)
		if err != nil {
			return err
		}
		var seq, stamp int64
		err = db.QueryRow(`SELECT seq, updated_us FROM ship_cursor WHERE kind = ?`, string(kind)).Scan(&seq, &stamp)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if stamp > bestStamp {
			best, bestStamp = seq, stamp
		}
	}
	s.ship.seq[kind] = best
	s.ship.updated = max(s.ship.updated, bestStamp)
	s.ship.loaded[kind] = true
	return nil
}

// RevealSourceIP retourne l'IP réelle d'une ligne reçue, désignée par son numéro chez la passerelle d'origine (le numéro que
// portent ses références). Entre deux bases de la même passerelle qui reprennent les mêmes numéros, la plus récente l'emporte.
func (s *Store) RevealSourceIP(kind Kind, sourceID int64) (string, error) {
	files := s.files(kind)
	for i := len(files) - 1; i >= 0; i-- {
		db, err := s.open(kind, files[i].start)
		if err != nil {
			return "", err
		}
		var enc string
		err = db.QueryRow(`SELECT ip_enc FROM entries WHERE origin = '' AND origin_id = ? ORDER BY ts DESC LIMIT 1`, sourceID).Scan(&enc)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
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

// AddImported range des lignes reprises d'un export, sans toucher à la position du flux de la passerelle : ces lignes ne
// viennent pas de son flux. Le numéro de chaque ligne (Seq) est celui que l'appelant lui donne ; la réception est idempotente
// comme celle d'un flux (index unique sur le numéro et la date).
func (s *Store) AddImported(kind Kind, rows []ShippedRow) (int, error) {
	if s.closed.Load() || s.opts.ReadOnly {
		return 0, ErrClosed
	}
	s.shipMu.Lock()
	defer s.shipMu.Unlock()
	now := s.opts.Now()
	groups := map[time.Time][]ShippedRow{}
	for _, r := range rows {
		if r.Seq <= 0 {
			continue
		}
		if r.Ts.IsZero() {
			r.Ts = now
		}
		start := kind.periodStart(r.Ts)
		groups[start] = append(groups[start], r)
	}
	var added int
	for start, group := range groups {
		n, err := s.insertShipped(kind, start, group, false, 0)
		added += n
		if err != nil {
			return added, err
		}
	}
	if added > 0 {
		s.signalChange()
	}
	return added, nil
}
