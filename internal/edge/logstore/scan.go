// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// ErrBadIP : le filtre d'IP n'est pas une adresse.
var ErrBadIP = errors.New("adresse IP invalide")

// ScanFilter borne un export : lignes datées de From à To inclus, d'un domaine et/ou d'une IP (en clair ou
// pseudonymisée, retrouvée par son empreinte).
type ScanFilter struct {
	From, To time.Time
	Domain   string
	IP       string
	// Origin lit les lignes qu'une ancienne version a répliquées de ce pair (colonne origin) au lieu des lignes propres ; vide : les lignes propres.
	Origin string
}

// clause rend la condition SQL du filtre et ses arguments.
func (s *Store) clause(f ScanFilter) (string, []any, error) {
	query := `origin = '' AND ts >= ? AND ts <= ?`
	args := []any{f.From.UTC().Format(tsLayout), f.To.UTC().Format(tsLayout)}
	if f.Origin != "" {
		query = `origin = ? AND ts >= ? AND ts <= ?`
		args = []any{f.Origin, f.From.UTC().Format(tsLayout), f.To.UTC().Format(tsLayout)}
	}
	if f.Domain != "" {
		query += ` AND domain = ?`
		args = append(args, f.Domain)
	}
	if f.IP != "" {
		if _, err := netip.ParseAddr(strings.TrimSpace(f.IP)); err != nil {
			return "", nil, ErrBadIP
		}
		canon := ipcrypt.CanonicalIP(f.IP)
		mac := ""
		if s.key != nil {
			mac = ipcrypt.IPIndex(s.key, canon)
		}
		query += ` AND ((ip = ? AND ip != '') OR (ip_hmac = ? AND ip_hmac != ''))`
		args = append(args, canon, mac)
	}
	return query, args, nil
}

// readRows lit les lignes d'une base de période qui répondent à la condition, dans l'ordre des identifiants.
func (s *Store) readRows(db *sql.DB, index int64, cond string, args []any, fn func(Row) error) error {
	rows, err := db.Query(`SELECT `+selectCols+` FROM entries WHERE `+cond+` ORDER BY id`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r, enc, err := scanRow(rows, index)
		if err != nil {
			return err
		}
		if enc != "" && s.key != nil {
			if ip, err := ipcrypt.Decrypt(s.key, enc); err == nil {
				r.RealIP = ip
			}
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Scan appelle fn pour chaque ligne d'un type qui répond au filtre, dans l'ordre des identifiants, avec l'IP réelle
// déchiffrée dans Entry.RealIP quand la clé locale le permet. Elle lit tous les fichiers de période de la plage, sans
// pagination : c'est le chemin de l'export complet. Les lignes qu'un gel légal par IP ou domaine a gardées au-delà de
// la rétention (archives de held/) en font partie. Une erreur de fn arrête la lecture.
func (s *Store) Scan(kind Kind, f ScanFilter, fn func(Row) error) error {
	cond, args, err := s.clause(f)
	if err != nil {
		return err
	}
	inRange := func(start time.Time) bool {
		return start.Before(f.To.Add(time.Nanosecond)) && kind.periodEnd(start).After(f.From)
	}
	mains := map[int64]periodFile{}
	for _, file := range s.files(kind) {
		if inRange(file.start) {
			mains[file.index] = file
		}
	}
	archives := map[int64][]periodFile{}
	for _, a := range s.heldFiles(kind) {
		if inRange(a.start) {
			archives[a.index] = append(archives[a.index], a)
		}
	}
	indexes := make([]int64, 0, len(mains)+len(archives))
	for i := range mains {
		indexes = append(indexes, i)
	}
	for i := range archives {
		if _, ok := mains[i]; !ok {
			indexes = append(indexes, i)
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	for _, idx := range indexes {
		main, hasMain := mains[idx]
		var db *sql.DB
		if hasMain {
			if db, err = s.open(kind, main.start); err != nil {
				return err
			}
		}
		if len(archives[idx]) == 0 {
			if err := s.readRows(db, idx, cond, args, fn); err != nil {
				return err
			}
			continue
		}
		// Une période dont des lignes ont été gardées dans une archive : on réunit le fichier et les archives, sans
		// doublon (une ligne copiée y reste tant que le fichier existe), dans l'ordre des identifiants.
		seen := map[int64]bool{}
		var merged []Row
		collect := func(r Row) error {
			if !seen[r.ID] {
				seen[r.ID] = true
				merged = append(merged, r)
			}
			return nil
		}
		if hasMain {
			if err := s.readRows(db, idx, cond, args, collect); err != nil {
				return err
			}
		}
		for _, a := range archives[idx] {
			adb, err := openArchive(a.path)
			if err != nil {
				return err
			}
			err = s.readRows(adb, idx, cond, args, collect)
			adb.Close()
			if err != nil {
				return err
			}
		}
		sort.Slice(merged, func(i, j int) bool { return merged[i].ID < merged[j].ID })
		for _, r := range merged {
			if err := fn(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// openArchive ouvre une base d'archive de gel, créée au besoin.
func openArchive(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=secure_delete(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := prepareSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// heldFiles liste les archives de tous les gels pour un type de logs.
func (s *Store) heldFiles(kind Kind) []periodFile {
	dirs, err := os.ReadDir(filepath.Join(s.opts.Dir, heldDir))
	if err != nil {
		return nil
	}
	var out []periodFile
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.opts.Dir, heldDir, d.Name()))
		if err != nil {
			continue
		}
		for _, de := range files {
			k, start, ok := parseFileName(de.Name())
			if !ok || k != kind {
				continue
			}
			out = append(out, periodFile{kind: k, start: start, index: k.periodIndex(start), path: filepath.Join(s.opts.Dir, heldDir, d.Name(), de.Name())})
		}
	}
	return out
}
