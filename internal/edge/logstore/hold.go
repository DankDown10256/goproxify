// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

const (
	holdsFile = "legal-holds.json"
	// heldDir contient, par gel filtré, les lignes que la rétention aurait supprimées : held/<id>/<fichier de période>.
	heldDir = "held"
)

// ErrHoldNotFound : aucun gel ne porte cet identifiant.
var ErrHoldNotFound = errors.New("gel légal introuvable")

// Hold est un gel légal sur [From, To], accès et système confondus.
//
// Sans filtre (ni IP ni domaine), la rétention ne supprime aucun fichier de période qui recoupe la plage : le fichier
// entier est gelé. Avec une IP et/ou un domaine, seules les lignes visées sont gardées : elles sont copiées dans une
// archive (held/<id>/) avant que la rétention ne supprime leur fichier, qui disparaît alors normalement avec les lignes
// des autres personnes. Les lignes gardées ne se lisent que par l'export.
type Hold struct {
	ID        string    `json:"id"`
	Reason    string    `json:"reason"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	IP        string    `json:"ip,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	By        string    `json:"by,omitempty"`
}

func (h Hold) filtered() bool { return h.IP != "" || h.Domain != "" }

func (h Hold) filter() ScanFilter {
	return ScanFilter{From: h.From, To: h.To, IP: h.IP, Domain: h.Domain}
}

func (s *Store) holdsPath() string {
	if s.opts.HoldsPath != "" {
		return s.opts.HoldsPath
	}
	return filepath.Join(s.opts.Dir, holdsFile)
}

// Holds lit les gels. Le registre est relu à chaque purge : une commande locale prend effet sans redémarrer la
// passerelle.
func (s *Store) Holds() ([]Hold, error) {
	raw, err := os.ReadFile(s.holdsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("logstore: registre des gels illisible: %w", err)
	}
	var holds []Hold
	if err := json.Unmarshal(raw, &holds); err != nil {
		return nil, fmt.Errorf("logstore: registre des gels illisible: %w", err)
	}
	return holds, nil
}

func (s *Store) saveHolds(holds []Hold) error {
	sort.Slice(holds, func(i, j int) bool { return holds[i].CreatedAt.Before(holds[j].CreatedAt) })
	raw, err := json.MarshalIndent(holds, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.holdsPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.holdsPath())
}

// AddHold pose un gel sur [From, To]. Un motif est obligatoire : le gel dit pourquoi des données personnelles
// sont gardées au-delà de la rétention. Un gel filtré copie tout de suite les lignes visées qui existent déjà.
func (s *Store) AddHold(h Hold) (Hold, error) {
	if strings.TrimSpace(h.Reason) == "" {
		return Hold{}, errors.New("un motif est obligatoire")
	}
	if h.From.IsZero() || h.To.IsZero() || h.To.Before(h.From) {
		return Hold{}, errors.New("plage de dates invalide")
	}
	if h.IP != "" {
		if _, err := netip.ParseAddr(strings.TrimSpace(h.IP)); err != nil {
			return Hold{}, ErrBadIP
		}
		h.IP = ipcrypt.CanonicalIP(h.IP)
	}
	holds, err := s.Holds()
	if err != nil {
		return Hold{}, err
	}
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	h.ID = hex.EncodeToString(b)
	h.From, h.To, h.CreatedAt = h.From.UTC(), h.To.UTC(), s.opts.Now().UTC()
	if h.filtered() {
		for _, kind := range []Kind{KindAccess, KindSystem} {
			for _, f := range s.files(kind) {
				if err := s.preserveFile(h, kind, f.start); err != nil {
					_ = os.RemoveAll(s.heldPath(h.ID))
					return Hold{}, err
				}
			}
		}
	}
	if err := s.saveHolds(append(holds, h)); err != nil {
		_ = os.RemoveAll(s.heldPath(h.ID))
		return Hold{}, err
	}
	return h, nil
}

// RemoveHold lève un gel ; la rétention reprend à la prochaine purge, et les lignes qu'un gel filtré avait gardées
// sont supprimées avec son archive.
func (s *Store) RemoveHold(id string) error {
	holds, err := s.Holds()
	if err != nil {
		return err
	}
	out := holds[:0:0]
	for _, h := range holds {
		if h.ID != id {
			out = append(out, h)
		}
	}
	if len(out) == len(holds) {
		return ErrHoldNotFound
	}
	if err := s.saveHolds(out); err != nil {
		return err
	}
	return os.RemoveAll(s.heldPath(id))
}

func (s *Store) heldPath(id string) string { return filepath.Join(s.opts.Dir, heldDir, id) }

// frozen dit si un gel sans filtre recoupe la période d'un fichier.
func frozen(holds []Hold, kind Kind, start time.Time) bool {
	for _, h := range holds {
		if !h.filtered() && overlaps(h, kind, start) {
			return true
		}
	}
	return false
}

func overlaps(h Hold, kind Kind, start time.Time) bool {
	return h.From.Before(kind.periodEnd(start)) && !h.To.Before(start)
}

const copyCols = `id, ts, level, component, domain, method, path, status, bytes, latency_ms, ip, ip_enc, ip_hmac, ip_truncated,
	user_agent, referrer, request_id, waf_matches, threat_signal, tls_ja3, tls_ja4, message`

// preserveFile copie dans l'archive du gel les lignes d'un fichier de période que le gel vise. Elle est sans effet si
// le gel ne recoupe pas la période, et rejouable : une ligne déjà copiée l'est une fois.
func (s *Store) preserveFile(h Hold, kind Kind, start time.Time) error {
	if !overlaps(h, kind, start) {
		return nil
	}
	cond, args, err := s.clause(h.filter())
	if err != nil {
		return err
	}
	src, err := s.open(kind, start)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.heldPath(h.ID), 0o700); err != nil {
		return err
	}
	dst, err := openArchive(filepath.Join(s.heldPath(h.ID), kind.fileName(start)))
	if err != nil {
		return err
	}
	defer dst.Close()
	rows, err := src.Query(`SELECT `+copyCols+` FROM entries WHERE `+cond, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	tx, err := dst.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	ins, err := tx.Prepare(`INSERT OR IGNORE INTO entries (` + copyCols + `) VALUES (?` + strings.Repeat(",?", len(cols)-1) + `)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if _, err := ins.Exec(vals...); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

// eraseHeld supprime des archives de gel les lignes d'une IP (ordre d'effacement explicite) et rend leur nombre.
func (s *Store) eraseHeld(canon, mac string) (int64, error) {
	var total int64
	for _, kind := range []Kind{KindAccess, KindSystem} {
		for _, a := range s.heldFiles(kind) {
			db, err := openArchive(a.path)
			if err != nil {
				return total, err
			}
			res, err := db.Exec(`DELETE FROM entries WHERE (ip = ? AND ip != '') OR (ip_hmac = ? AND ip_hmac != '')`, canon, mac)
			if err == nil {
				n, _ := res.RowsAffected()
				total += n
				_, _ = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
			}
			db.Close()
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// ReadHoldsFile lit un registre de gels sans ouvrir de store (liste, contrôle de l'Admin).
func ReadHoldsFile(path string) ([]Hold, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("logstore: registre des gels illisible: %w", err)
	}
	var holds []Hold
	if err := json.Unmarshal(raw, &holds); err != nil {
		return nil, fmt.Errorf("logstore: registre des gels illisible: %w", err)
	}
	return holds, nil
}

// PreserveHold copie dans l'archive du gel h les lignes visées qui existent déjà dans ce store, sans toucher au
// registre : l'Admin pose un gel dans le registre commun une fois, puis demande à chaque store de garder ses lignes.
func (s *Store) PreserveHold(h Hold) error {
	if !h.filtered() {
		return nil
	}
	for _, kind := range []Kind{KindAccess, KindSystem} {
		for _, f := range s.files(kind) {
			if err := s.preserveFile(h, kind, f.start); err != nil {
				return err
			}
		}
	}
	return nil
}

// DropHoldArchive supprime l'archive d'un gel dans ce store (gel levé, ou pose échouée).
func (s *Store) DropHoldArchive(id string) error { return os.RemoveAll(s.heldPath(id)) }
