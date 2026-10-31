// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgelogs

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// ImportedIDBase décale les numéros des lignes reprises d'un export. Une ligne reprise garde son numéro d'origine (celui de la
// base d'où elle vient, souvent remplacée depuis), qui peut être le même que celui d'une ligne que la passerelle a envoyée
// depuis : sans décalage, une référence de ligne désignerait deux lignes, et une révélation d'IP la mauvaise. Les numéros
// ordinaires sont bien en dessous (période << 40, plus un numéro de ligne).
const ImportedIDBase int64 = 1 << 60

// ImportReport dit ce qu'une reprise a lu et rangé.
type ImportReport struct {
	Node     string
	Kind     string
	Read     int // lignes de l'export
	Added    int // lignes nouvelles (0 si la reprise a déjà eu lieu)
	Skipped  int // lignes sans numéro d'origine lisible
	FirstTS  string
	LastTS   string
	FromNode string // passerelle du manifeste (celle qui a exporté)
}

const importBatch = 1000

// ImportExport verse dans le store de la passerelle node (nom ou identifiant) les lignes d'un export signé de l'historique
// d'une autre base : par exemple les copies qu'une passerelle gardait d'un pair, avant que la réplication soit retirée. Les
// lignes sont rangées sans toucher à la position du flux de la passerelle, sous des numéros décalés (ImportedIDBase). dryRun
// compte sans rien écrire. Rejouer la reprise n'écrit rien de plus.
func (v *Vault) ImportExport(node, manifestPath, dataPath, password string, pinned ed25519.PublicKey, dryRun bool) (*ImportReport, error) {
	var target NodeInfo
	for _, n := range v.Nodes() {
		if node == n.ID || node == n.Name {
			target = n
			break
		}
	}
	id := target.ID
	if id == "" {
		return nil, fmt.Errorf("aucune passerelle %q dans le volume de logs", node)
	}
	st, err := v.Store(id, "")
	if err != nil {
		return nil, err
	}
	rep := &ImportReport{Node: node}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	head, err := logexport.ParseManifest(raw, pinned)
	if err != nil {
		return nil, err
	}
	if head.Origin == "" {
		return nil, errors.New("cet export n'est pas celui des copies d'un pair (origin absent du manifeste) : la reprise ne verse que des copies d'un pair ; refaites l'export avec edge logs export -origin <pair> sur une passerelle en Edge 0.130.0 ou plus")
	}
	if head.Origin != target.ID && !strings.EqualFold(head.Origin, target.Name) {
		return nil, fmt.Errorf("l'export reprend les copies du pair %q, pas celles de %q : refusé", head.Origin, node)
	}
	kind := logstore.Kind(head.Kind)
	if kind != logstore.KindAccess && kind != logstore.KindSystem {
		return nil, errors.New("type de logs de l'export inconnu")
	}
	rep.Kind, rep.FromNode = head.Kind, head.Node
	var batch []logstore.ShippedRow
	flush := func() error {
		if len(batch) == 0 || dryRun {
			batch = batch[:0]
			return nil
		}
		n, err := st.AddImported(kind, batch)
		rep.Added += n
		batch = batch[:0]
		return err
	}
	_, err = logexport.ReadRows(manifestPath, dataPath, password, pinned, func(row logexport.Row) error {
		rep.Read++
		sr, ok := shippedFromExport(row)
		if !ok {
			rep.Skipped++
			return nil
		}
		if rep.FirstTS == "" {
			rep.FirstTS = row.Ts
		}
		rep.LastTS = row.Ts
		batch = append(batch, sr)
		if len(batch) >= importBatch {
			return flush()
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	return rep, flush()
}

// shippedFromExport convertit une ligne d'export en ligne à ranger. Une ligne pseudonymisée porte l'IP réelle dans IP et
// l'IP telle que la base la gardait dans IPStored : l'Admin chiffre la première avec sa clé et garde la seconde lisible.
func shippedFromExport(row logexport.Row) (logstore.ShippedRow, bool) {
	parts := strings.Split(row.ID, ":")
	src, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil || src <= 0 {
		return logstore.ShippedRow{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, row.Ts)
	if err != nil {
		return logstore.ShippedRow{}, false
	}
	e := logstore.Entry{
		Ts: ts, Level: row.Level, Component: row.Component, Domain: row.Domain, Method: row.Method, Path: row.Path,
		Status: row.Status, Bytes: row.Bytes, LatencyMs: row.LatencyMs, IP: row.IP, IPTruncated: row.IPTruncated,
		UserAgent: row.UserAgent, Referrer: row.Referrer, RequestID: row.RequestID, WAFMatches: row.WAFMatches,
		ThreatSignal: row.ThreatSignal, TLSJA3: row.TLSJA3, TLSJA4: row.TLSJA4, Message: row.Message,
	}
	if row.IPPseudonymized {
		e.RealIP, e.IP, e.IPTruncated = row.IP, row.IPStored, true
	}
	return logstore.ShippedRow{Seq: ImportedIDBase + src, Entry: e}, true
}
