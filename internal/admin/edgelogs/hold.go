// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgelogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// Gel légal et export signé sur le volume de logs (ADR 0018). Le registre des gels est commun à tous les stores du volume ; un
// gel filtré garde ses lignes dans l'archive de chaque store.

// NodeInfo désigne une passerelle du volume.
type NodeInfo struct {
	ID   string // nom du dossier
	Name string // nom de la passerelle, vide si node.json manque
}

// Label rend le nom sous lequel la passerelle figure dans un export.
func (n NodeInfo) Label() string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

// Nodes liste les passerelles qui ont un dossier dans le volume, retirées ou renommées comprises.
func (v *Vault) Nodes() []NodeInfo {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return nil
	}
	var out []NodeInfo
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		n := NodeInfo{ID: de.Name()}
		if raw, err := os.ReadFile(filepath.Join(v.dir, de.Name(), "node.json")); err == nil {
			var m meta
			if json.Unmarshal(raw, &m) == nil {
				n.Name = m.Name
			}
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label() < out[j].Label() })
	return out
}

// Sources rend les stores à exporter : toutes les passerelles (selector vide ou « all »), ou celle qu'il désigne par son nom
// ou son identifiant.
func (v *Vault) Sources(selector string) ([]logexport.Source, error) {
	var out []logexport.Source
	for _, n := range v.Nodes() {
		if selector != "" && selector != "all" && selector != n.ID && selector != n.Name {
			continue
		}
		st, err := v.Store(n.ID, "")
		if err != nil {
			return nil, err
		}
		out = append(out, logexport.Source{Name: n.Label(), Store: st})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("aucune passerelle ne correspond à %q dans le volume de logs", selector)
	}
	return out, nil
}

// Holds lit le registre commun des gels légaux.
func (v *Vault) Holds() ([]logstore.Hold, error) {
	return logstore.ReadHoldsFile(filepath.Join(v.dir, "legal-holds.json"))
}

// AddHold pose un gel légal pour tout le volume : une fois dans le registre commun, puis, pour un gel filtré, dans l'archive
// de chaque store. Si un store ne peut pas garder ses lignes, le gel est retiré partout : mieux vaut ne rien poser que
// croire des lignes gardées qui ne le sont pas.
func (v *Vault) AddHold(h logstore.Hold) (logstore.Hold, error) {
	stores, err := v.allStores()
	if err != nil {
		return logstore.Hold{}, err
	}
	if len(stores) == 0 {
		return logstore.Hold{}, errors.New("le volume de logs ne contient aucune passerelle")
	}
	h, err = stores[0].AddHold(h)
	if err != nil {
		return logstore.Hold{}, err
	}
	for i, st := range stores[1:] {
		if err := st.PreserveHold(h); err != nil {
			_ = stores[0].RemoveHold(h.ID)
			for _, done := range stores[1 : i+1] {
				_ = done.DropHoldArchive(h.ID)
			}
			_ = st.DropHoldArchive(h.ID)
			return logstore.Hold{}, err
		}
	}
	return h, nil
}

// RemoveHold lève un gel pour tout le volume ; les archives d'un gel filtré sont supprimées dans chaque store.
func (v *Vault) RemoveHold(id string) error {
	stores, err := v.allStores()
	if err != nil {
		return err
	}
	if len(stores) == 0 {
		return errors.New("le volume de logs ne contient aucune passerelle")
	}
	if err := stores[0].RemoveHold(id); err != nil {
		return err
	}
	for _, st := range stores[1:] {
		_ = st.DropHoldArchive(id)
	}
	return nil
}

func (v *Vault) allStores() ([]*logstore.Store, error) {
	var out []*logstore.Store
	for _, n := range v.Nodes() {
		st, err := v.Store(n.ID, "")
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}
