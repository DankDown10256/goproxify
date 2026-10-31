// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// Rapport de couverture et surcharges de CPE (ADR 0017, étape 3). La table des produits connus est embarquée ; elle ne couvre pas tout.
// Le rapport dit ce que la recherche de CVE ne peut pas faire et pourquoi, et une surcharge de l'administrateur, gardée sur l'Admin avec
// le reste de la recherche de CVE, donne un identifiant CPE à un produit que la table ne connaît pas.

const (
	overridesKey = "cve_cpe_overrides"
	maxOverrides = 200
)

// Override associe un nom (produit reconnu sans CPE, dépôt d'image ou logiciel inconnu) à un identifiant CPE « vendor:product ».
type Override struct {
	// Match : le nom tel que le rapport le donne (« vaultwarden », « team/app », « microsoft-httpapi »), sans tenir compte de la casse. Le
	// dernier segment d'un dépôt d'image suffit (« app » pour « team/app »).
	Match string `json:"match"`
	// CPE : « vendor:product » dans NVD (« dani-garcia:vaultwarden »).
	CPE string `json:"cpe"`
}

// ValidateOverrides rend la liste normalisée ou la première erreur.
func ValidateOverrides(in []Override) ([]Override, error) {
	if len(in) > maxOverrides {
		return nil, fmt.Errorf("au plus %d surcharges", maxOverrides)
	}
	seen := map[string]bool{}
	out := make([]Override, 0, len(in))
	for i, o := range in {
		o.Match = strings.ToLower(strings.TrimSpace(o.Match))
		o.CPE = strings.ToLower(strings.TrimSpace(o.CPE))
		switch {
		case o.Match == "" || len(o.Match) > 128:
			return nil, fmt.Errorf("surcharge %d : match requis (128 caractères au plus)", i+1)
		case !appinv.CPEPattern.MatchString(o.CPE):
			return nil, fmt.Errorf("surcharge %d : %q n'est pas un identifiant CPE « vendor:product »", i+1, o.CPE)
		case seen[o.Match]:
			return nil, fmt.Errorf("surcharge %d : %q est déjà surchargé", i+1, o.Match)
		}
		seen[o.Match] = true
		out = append(out, o)
	}
	return out, nil
}

// LoadOverrides lit les surcharges enregistrées ; aucune si le réglage manque ou est illisible.
func LoadOverrides(ctx context.Context, db *sql.DB) []Override {
	var raw string
	if db == nil || db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, overridesKey).Scan(&raw) != nil {
		return nil
	}
	var out []Override
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}

// SaveOverrides enregistre les surcharges (après ValidateOverrides).
func SaveOverrides(ctx context.Context, db *sql.DB, list []Override) error {
	b, _ := json.Marshal(list)
	_, err := db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, overridesKey, string(b))
	return err
}

func (o Override) matches(f appinv.Finding) bool {
	name := strings.ToLower(f.Name())
	if name == "" {
		return false
	}
	return name == o.Match || name[strings.LastIndex(name, "/")+1:] == o.Match
}

// ApplyOverrides complète les entrées que la table ne couvrait pas (sans CPE) avec les surcharges de l'administrateur, et renseigne la
// couverture de chacune. Une entrée déjà couverte par la table n'est pas modifiée. Les entrées passées ne sont pas modifiées.
func ApplyOverrides(entries []logapi.InventoryEntry, ov []Override) []logapi.InventoryEntry {
	out := make([]logapi.InventoryEntry, len(entries))
	for i, e := range entries {
		if e.CPE == "" {
			for _, o := range ov {
				if o.matches(e.Finding) {
					e.Finding = e.Finding.WithCPE(o.Match, o.CPE)
					break
				}
			}
		}
		e.Coverage = e.Finding.Coverage()
		out[i] = e
	}
	return out
}

// Gap est un produit ou un logiciel que la recherche de CVE n'a pas pu traiter, regroupé par raison et par nom.
type Gap struct {
	Reason   string   `json:"reason"` // no_cpe | no_version | unknown
	Name     string   `json:"name"`
	Evidence string   `json:"evidence"`
	Entries  int      `json:"entries"`
	Hosts    []string `json:"hosts"`
}

// Coverage résume la couverture de la recherche de CVE sur un ensemble d'entrées d'inventaire.
type Coverage struct {
	Total     int   `json:"total"`
	Covered   int   `json:"covered"`
	Partial   int   `json:"partial"` // parmi les couvertes, celles dont la version n'a que deux composantes (correspondance approchée)
	NoVersion int   `json:"no_version"`
	NoCPE     int   `json:"no_cpe"`
	Unknown   int   `json:"unknown"`
	Gaps      []Gap `json:"gaps"`
}

// BuildCoverage calcule le rapport. Les entrées doivent avoir été passées par ApplyOverrides.
func BuildCoverage(entries []logapi.InventoryEntry) Coverage {
	c := Coverage{Gaps: []Gap{}}
	gaps := map[string]*Gap{}
	for _, e := range entries {
		c.Total++
		cov := e.Coverage
		if cov == "" {
			cov = e.Finding.Coverage()
		}
		switch cov {
		case appinv.CoverageCovered:
			c.Covered++
			if e.Partial {
				c.Partial++
			}
			continue
		case appinv.CoverageNoVersion:
			c.NoVersion++
		case appinv.CoverageNoCPE:
			c.NoCPE++
		default:
			c.Unknown++
			cov = appinv.CoverageUnknown
		}
		name := e.Finding.Name()
		k := cov + "|" + name
		g := gaps[k]
		if g == nil {
			g = &Gap{Reason: cov, Name: name, Evidence: e.Evidence, Hosts: []string{}}
			gaps[k] = g
		}
		g.Entries++
		if e.Host != "" && len(g.Hosts) < 10 && !contains(g.Hosts, e.Host) {
			g.Hosts = append(g.Hosts, e.Host)
		}
	}
	for _, g := range gaps {
		sort.Strings(g.Hosts)
		c.Gaps = append(c.Gaps, *g)
	}
	sort.Slice(c.Gaps, func(i, j int) bool {
		if c.Gaps[i].Entries != c.Gaps[j].Entries {
			return c.Gaps[i].Entries > c.Gaps[j].Entries
		}
		return c.Gaps[i].Name < c.Gaps[j].Name
	})
	return c
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
