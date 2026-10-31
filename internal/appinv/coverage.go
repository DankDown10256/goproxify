// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package appinv

import (
	"regexp"
	"strings"
)

// Couverture d'une entrée de l'inventaire par la recherche de CVE (ADR 0017, étape 3).
const (
	// CoverageCovered : produit à CPE sûr et version connue, la recherche NVD a lieu (approchée si Partial).
	CoverageCovered = "covered"
	// CoverageNoVersion : produit à CPE, mais l'étiquette ou les réponses ne donnent pas de version.
	CoverageNoVersion = "no_version"
	// CoverageNoCPE : produit reconnu, sans identifiant CPE sûr : jamais cherché en texte libre.
	CoverageNoCPE = "no_cpe"
	// CoverageUnknown : image, en-tête ou générateur absent de la table.
	CoverageUnknown = "unknown"
)

// CPEPattern : la forme « vendor:product » d'un identifiant CPE tel que NVD le nomme.
var CPEPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.\-]*:[a-z0-9][a-z0-9_.\-]*$`)

// Coverage dit si la recherche de CVE peut se faire pour cette entrée, et sinon pourquoi.
func (f Finding) Coverage() string {
	switch {
	case f.Product == "":
		return CoverageUnknown
	case f.CPE == "":
		return CoverageNoCPE
	case f.Version == "":
		return CoverageNoVersion
	}
	return CoverageCovered
}

// Name est le nom sous lequel l'entrée se range dans le rapport : le produit quand il est reconnu, sinon ce que la preuve nomme (le
// dépôt de l'image sans registre ni étiquette, le jeton d'un en-tête, le générateur d'une page).
func (f Finding) Name() string {
	if f.Product != "" {
		return f.Product
	}
	switch f.Source {
	case SourceImage:
		return ParseImage(f.Evidence).Repo
	case SourceHTML:
		_, v, _ := strings.Cut(f.Evidence, "> ")
		name, _, _ := strings.Cut(strings.TrimSpace(v), " ")
		return strings.ToLower(name)
	}
	_, v, _ := strings.Cut(f.Evidence, ": ")
	name, _, _ := strings.Cut(v, "/")
	return strings.ToLower(strings.TrimSpace(name))
}

// EvidenceVersion lit la version dans la preuve d'une entrée non reconnue (étiquette d'image, jeton nom/version), pour qu'une surcharge
// de CPE puisse la chercher. Vide quand la preuve n'en porte pas de précise.
func (f Finding) EvidenceVersion() string {
	switch f.Source {
	case SourceImage:
		if m := versionTag.FindStringSubmatch(strings.ToLower(ParseImage(f.Evidence).Tag)); m != nil {
			return m[1]
		}
	case SourceHTML:
		_, v, _ := strings.Cut(f.Evidence, "> ")
		if m := generatorRe.FindStringSubmatch(v); m != nil && strings.Contains(m[2], ".") {
			return m[2]
		}
	default:
		_, v, _ := strings.Cut(f.Evidence, ": ")
		_, ver, _ := strings.Cut(v, "/")
		if m := tokenVersion.FindStringSubmatch(strings.ToLower(ver)); m != nil {
			return m[1]
		}
	}
	return ""
}

// WithCPE rend l'entrée telle qu'une surcharge de l'administrateur la complète : le produit prend le nom donné, le CPE est celui de la
// surcharge, et la version est lue dans la preuve quand l'entrée n'en avait pas.
func (f Finding) WithCPE(name, cpe string) Finding {
	if f.Product == "" {
		f.Product = name
	}
	f.CPE = cpe
	if f.Version == "" {
		if v := f.EvidenceVersion(); v != "" {
			f.Version = v
			f.Partial = strings.Count(v, ".") == 1
		}
	}
	return f
}
