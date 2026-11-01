// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import "strings"

// TLSTableVersion date la table livrée avec le binaire. Elle reste courte et stable à dessein : famille de navigateur ↔
// empreinte JA4 des suites de chiffrement (la partie « b » du JA4, triée et sans GREASE). Une famille absente de la table
// n'est jamais évaluée : ni signal ni faux positif. L'administrateur complète la table dans la configuration d'Ephor
// (`behavior.tls_families`).
const TLSTableVersion = "2026-10-24"

// builtinTLSFamilies : seules les suites que l'on sait stables.
//
//   - chromium : Chrome, Edge, Opera, Brave et Electron partagent la pile BoringSSL ; sa liste de 15 suites de chiffrement
//     (t13d1516h2_8daaf6152771_…) n'a pas changé de contenu depuis des années. Chrome sur iOS (WebKit) en est exclu côté User-Agent.
var builtinTLSFamilies = map[string][]string{
	"chromium": {"8daaf6152771"},
}

// TLSTable associe une famille de navigateurs aux empreintes de suites de chiffrement qu'elle présente.
type TLSTable struct {
	families map[string]map[string]struct{}
}

func defaultTLSTable() *TLSTable { return NewTLSTable(nil) }

// NewTLSTable construit la table livrée, complétée par extra (famille → empreintes « b » de JA4).
func NewTLSTable(extra map[string][]string) *TLSTable {
	t := &TLSTable{families: map[string]map[string]struct{}{}}
	for _, src := range []map[string][]string{builtinTLSFamilies, extra} {
		for fam, hashes := range src {
			fam = strings.ToLower(strings.TrimSpace(fam))
			if fam == "" {
				continue
			}
			set := t.families[fam]
			if set == nil {
				set = map[string]struct{}{}
				t.families[fam] = set
			}
			for _, h := range hashes {
				if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
					set[h] = struct{}{}
				}
			}
		}
	}
	return t
}

// SetTLSFamilies remplace la table par la table livrée complétée de extra.
func (s *Store) SetTLSFamilies(extra map[string][]string) { s.tlsTable.Store(NewTLSTable(extra)) }

// uaFamily : la famille de navigateurs que le User-Agent annonce, "" si inconnue ou non évaluée. Un navigateur d'Apple (tous
// utilisent la pile de la plateforme, même « Chrome » sur iOS) n'est jamais rapproché de la table.
func uaFamily(ua string) string {
	for _, apple := range []string{"iPhone", "iPad", "iPod", "CriOS", "EdgiOS", "FxiOS"} {
		if strings.Contains(ua, apple) {
			return ""
		}
	}
	if strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Edg/") || strings.Contains(ua, "OPR/") {
		return "chromium"
	}
	return ""
}

// ja4Ciphers extrait l'empreinte des suites de chiffrement d'un JA4 TLS sur TCP ("t13d1516h2_8daaf6152771_02713d6af862").
func ja4Ciphers(ja4 string) string {
	if len(ja4) == 0 || ja4[0] != 't' {
		return ""
	}
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 || len(parts[1]) != 12 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// Mismatch indique que le User-Agent annonce une famille connue de la table alors que les suites de chiffrement de la connexion
// ne sont pas les siennes : un client programmatique qui se fait passer pour un navigateur.
func (t *TLSTable) Mismatch(ua, ja4 string) bool {
	if t == nil {
		return false
	}
	set := t.families[uaFamily(ua)]
	if len(set) == 0 {
		return false
	}
	h := ja4Ciphers(ja4)
	if h == "" {
		return false
	}
	_, ok := set[h]
	return !ok
}

// KnownBrowser indique que les suites de chiffrement de la connexion sont celles d'une famille de navigateurs de la table.
func (t *TLSTable) KnownBrowser(ja4 string) bool {
	if t == nil {
		return false
	}
	h := ja4Ciphers(ja4)
	if h == "" {
		return false
	}
	for _, set := range t.families {
		if _, ok := set[h]; ok {
			return true
		}
	}
	return false
}

// IsBrowserJA4 indique qu'une empreinte JA4 est celle d'un navigateur connu : des millions de visiteurs la partagent, elle ne
// désigne jamais un client en particulier.
func (s *Store) IsBrowserJA4(ja4 string) bool {
	return s.tlsTable.Load().KnownBrowser(ja4)
}
