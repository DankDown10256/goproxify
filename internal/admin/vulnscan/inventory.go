// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// Inventaire des applications (ADR 0017) : pour un proxy dont l'Agent annonce l'image du conteneur, la passerelle sait quel produit et quelle
// version tournent. Le scanner les lit chez elle au lieu de sonder le backend, qu'il n'atteint d'ailleurs pas toujours (réseau Docker).

// loadInventory lit l'inventaire de chaque passerelle. Une passerelle qui ne répond pas, ou trop ancienne pour connaître l'inventaire,
// n'en donne simplement pas : ses backends sont sondés comme avant.
func (s *Scanner) loadInventory(ctx context.Context) []logapi.InventoryEntry {
	targets, err := edgeproxy.ListTargets(ctx, s.db)
	if err != nil {
		return nil
	}
	client := edgeproxy.NewClient()
	seen := map[string]bool{}
	var out []logapi.InventoryEntry
	for _, t := range targets {
		res, err := client.Inventory(ctx, t, "")
		if err != nil {
			continue
		}
		for _, e := range res.Entries {
			// Les membres d'un groupe HA connaissent les mêmes backends : une entrée par conteneur suffit.
			key := e.Backend + "|" + e.Container + "|" + e.Evidence
			if e.Backend == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}

// nvdQuery est une recherche de CVE à faire pour un backend : l'URL NVD, le produit et la version qu'elle vise, et d'où ils viennent.
type nvdQuery struct {
	label   string
	url     string
	product string
	version string
	source  string
}

// cpeQueryURL interroge NVD par identifiant CPE : NVD compare alors la version aux plages de chaque CVE.
func cpeQueryURL(vendorProduct, version string) string {
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*", vendorProduct, version)
	return "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=" + url.QueryEscape(cpe) + "&resultsPerPage=20"
}

// inventoryQueries rend les recherches que l'inventaire d'un backend permet : seulement les produits dont le CPE est sûr et dont la version
// est connue. Un produit sans version ou sans CPE n'est jamais cherché en texte libre.
func inventoryQueries(entries []logapi.InventoryEntry) []nvdQuery {
	var out []nvdQuery
	seen := map[string]bool{}
	for _, e := range entries {
		if e.CPE == "" || e.Version == "" {
			continue
		}
		u := cpeQueryURL(e.CPE, e.Version)
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, nvdQuery{label: e.Product + " " + e.Version, url: u, product: e.Product, version: e.Version, source: e.Source})
	}
	return out
}

// appLabels résume ce que l'inventaire sait d'un backend, en disant ce qui n'a pas pu être cherché.
func appLabels(entries []logapi.InventoryEntry) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range entries {
		var l string
		switch {
		case e.Product == "" && e.Source == appinv.SourceImage:
			l = e.Evidence + " (image non reconnue)"
		case e.Product == "":
			l = e.Evidence + " (logiciel non reconnu)"
		case e.CPE == "":
			l = strings.TrimSpace(e.Product+" "+e.Version) + " (non couvert)"
		case e.Version == "":
			l = e.Product + " (version inconnue)"
		case e.Partial:
			l = e.Product + " " + e.Version + " (version partielle)"
		default:
			l = e.Product + " " + e.Version
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// headerQuery est la recherche faite pour un en-tête « produit version » lu sur le backend.
func headerQuery(kw string) nvdQuery {
	product, version, _ := strings.Cut(kw, " ")
	return nvdQuery{label: kw, url: buildNVDQuery(kw), product: product, version: version, source: "headers"}
}
