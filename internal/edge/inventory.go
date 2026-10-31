// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"

	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/fingerprint"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Inventaire des applications (ADR 0017). Deux sources, toutes deux déjà sur la passerelle :
//   - l'image du conteneur, annoncée par l'Agent et gardée sur le backend correspondant (proxys créés par labels) : elle est dans la
//     copie locale chiffrée des routes ;
//   - l'empreinte des réponses du backend (en-têtes, <meta name="generator">), lue avant hide_server pour tous les proxys : elle a sa
//     propre copie locale chiffrée et se partage entre les membres d'un groupe HA.
// Rien n'est nécessaire de l'Admin : l'inventaire se constitue et se relit après un redémarrage pendant une coupure.

// imageEntries liste, pour un proxy, les applications reconnues d'après l'image de chacun de ses backends.
func imageEntries(rt *router.Route) []logapi.InventoryEntry {
	var out []logapi.InventoryEntry
	for _, b := range rt.Backends {
		f, ok := appinv.FromImage(b.Image)
		if !ok {
			continue
		}
		out = append(out, logapi.InventoryEntry{Route: rt.ID, Host: rt.Host, Backend: b.URL, Container: b.ContainerID, Finding: f})
	}
	return out
}

// inventoryEntries réunit les deux sources d'un proxy. Pour un même produit sur un même backend, l'entrée qui porte une version l'emporte
// (une image « latest » n'en a pas, les réponses du backend l'annoncent) ; à égalité, l'image, qui décrit ce qui est déployé. Quand les
// deux donnent une version et qu'elles diffèrent, l'image reste et la note le dit.
func inventoryEntries(rt *router.Route, seen []fingerprint.Obs) []logapi.InventoryEntry {
	all := imageEntries(rt)
	for _, o := range seen {
		all = append(all, logapi.InventoryEntry{Route: rt.ID, Host: rt.Host, Backend: o.Backend, Finding: o.Finding()})
	}
	type slot struct{ backend, product string }
	best := map[slot]int{}
	var out []logapi.InventoryEntry
	for _, e := range all {
		if e.Product == "" {
			out = append(out, e) // image non reconnue : listée telle quelle
			continue
		}
		k := slot{e.Backend, e.Product}
		i, ok := best[k]
		if !ok {
			best[k] = len(out)
			out = append(out, e)
			continue
		}
		cur := out[i]
		switch {
		case cur.Version == "" && e.Version != "":
			e.Container = cur.Container
			out[i] = e
		case cur.Version != "" && e.Version != "" && cur.Version != e.Version:
			if cur.Source == appinv.SourceImage {
				out[i].Note = "les réponses du backend annoncent " + e.Product + " " + e.Version + " (" + e.Evidence + ")"
			} else {
				e.Note = "l'image annonce " + cur.Product + " " + cur.Version + " (" + cur.Evidence + ")"
				e.Container = cur.Container
				out[i] = e
			}
		}
	}
	return out
}

// handleInventory : GET /internal/v1/inventory[?route=…] — les applications reconnues derrière les proxies de la passerelle.
func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("route")
	out := logapi.InventoryResponse{Entries: []logapi.InventoryEntry{}}
	for _, rt := range s.table.All() {
		if ref != "" && rt.ID != ref && rt.Host != ref {
			continue
		}
		var seen []fingerprint.Obs
		if s.apps != nil {
			seen = s.apps.Entries(rt.ID)
		}
		out.Entries = append(out.Entries, inventoryEntries(rt, seen)...)
	}
	for i := range out.Entries {
		out.Entries[i].Coverage = out.Entries[i].Finding.Coverage()
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		if out.Entries[i].Host != out.Entries[j].Host {
			return out.Entries[i].Host < out.Entries[j].Host
		}
		if out.Entries[i].Backend != out.Entries[j].Backend {
			return out.Entries[i].Backend < out.Entries[j].Backend
		}
		return out.Entries[i].Product < out.Entries[j].Product
	})
	writeJSON(w, out)
}

// --- empreinte des réponses : copie locale chiffrée et partage entre pairs (ADR 0006, ADR 0014) ---

func appsStatePath() string {
	if p := os.Getenv("GPX_APPS_STATE_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/apps-state.gpx"
}

func (s *Server) loadAppsStateFromDisk() {
	var st fingerprint.State
	ok, err := s.cache.LoadFile(appsStatePath(), &st)
	if err != nil {
		s.log.Warn("inventaire: état local illisible — l'empreinte des backends repart de zéro", "err", err)
		return
	}
	if !ok {
		return
	}
	s.apps.Restore(st)
	s.log.Info("inventaire: empreintes restaurées depuis le disque", "proxies", len(st.Routes))
}

func (s *Server) saveAppsState() {
	if s.apps == nil {
		return
	}
	// Un proxy supprimé n'a plus d'inventaire ; table vide = pas encore chargée, on ne juge rien.
	if s.table.Len() > 0 {
		s.apps.Forget(func(id string) bool { _, ok := s.table.ByID(id); return ok })
	}
	if err := s.cache.SaveFile(appsStatePath(), s.apps.Snapshot()); err != nil {
		s.log.Warn("inventaire: sauvegarde de l'état échouée", "err", err)
	}
}

// syncAppsFromPeer tire les empreintes d'un pair du groupe ; la fusion est idempotente.
func (s *Server) syncAppsFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.apps == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+logapi.PathInventoryExport, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var payload fingerprint.Payload
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<20)).Decode(&payload); err != nil {
		return
	}
	s.apps.ApplyPeer(p.Name, payload)
}

func (s *Server) handleInventoryExport(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.apps.Export())
}
