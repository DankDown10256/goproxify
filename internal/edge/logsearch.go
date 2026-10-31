// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logserve"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// Les lectures de logs (recherche, histogramme, facettes, classements, IP distinctes, révélation) sont servies par
// internal/edge/logserve, que l'Admin applique aussi à ses stores (ADR 0018) : ici, seulement la base de cette passerelle.

func (s *Server) searchGate() *logserve.Gate {
	s.logGateOnce.Do(func() { s.logGate = logserve.NewGate() })
	return s.logGate
}

// logSvc rend le service de lecture de la base de logs de cette passerelle.
func (s *Server) logSvc() *logserve.Service {
	return &logserve.Service{Store: s.logStore, Node: s.cfg.Identity.NodeName, Log: s.log, Gate: s.searchGate(), }
}

// withLogGateFor applique le plafond de recherches simultanées et le délai de la requête.
func (s *Server) withLogGateFor(w http.ResponseWriter, r *http.Request, bulk bool, timeout time.Duration, fn func(ctx context.Context)) {
	s.logSvc().WithGate(w, r, bulk, timeout, fn)
}

// handleLogSearch : GET /internal/v1/logs/search — une page de lignes, du plus récent au plus ancien.
func (s *Server) handleLogSearch(w http.ResponseWriter, r *http.Request) { s.logSvc().Search(w, r) }

// handleLogHistogram : GET /internal/v1/logs/histogram.
func (s *Server) handleLogHistogram(w http.ResponseWriter, r *http.Request) {
	s.logSvc().Histogram(w, r)
}

// handleLogFacets : GET /internal/v1/logs/facets.
func (s *Server) handleLogFacets(w http.ResponseWriter, r *http.Request) { s.logSvc().Facets(w, r) }

// handleLogReveal : POST /internal/v1/logs/reveal — l'IP réelle d'une ligne pseudonymisée. La demande vient de
// l'Admin, qui a déjà contrôlé le droit de l'utilisateur et le motif ; la passerelle garde sa propre trace.
func (s *Server) handleLogReveal(w http.ResponseWriter, r *http.Request) { s.logSvc().Reveal(w, r) }

// handleLogTop : POST /internal/v1/logs/top — un regroupement des accès par champ.
func (s *Server) handleLogTop(w http.ResponseWriter, r *http.Request) { s.logSvc().Top(w, r) }

// handleLogUniqueIPs : GET /internal/v1/logs/unique-ips — l'ensemble des IP des accès, résumé pour être fusionné.
func (s *Server) handleLogUniqueIPs(w http.ResponseWriter, r *http.Request) {
	s.logSvc().UniqueIPs(w, r)
}

// eraseIP supprime d'une IP les lignes de la base de logs (accès et système, pseudonymisées comprises) et l'historique
// des bans de la passerelle ; il rend les comptes.
func (s *Server) eraseIP(ip string) (lines, bans int64, err error) {
	if s.threatEngine != nil {
		s.threatEngine.ForgetIP(ip)
	}
	if s.logStore != nil {
		if lines, err = s.logStore.EraseIP(ip); err != nil {
			return lines, 0, err
		}
	}
	if s.bansDB != nil {
		if bans, err = s.bansDB.EraseIP(ip, ipcrypt.CanonicalIP(ip)); err != nil {
			return lines, bans, err
		}
	}
	return lines, bans, nil
}

// handleLogErase : POST /internal/v1/logs/erase — efface une IP (droit à l'effacement RGPD) et rend ce qui a été
// supprimé, pour que l'Admin puisse dire, passerelle par passerelle, que l'effacement a eu lieu. L'IP doit être une
// adresse : une valeur quelconque (« [pseudonymisé] ») ne doit jamais effacer d'un coup toutes les lignes pseudonymisées.
func (s *Server) handleLogErase(w http.ResponseWriter, r *http.Request) {
	var req logapi.EraseRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	if _, err := netip.ParseAddr(req.IP); err != nil {
		http.Error(w, "adresse IP invalide", http.StatusBadRequest)
		return
	}
	
	lines, bans, err := s.eraseIP(req.IP)
	s.persistEphorState()
	if err != nil {
		s.log.Warn("rgpd: effacement d'une IP échoué", "err", err)
		http.Error(w, "effacement impossible", http.StatusInternalServerError)
		return
	}
	s.log.Info("rgpd: IP effacée de la passerelle sur demande de l'Admin", "log_lines", lines, "ban_rows", bans)
	writeJSON(w, logapi.EraseResponse{LogLines: lines, BanRows: bans})
}
