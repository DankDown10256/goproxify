// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/domainwatch"
)

// DomainWatchView rend la configuration, l'état et les constats de la surveillance des domaines (ADR 0020, étape 4.d).
func DomainWatchView(w *domainwatch.Watcher) (map[string]any, error) {
	if w == nil {
		return nil, errors.New("surveillance des domaines indisponible")
	}
	findings, err := w.Findings("")
	if err != nil {
		return nil, err
	}
	open := 0
	for _, f := range findings {
		if f.Status == domainwatch.StatusOpen {
			open++
		}
	}
	return map[string]any{"config": w.Config(), "state": w.State(), "open": open, "findings": findings}, nil
}

// getDomainWatch : GET /api/v1/security/domain-watch.
func (h *SecurityHandler) getDomainWatch(rw http.ResponseWriter, r *http.Request) {
	out, err := DomainWatchView(h.DomainWatch)
	if err != nil {
		secJSONErr(rw, err, http.StatusServiceUnavailable)
		return
	}
	jsonOK(rw, out)
}

// putDomainWatch : PUT /api/v1/security/domain-watch — enregistre la configuration (tout est désactivé par défaut : chaque
// vérification envoie des noms de domaine à un service extérieur et s'active séparément).
func (h *SecurityHandler) putDomainWatch(rw http.ResponseWriter, r *http.Request) {
	if h.DomainWatch == nil {
		secJSONErr(rw, errors.New("surveillance des domaines indisponible"), http.StatusServiceUnavailable)
		return
	}
	var cfg domainwatch.Config
	dec := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		secJSONErr(rw, err, http.StatusBadRequest)
		return
	}
	if err := h.DomainWatch.SetConfig(cfg); err != nil {
		secJSONErr(rw, err, http.StatusBadRequest)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// runDomainWatch : POST /api/v1/security/domain-watch/run — lance une analyse en arrière-plan (au plus une toutes les cinq minutes).
func (h *SecurityHandler) runDomainWatch(rw http.ResponseWriter, r *http.Request) {
	if h.DomainWatch == nil {
		secJSONErr(rw, errors.New("surveillance des domaines indisponible"), http.StatusServiceUnavailable)
		return
	}
	if !h.DomainWatch.Config().Active() {
		secJSONErr(rw, errors.New("la surveillance est désactivée : activez-la et au moins une vérification"), http.StatusConflict)
		return
	}
	if err := h.DomainWatch.RunNow(); err != nil {
		secJSONErr(rw, err, http.StatusTooManyRequests)
		return
	}
	rw.WriteHeader(http.StatusAccepted)
}

// acceptDomainWatch : POST /api/v1/security/domain-watch/accept — reconnaît un constat (corps {domain, check, key}).
func (h *SecurityHandler) acceptDomainWatch(rw http.ResponseWriter, r *http.Request) {
	if h.DomainWatch == nil {
		secJSONErr(rw, errors.New("surveillance des domaines indisponible"), http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Domain string `json:"domain"`
		Check  string `json:"check"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 1<<12)).Decode(&body); err != nil || body.Domain == "" || body.Check == "" || body.Key == "" {
		writeErr(rw, r, http.StatusBadRequest, "api.err.json")
		return
	}
	ok, err := h.DomainWatch.Accept(body.Domain, body.Check, body.Key)
	if err != nil {
		secJSONErr(rw, err, http.StatusInternalServerError)
		return
	}
	if !ok {
		secJSONErr(rw, errors.New("aucun constat ouvert ou de référence ne correspond"), http.StatusNotFound)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}
