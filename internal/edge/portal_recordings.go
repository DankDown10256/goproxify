// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
)

// GET /internal/v1/portal/recordings : métadonnées des enregistrements de sessions du portail.
func (s *Server) handlePortalRecordingsList(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"recordings":[]}`))
		return
	}
	list, err := s.portal.ListRecordings()
	if err != nil {
		http.Error(w, "enregistrements indisponibles", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"recordings": list})
}

// GET /internal/v1/portal/recordings/{id} : enregistrement déchiffré (asciicast v2).
func (s *Server) handlePortalRecordingGet(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		http.Error(w, "introuvable", http.StatusNotFound)
		return
	}
	data, err := s.portal.ReadRecording(r.PathValue("id"))
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "lecture impossible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// DELETE /internal/v1/portal/recordings/{id}
func (s *Server) handlePortalRecordingDelete(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		http.Error(w, "introuvable", http.StatusNotFound)
		return
	}
	err := s.portal.DeleteRecording(r.PathValue("id"))
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "suppression impossible", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
