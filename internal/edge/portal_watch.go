// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// GET /internal/v1/portal/sessions/{id}/watch : flux SSE de la sortie d'une connexion en cours.
// Chaque événement `data:` porte un morceau de sortie en base64 ; `event: end` annonce la fin de la session.
func (s *Server) handlePortalSessionWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok || s.portal == nil {
		http.Error(w, "indisponible", http.StatusServiceUnavailable)
		return
	}
	backlog, out, cancel, found := s.portal.WatchLive(r.PathValue("id"))
	if !found {
		http.Error(w, "session introuvable", http.StatusNotFound)
		return
	}
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	send := func(p []byte) {
		fmt.Fprintf(w, "data: %s\n\n", base64.StdEncoding.EncodeToString(p))
		flusher.Flush()
	}
	if len(backlog) > 0 {
		send(backlog)
	} else {
		fmt.Fprint(w, ": ok\n\n")
		flusher.Flush()
	}
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case p, open := <-out:
			if !open {
				fmt.Fprint(w, "event: end\ndata: \n\n")
				flusher.Flush()
				return
			}
			send(p)
		case <-beat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
