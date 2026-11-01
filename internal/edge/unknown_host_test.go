// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnknownHostNeutralResponseRevealsNothing(t *testing.T) {
	s := whitelistServer(t, nil)
	s.threatEngine = nil

	req := httptest.NewRequest(http.MethodGet, "http://inconnu.test/", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder()
	s.dispatch(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("statut %d, attendu 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("la réponse neutre n'a pas de corps : %q", rec.Body.String())
	}
	for name := range rec.Header() {
		if strings.Contains(strings.ToLower(name), "goproxify") {
			t.Fatalf("en-tête révélateur : %s", name)
		}
	}
}

func TestUnknownHostCloseDropsTheConnection(t *testing.T) {
	s := whitelistServer(t, nil)
	s.threatEngine = nil
	s.cfg.Network.UnknownHostAction = "close"
	srv := httptest.NewServer(http.HandlerFunc(s.dispatch))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("la connexion devait être coupée sans réponse, reçu %d %q", resp.StatusCode, body)
	}
}

func TestUnknownHostCloseFallsBackToNeutralWithoutHijacker(t *testing.T) {
	s := whitelistServer(t, nil)
	s.threatEngine = nil
	s.cfg.Network.UnknownHostAction = "close"

	req := httptest.NewRequest(http.MethodGet, "http://inconnu.test/", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	rec := httptest.NewRecorder() // ne sait pas détourner la connexion, comme une requête HTTP/2
	s.dispatch(rec, req)

	if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
		t.Fatalf("sans détournement possible : %d %q, attendu un 404 neutre", rec.Code, rec.Body.String())
	}
}
