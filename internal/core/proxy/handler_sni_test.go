// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestHostnameForSNI(t *testing.T) {
	cases := map[string]string{
		"api.example.fr":     "api.example.fr",
		"api.example.fr:443": "api.example.fr",
		"192.0.2.4:8443": "192.0.2.4",
		"":                   "",
	}
	for in, want := range cases {
		if got := hostnameForSNI(in); got != want {
			t.Errorf("hostnameForSNI(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBuildTransportUsesHostSNIForDeleg(t *testing.T) {
	r := &router.Route{
		ID:            "deleg-abc",
		TLSSkipVerify: true,
		Backends:      []router.Backend{{URL: "https://192.0.2.4:443"}},
	}
	rt := buildTransport(r)
	if _, ok := rt.(*hostSNITransport); !ok {
		t.Fatalf("expected hostSNITransport, got %T", rt)
	}
}

func TestHostSNITransportSendsVirtualHostSNI(t *testing.T) {
	var gotSNI string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			gotSNI = chi.ServerName
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	rt := &hostSNITransport{base: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}}
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "devtools.dankdown.fr"

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if gotSNI != "devtools.dankdown.fr" {
		t.Fatalf("SNI=%q want devtools.dankdown.fr", gotSNI)
	}
}
