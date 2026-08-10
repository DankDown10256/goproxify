// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestOIDCSessionSecretFailClosed(t *testing.T) {
	h := &HTTPServer{masterSecret: ""}
	if _, err := h.oidcSessionSecret(nil); err == nil {
		t.Fatal("attendu erreur sans secret")
	}
	if _, err := h.oidcSessionSecret(&router.SSOConfig{OIDC: &router.OIDCConfig{}}); err == nil {
		t.Fatal("attendu erreur OIDC sans session_secret")
	}
	sec, err := h.oidcSessionSecret(&router.SSOConfig{
		OIDC: &router.OIDCConfig{SessionSecret: "from-sso"},
	})
	if err != nil || sec != "from-sso" {
		t.Fatalf("got %q %v", sec, err)
	}
	h.masterSecret = "master"
	sec, err = h.oidcSessionSecret(nil)
	if err != nil || sec != "master" {
		t.Fatalf("master: got %q %v", sec, err)
	}
}
