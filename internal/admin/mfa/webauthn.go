// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// NewWebAuthn crée une instance WebAuthn configurée pour l'Admin.
func NewWebAuthn(rpID, rpOrigin, rpDisplayName string) (*webauthn.WebAuthn, error) {
	if rpID == "" {
		rpID = "localhost"
	}
	if rpOrigin == "" {
		rpOrigin = "http://localhost:9000"
	}
	if rpDisplayName == "" {
		rpDisplayName = "Goproxify"
	}
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}
	return w, nil
}
