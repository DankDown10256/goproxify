// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"github.com/vincamok/goproxify/internal/ssrf"
)

// allowPrivateBackends lit l’opt-in GPX_VULNSCAN_ALLOW_PRIVATE (1/true/yes).
func allowPrivateBackends() bool {
	return ssrf.AllowPrivateEnv("GPX_VULNSCAN_ALLOW_PRIVATE")
}

// validateProbeURL refuse les cibles SSRF (schéma, loopback, link-local, metadata ;
// RFC1918/ULA sauf opt-in).
func validateProbeURL(raw string) error {
	return validateProbeURLOpts(raw, allowPrivateBackends())
}

func validateProbeURLOpts(raw string, allowPrivate bool) error {
	return ssrf.ValidateHTTPURL(raw, allowPrivate)
}
