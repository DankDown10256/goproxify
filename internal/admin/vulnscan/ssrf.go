// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"github.com/vincamok/goproxify/internal/ssrf"
)

func validateProbeURLOpts(raw string, allowPrivate bool) error {
	return ssrf.ValidateHTTPURL(raw, allowPrivate)
}
