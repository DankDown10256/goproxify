// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"fmt"
	"sync/atomic"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Metrics comptabilise les octets et connexions des streams L4.
type Metrics struct {
	BytesIn           atomic.Int64
	BytesOut          atomic.Int64
	ActiveConnections atomic.Int64
}

func addrForRoute(r *router.Route) string {
	return fmt.Sprintf(":%d", r.ListenPort)
}

// pickBackend sélectionne le premier backend disponible (round-robin simple).
func pickBackend(r *router.Route) *router.Backend {
	if len(r.Backends) == 0 {
		return nil
	}
	return &r.Backends[0]
}
