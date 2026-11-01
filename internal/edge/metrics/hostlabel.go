// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net/http"
)

type hostLabelKey struct{}

// WithHost fixe l'étiquette `host` des métriques de la requête. Le dispatch la pose une fois la route trouvée : le nom
// que le client écrit dans `Host` n'est pas une étiquette sûre, un wildcard sert une infinité de sous-domaines.
func WithHost(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, hostLabelKey{}, label)
}

// HostOf donne l'étiquette `host` des métriques d'une requête : celle que le dispatch a fixée, sinon le nom reçu (un
// test, ou une requête qui n'est pas passée par le routage).
func HostOf(r *http.Request) string {
	if v, ok := r.Context().Value(hostLabelKey{}).(string); ok {
		return v
	}
	return r.Host
}
