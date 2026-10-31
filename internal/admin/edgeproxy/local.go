// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"sync"
)

// LocalLogs sert les lectures de logs d'une passerelle depuis le volume de logs de l'Admin (ADR 0018), sans réseau.
// ok est faux quand la copie ne peut pas répondre (pas de copie, pas à jour, autre chemin) : l'appel va alors à la passerelle.
type LocalLogs interface {
	Serve(ctx context.Context, nodeID, nodeName, method, pathAndQuery string, body []byte) (status int, data []byte, ok bool)
}

var (
	localMu   sync.RWMutex
	localLogs LocalLogs
)

// SetLocalLogs branche (ou, avec nil, débranche) la lecture des logs sur le volume de logs de l'Admin.
func SetLocalLogs(l LocalLogs) {
	localMu.Lock()
	localLogs = l
	localMu.Unlock()
}


func serveLocal(ctx context.Context, t Target, method, path string, body []byte) (int, []byte, bool) {
	localMu.RLock()
	l := localLogs
	localMu.RUnlock()
	if l == nil || t.ID == "" {
		return 0, nil, false
	}
	return l.Serve(ctx, t.ID, t.NodeName, method, path, body)
}
