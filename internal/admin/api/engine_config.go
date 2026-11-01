// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/vincamok/goproxify/internal/edge/engines"
)

// decodeEngineConfig lit le corps d'une requête de configuration d'un moteur de sécurité (Ephor,
// Seuils multi-passerelles, CrowdSec), le valide avec son manifeste (clés connues, valeurs cohérentes) et le décode dans
// into. prev, la configuration enregistrée, fournit les secrets qu'un envoi omet ou renvoie masqués.
// En cas d'échec la réponse (400) est écrite et le résultat est false.
func decodeEngineConfig(w http.ResponseWriter, r *http.Request, typ string, into any, prev ...json.RawMessage) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || !json.Valid(body) {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return false
	}
	if len(prev) > 0 && len(prev[0]) > 0 {
		body = engines.KeepSecrets(typ, prev[0], body)
	}
	if err := engines.Validate(typ, body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	if raw, ok := into.(*json.RawMessage); ok {
		*raw = body
		return true
	}
	if err := json.Unmarshal(body, into); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return false
	}
	return true
}

// EngineTypesHandler GET /api/v1/security/engine-types : manifestes d'Ephor, des Seuils multi-passerelles et de CrowdSec.
type EngineTypesHandler struct{}

func (EngineTypesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, engines.Manifests())
}
