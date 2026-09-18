// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

// OpenAPIHandler sert la spec OpenAPI et l'UI Scalar interactive.
type OpenAPIHandler struct{}

func (h *OpenAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/openapi.yaml" {
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(openapiSpec)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(scalarHTML))
}

const scalarHTML = `<!DOCTYPE html>
<html>
<head>
  <title>GoProxify API</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
  <script
    id="api-reference"
    data-url="/openapi.yaml"
    data-configuration='{"theme":"purple","defaultHttpClient":{"targetKey":"shell","clientKey":"curl"}}'
  ></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`
