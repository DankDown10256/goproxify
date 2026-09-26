// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/vincamok/goproxify/internal/edge/proxystore"
)

func runMigrateYAML() {
	root := dataRootFromEnv()
	st := proxystore.New(root)

	results := st.MigrateJSONToYAML()
	if len(results) == 0 {
		fmt.Println("Aucun fichier .json trouvé — rien à convertir.")
		return
	}

	ok, failed := 0, 0
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "ERREUR  %s → %v\n", r.JSON, r.Err)
			failed++
		} else {
			fmt.Printf("OK      %s → %s\n", r.JSON, r.YAML)
			ok++
		}
	}
	fmt.Printf("\n%d converti(s), %d erreur(s).\n", ok, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// dataRootFromEnv mirrors the logic in internal/edge/proxyfiles.go.
func dataRootFromEnv() string {
	if p := os.Getenv("GPX_DATA_PATH"); p != "" {
		return p
	}
	if p := os.Getenv("GPX_EDGE_CACHE_PATH"); p != "" {
		for i := len(p) - 1; i >= 0; i-- {
			if p[i] == '/' || p[i] == '\\' {
				return p[:i]
			}
		}
		return "."
	}
	return "/etc/goproxify"
}
