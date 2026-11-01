// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router_test

import (
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestTableLabelHost(t *testing.T) {
	tbl := &router.Table{}
	wild := route("wild", "*.example.fr")
	app := route("app", "app.example.fr")
	app.Aliases = []string{"www.example.fr"}
	tbl.Upsert(wild)
	tbl.Upsert(app)

	for host, want := range map[string]string{
		"app.example.fr":   "app.example.fr",
		"APP.Example.FR.":  "app.example.fr",
		"www.example.fr":   "www.example.fr",
		"x1234.example.fr": "*.example.fr",
		"autre.example.fr": "*.example.fr",
		"a.b.c.example.fr": "",
	} {
		r, ok := tbl.ByHost(host)
		if !ok {
			if want != "" {
				t.Errorf("%q devrait être servi", host)
			}
			continue
		}
		if got := tbl.LabelHost(host, r); got != want {
			t.Errorf("LabelHost(%q) = %q, attendu %q", host, got, want)
		}
	}
}
