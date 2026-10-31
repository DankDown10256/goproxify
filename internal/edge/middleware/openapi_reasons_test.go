// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const reasonsSpec = `{"openapi":"3.1.0","paths":{
 "/users/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],"responses":{"200":{"description":"ok"}}}},
 "/items":{"post":{"requestBody":{"content":{"application/json":{}}},"responses":{"201":{"description":"ok"}}}}}}`

func reasonsCfg(mode, unknown string, block ...string) *router.OpenAPIConfig {
	return &router.OpenAPIConfig{Enabled: true, Mode: mode, UnknownPaths: unknown, BlockReasons: block, Spec: json.RawMessage(reasonsSpec)}
}

// oaServe passe une requête dans le contrôle et rend le code, l'en-tête Allow et le verdict.
func oaServe(t *testing.T, cfg *router.OpenAPIConfig, method, target, contentType string) (int, string, OpenAPIOutcome) {
	t.Helper()
	h := OpenAPI("h", cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(method, target, strings.NewReader(`{"a":1}`))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	ctx, out := WithOpenAPIOutcome(r.Context())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r.WithContext(ctx))
	return rec.Code, rec.Header().Get("Allow"), *out
}

func TestOpenAPIBlockReasonsRefuseOnlyTheListedViolations(t *testing.T) {
	cfg := reasonsCfg("detect", "block", "unknown_path")
	if code, _, out := oaServe(t, cfg, "GET", "/nope", ""); code != http.StatusNotFound || out.Reason != "unknown_path" || !out.Blocked {
		t.Errorf("chemin inconnu listé : %d %+v", code, out)
	}
	if code, _, out := oaServe(t, cfg, "DELETE", "/users/1", ""); code != http.StatusNoContent || out.Reason != "unknown_method" || out.Blocked {
		t.Errorf("méthode inconnue non listée : %d %+v", code, out)
	}
	if code, _, out := oaServe(t, cfg, "GET", "/users/abc", ""); code != http.StatusNoContent || out.Reason != "invalid_param" || out.Blocked {
		t.Errorf("paramètre invalide non listé : %d %+v", code, out)
	}
	if code, _, out := oaServe(t, cfg, "GET", "/users/12", ""); code != http.StatusNoContent || out.Reason != "" || out.Blocked {
		t.Errorf("requête conforme : %d %+v", code, out)
	}

	cfg = reasonsCfg("detect", "block", "invalid_param", "unknown_method", "unsupported_media")
	if code, _, out := oaServe(t, cfg, "GET", "/users/abc", ""); code != http.StatusBadRequest || !out.Blocked {
		t.Errorf("paramètre invalide listé : %d %+v", code, out)
	}
	if code, allow, out := oaServe(t, cfg, "DELETE", "/users/1", ""); code != http.StatusMethodNotAllowed || allow != "GET" || !out.Blocked {
		t.Errorf("méthode inconnue listée : %d Allow=%q %+v", code, allow, out)
	}
	if code, _, out := oaServe(t, cfg, "POST", "/items", "text/xml"); code != http.StatusUnsupportedMediaType || !out.Blocked {
		t.Errorf("type de contenu listé : %d %+v", code, out)
	}
	if code, _, out := oaServe(t, cfg, "GET", "/nope", ""); code != http.StatusNoContent || out.Blocked {
		t.Errorf("chemin inconnu non listé : %d %+v", code, out)
	}
}

func TestOpenAPIModeBlockRefusesEverythingAndDetectNothing(t *testing.T) {
	block := reasonsCfg("block", "block", "unknown_path") // la liste n'a aucun effet en block
	for _, tc := range []struct {
		method, target string
		want           int
	}{{"GET", "/nope", 404}, {"DELETE", "/users/1", 405}, {"GET", "/users/abc", 400}} {
		if code, _, _ := oaServe(t, block, tc.method, tc.target, ""); code != tc.want {
			t.Errorf("block %s %s : %d, attendu %d", tc.method, tc.target, code, tc.want)
		}
	}
	detect := reasonsCfg("detect", "block")
	for _, tc := range []struct{ method, target string }{{"GET", "/nope"}, {"DELETE", "/users/1"}, {"GET", "/users/abc"}} {
		if code, _, out := oaServe(t, detect, tc.method, tc.target, ""); code != http.StatusNoContent || out.Blocked || out.Reason == "" {
			t.Errorf("detect %s %s : %d %+v", tc.method, tc.target, code, out)
		}
	}
}

func TestOpenAPIUnknownPathsAllowIsNotAViolation(t *testing.T) {
	cfg := reasonsCfg("block", "allow")
	code, _, out := oaServe(t, cfg, "GET", "/nope", "")
	if code != http.StatusNoContent || out.Reason != "" || out.Blocked {
		t.Errorf("unknown_paths=allow : %d %+v", code, out)
	}
	if code, _, out := oaServe(t, cfg, "DELETE", "/users/1", ""); code != http.StatusNoContent || out.Reason != "" {
		t.Errorf("méthode inconnue avec unknown_paths=allow : %d %+v", code, out)
	}
}

func TestValidateOpenAPIBlockReasons(t *testing.T) {
	if errs := ValidateOpenAPIConfig(reasonsCfg("detect", "block", OpenAPIReasons...)); len(errs) != 0 {
		t.Errorf("toutes les raisons connues : %v", errs)
	}
	errs := ValidateOpenAPIConfig(reasonsCfg("detect", "block", "unknown_path", "inconnue"))
	if len(errs) != 1 || !strings.Contains(errs[0], "inconnue") {
		t.Errorf("raison inconnue : %v", errs)
	}
}
