// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"os"
	"testing"
)

func TestMergeProviderParams_EnvFallbackCloudflare(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "env-token-xyz")
	t.Setenv("CF_ZONE_ID", "zone-from-env")

	params := mergeProviderParams("cloudflare", map[string]any{
		"api_token": "", // vide → fallback env
	})
	if params["api_token"] != "env-token-xyz" {
		t.Fatalf("api_token = %q, want env-token-xyz", params["api_token"])
	}
	if params["zone_id"] != "zone-from-env" {
		t.Fatalf("zone_id = %q, want zone-from-env", params["zone_id"])
	}
}

func TestMergeProviderParams_DomainOverridesEnv(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "env-token")
	params := mergeProviderParams("cloudflare", map[string]any{
		"api_token": "domain-token",
	})
	if params["api_token"] != "domain-token" {
		t.Fatalf("api_token = %q, want domain-token", params["api_token"])
	}
}

func TestMergeProviderParams_NilCredentials(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "only-env")
	_ = os.Unsetenv("CF_ZONE_ID")
	params := mergeProviderParams("cloudflare", nil)
	if params["api_token"] != "only-env" {
		t.Fatalf("api_token = %q, want only-env", params["api_token"])
	}
}

func TestAcmeNames_NoImplicitApex(t *testing.T) {
	got := acmeNames("*.example.com")
	if len(got) != 1 || got[0] != "*.example.com" {
		t.Fatalf("wildcard: got %v, want [*.example.com]", got)
	}
	got = acmeNames("app.example.com")
	if len(got) != 1 || got[0] != "app.example.com" {
		t.Fatalf("host: got %v, want [app.example.com]", got)
	}
}
