// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import "os"

// ProviderConfigFromEnv construit un ProviderConfig depuis les variables
// d'environnement standard pour le fournisseur DNS donné.
func ProviderConfigFromEnv(dnsType string) ProviderConfig {
	params := map[string]string{}
	switch dnsType {
	case "ovh":
		params["endpoint"] = os.Getenv("OVH_ENDPOINT")
		params["app_key"] = os.Getenv("OVH_APPLICATION_KEY")
		params["app_secret"] = os.Getenv("OVH_APPLICATION_SECRET")
		params["consumer_key"] = os.Getenv("OVH_CONSUMER_KEY")
		params["zone"] = os.Getenv("OVH_ZONE")
	case "cloudflare":
		params["api_token"] = os.Getenv("CF_API_TOKEN")
		params["zone_id"] = os.Getenv("CF_ZONE_ID")
	case "gandi":
		params["api_key"] = os.Getenv("GANDI_API_KEY")
	case "route53":
		params["hosted_zone_id"] = os.Getenv("AWS_HOSTED_ZONE_ID")
		// AWS SDK lit AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION nativement
	case "hetzner":
		params["api_token"] = os.Getenv("HETZNER_API_KEY")
		params["zone_id"] = os.Getenv("HETZNER_ZONE_ID")
	}
	return ProviderConfig{Type: dnsType, Params: params}
}
