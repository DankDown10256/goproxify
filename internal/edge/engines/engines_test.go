// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package engines

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestManifestsOrderAndEphorPaths(t *testing.T) {
	var types []string
	for _, m := range Manifests() {
		types = append(types, m.Type)
	}
	if strings.Join(types, ",") != "ephor,fleet,crowdsec,waf" {
		t.Fatalf("types = %v", types)
	}
	sm, _ := Manifest(Ephor)
	have := map[string]bool{}
	for _, f := range sm.Fields {
		have[f.Key] = true
	}
	for _, k := range []string{"enabled", "mode", "ip_score.ban_threshold", "ip_score.errors.weights", "escalation.factor", "lists.ip_sources", "custom_lists.tls_fingerprints", "whitelist.paths", "tarpit.delay_ms", "ban_duration", "behavior.mode", "behavior.signals", "behavior.tls_families", "behavior.no_trust", "behavior.reference_min_age"} {
		if !have[k] {
			t.Errorf("champ %q absent du manifeste Ephor", k)
		}
	}
}

// Une configuration que l'interface et les passerelles utilisent déjà doit rester valide.
func TestValidateAcceptsRealConfigs(t *testing.T) {
	ok := map[string]string{
		Ephor: `{"enabled":true,"mode":"block","score_threshold":5,"global_rps":500,"rate_limit":20,"rate_window":"1s","error_threshold":30,"error_window":"10s","ban_duration":"24h",
			"ip_score":{"enabled":true,"ban_threshold":10,"half_life":"10m","errors":{"enabled":true,"weights":{"404":0.5,"405":2},"routes":[{"prefix":"/wp-admin","factor":3}]}},
			"escalation":{"enabled":true,"factor":2,"window":"168h","max_duration":"720h"},
			"lists":{"ua_enabled":true,"ip_sources":["https://example.com/list.txt"]},
			"custom_lists":{"ips":["203.0.113.0/24"],"uas":["badbot"],"paths":["/.env"],"tls_fingerprints":["e7d705a3286e19ea42f587b344ee6865"]},
			"whitelist":{"ips":["10.0.0.0/8"],"paths":["/health"]},"tarpit":{"enabled":true,"delay_ms":3000,"max_concurrent":100},
			"behavior":{"mode":"detect","signals":{"ua_tls_mismatch":"block","no_assets":"off","asn_aggregate":"detect"},"tls_families":{"chromium":["8DAAF6152771"]},"no_trust":false,"reference_min_age":"24h"},
			"seasonal":{"mode":"detect","floor_rps":50,"fast_factor":8,"slow_sigmas":3,"min_hours":1}}`,
		Fleet:    `{"enabled":true,"window_sec":300,"max_errors":50,"ban_duration_sec":0,"trust_forwarded_for":true,"whitelist":["10.0.0.0/8","203.0.113.7"]}`,
		CrowdSec: `{"enabled":true,"api_url":"http://localhost:8080","api_key":"k"}`,
		WAF:      `{"enabled":false}`,
	}
	for typ, body := range ok {
		if err := Validate(typ, json.RawMessage(body)); err != nil {
			t.Errorf("%s : %v", typ, err)
		}
	}
	for _, typ := range []string{Ephor, Fleet, CrowdSec, WAF} {
		if err := Validate(typ, nil); err != nil {
			t.Errorf("%s vide : %v", typ, err)
		}
	}
	if err := Validate(CrowdSec, json.RawMessage(`{"enabled":false}`)); err != nil {
		t.Errorf("crowdsec désactivé sans clé : %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	bad := map[string]struct{ typ, body string }{
		"ephor clé inconnue":         {Ephor, `{"enabled":true,"modee":"block"}`},
		"ephor clé imbriquée":        {Ephor, `{"ip_score":{"ban_treshold":3}}`},
		"ephor mode":                 {Ephor, `{"mode":"off"}`},
		"ephor saisonnière block":    {Ephor, `{"seasonal":{"mode":"block"}}`},
		"ephor saisonnière facteur":  {Ephor, `{"seasonal":{"fast_factor":1}}`},
		"ephor durée illisible":      {Ephor, `{"ban_duration":"un jour"}`},
		"ephor durée négative":       {Ephor, `{"rate_window":"-5s"}`},
		"ephor seuil négatif":        {Ephor, `{"error_threshold":-1}`},
		"ephor IP":                   {Ephor, `{"whitelist":{"ips":["10.0.0.0/99"]}}`},
		"ephor code HTTP":            {Ephor, `{"ip_score":{"errors":{"weights":{"abc":1}}}}`},
		"ephor poids négatif":        {Ephor, `{"ip_score":{"errors":{"weights":{"404":-1}}}}`},
		"ephor préfixe route":        {Ephor, `{"ip_score":{"errors":{"routes":[{"prefix":"admin","factor":1}]}}}`},
		"ephor source":               {Ephor, `{"lists":{"ip_sources":["ftp://x"]}}`},
		"ephor chemin":               {Ephor, `{"whitelist":{"paths":["health"]}}`},
		"ephor tarpit":               {Ephor, `{"tarpit":{"enabled":true,"delay_ms":90000}}`},
		"ephor type":                 {Ephor, `{"global_rps":"vite"}`},
		"ephor behavior mode":        {Ephor, `{"behavior":{"mode":"bloque"}}`},
		"ephor behavior signal":      {Ephor, `{"behavior":{"signals":{"ua_tls_mismach":"block"}}}`},
		"ephor behavior signal mode": {Ephor, `{"behavior":{"signals":{"no_assets":"maybe"}}}`},
		"ephor behavior empreinte":   {Ephor, `{"behavior":{"tls_families":{"chromium":["pas-un-hash"]}}}`},
		"ephor behavior famille":     {Ephor, `{"behavior":{"tls_families":{"":["8daaf6152771"]}}}`},
		"ephor behavior âge":         {Ephor, `{"behavior":{"reference_min_age":"9000h"}}`},
		"fleet clé":                  {Fleet, `{"window":300}`},
		"fleet négatif":              {Fleet, `{"max_errors":-3}`},
		"fleet liste blanche":        {Fleet, `{"whitelist":["nope"]}`},
		"crowdsec URL":               {CrowdSec, `{"api_url":"localhost:8080"}`},
		"crowdsec sans clé":          {CrowdSec, `{"enabled":true,"api_url":"http://localhost:8080"}`},
		"crowdsec clé inconnue":      {CrowdSec, `{"apikey":"k"}`},
		"waf clé inconnue":           {WAF, `{"enable":true}`},
		"waf type":                   {WAF, `{"enabled":"oui"}`},
	}
	for name, c := range bad {
		if err := Validate(c.typ, json.RawMessage(c.body)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if Validate("autre", nil) == nil {
		t.Error("moteur inconnu accepté")
	}
}

func TestCrowdSecKeyMaskedAndKept(t *testing.T) {
	masked := string(MaskConfig(CrowdSec, json.RawMessage(`{"enabled":true,"api_url":"http://l","api_key":"SECRET"}`)))
	if strings.Contains(masked, "SECRET") || !strings.Contains(masked, modules.Masque) || !strings.Contains(masked, "http://l") {
		t.Fatalf("masquage = %s", masked)
	}
	kept := string(KeepSecrets(CrowdSec, json.RawMessage(`{"api_key":"SECRET","api_url":"http://l"}`), json.RawMessage(`{"enabled":true,"api_url":"http://m","api_key":"`+modules.Masque+`"}`)))
	if !strings.Contains(kept, "SECRET") || !strings.Contains(kept, "http://m") || strings.Contains(kept, modules.Masque) {
		t.Fatalf("conservation = %s", kept)
	}
	omitted := string(KeepSecrets(CrowdSec, json.RawMessage(`{"api_key":"SECRET"}`), json.RawMessage(`{"enabled":false}`)))
	if !strings.Contains(omitted, "SECRET") {
		t.Fatalf("secret omis = %s", omitted)
	}
}

func TestEphorChallengeSecretIsMasked(t *testing.T) {
	raw := json.RawMessage(`{"enabled":true,"ip_score":{"enabled":true},"challenge":{"mode":"detect","secret":"valeur-secrete"}}`)
	if err := Validate(Ephor, raw); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	if got := string(MaskConfig(Ephor, raw)); strings.Contains(got, "valeur-secrete") {
		t.Fatalf("le secret du défi doit être masqué à l'affichage : %s", got)
	}
	masked := MaskConfig(Ephor, raw)
	kept := KeepSecrets(Ephor, raw, masked)
	if !strings.Contains(string(kept), "valeur-secrete") {
		t.Fatalf("renvoyé masqué, le secret enregistré doit être conservé : %s", kept)
	}
	if err := Validate(Ephor, json.RawMessage(`{"challenge":{"mode":"block"}}`)); err == nil {
		t.Fatal("un défi sans score cumulé doit être refusé")
	}
}
