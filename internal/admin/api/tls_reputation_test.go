// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

const toolJA4 = "t13d1010h2_aaaaaaaaaaaa_bbbbbbbbbbbb"

func tlsReputationHandler(t *testing.T) (*SecurityHandler, *[]json.RawMessage) {
	t.Helper()
	h, paris, lyon := surfaceHandler(t)
	paris.TLSReputation = logapi.TLSReputationResponse{Enabled: true, Tracked: 40, Browsers: 3,
		Proposals: []threat.TLSProposal{{JA4: toolJA4, IPs: 60, Requests: 400, BadShare: 1, WAFShare: 0.33, ErrShare: 1}}}
	lyon.TLSReputation = logapi.TLSReputationResponse{Proposals: []threat.TLSProposal{}}
	var pushed []json.RawMessage
	h.OnThreatConfigChange = func(scope string, cfg any) { pushed = append(pushed, cfg.(json.RawMessage)) }
	return h, &pushed
}

func postRep(t *testing.T, h *SecurityHandler, target, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestTLSReputationIsReadFromEachGateway(t *testing.T) {
	h, _ := tlsReputationHandler(t)
	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/tls-reputation")
	if code != http.StatusOK {
		t.Fatalf("liste : %d %v", code, out)
	}
	byNode := map[string]map[string]any{}
	for _, g := range out["gateways"].([]any) {
		gw := g.(map[string]any)
		byNode[gw["node_name"].(string)] = gw["reputation"].(map[string]any)
	}
	props := byNode["paris"]["proposals"].([]any)
	if len(byNode) != 2 || len(props) != 1 || props[0].(map[string]any)["ja4"] != toolJA4 || props[0].(map[string]any)["ips"] != float64(60) {
		t.Fatalf("réputation de paris : %v", byNode)
	}
	if len(byNode["lyon"]["proposals"].([]any)) != 0 {
		t.Fatalf("lyon ne propose rien : %v", byNode["lyon"])
	}
	if code, out = surfCall(t, h, http.MethodGet, "/api/v1/security/tls-reputation?edge=lyon"); len(out["gateways"].([]any)) != 1 || code != http.StatusOK {
		t.Fatalf("edge=lyon : %d %v", code, out)
	}
}

func seedThreatConfig(t *testing.T, h *SecurityHandler, raw string) {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`, threatConfigKey(""), raw); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptingAProposalAddsItToTheCustomListAndKeepsTheRest(t *testing.T) {
	h, pushed := tlsReputationHandler(t)
	seedThreatConfig(t, h, `{"enabled":true,"ban_duration":"2h","custom_lists":{"ips":["203.0.113.0/24"],"tls_fingerprints":["e7d705a3286e19ea42f587b344ee6865"]}}`)

	code, out := postRep(t, h, "/api/v1/security/tls-reputation/accept", `{"ja4s":["`+strings.ToUpper(toolJA4)+`"]}`)
	if code != http.StatusOK || len(out["added"].([]any)) != 1 || out["added"].([]any)[0] != toolJA4 {
		t.Fatalf("acceptation : %d %v", code, out)
	}
	var cfg threat.Config
	var raw string
	if err := h.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, threatConfigKey("")).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.CustomLists.TLSFingerprints; len(got) != 2 || got[0] != "e7d705a3286e19ea42f587b344ee6865" || got[1] != toolJA4 {
		t.Fatalf("l'empreinte s'ajoute à la liste existante : %v", got)
	}
	if len(cfg.CustomLists.IPs) != 1 || !cfg.Enabled || cfg.BanDuration.Duration.String() != "2h0m0s" {
		t.Fatalf("le reste de la configuration est conservé : %+v", cfg)
	}
	if len(*pushed) != 1 {
		t.Fatalf("la configuration doit être poussée aux passerelles : %d poussées", len(*pushed))
	}

	code, out = postRep(t, h, "/api/v1/security/tls-reputation/accept", `{"all":true}`)
	if code != http.StatusOK || len(out["added"].([]any)) != 0 || len(out["already"].([]any)) != 1 || len(*pushed) != 1 {
		t.Fatalf("une empreinte déjà listée n'est ni rajoutée ni repoussée : %d %v", code, out)
	}
}

func TestOnlyCurrentProposalsCanBeAccepted(t *testing.T) {
	h, pushed := tlsReputationHandler(t)
	seedThreatConfig(t, h, `{"enabled":true}`)
	code, out := postRep(t, h, "/api/v1/security/tls-reputation/accept", `{"ja4s":["t13d9999h2_cccccccccccc_dddddddddddd"]}`)
	if code != http.StatusConflict {
		t.Fatalf("une empreinte que personne ne propose est refusée : %d %v", code, out)
	}
	if len(*pushed) != 0 {
		t.Fatal("un refus ne pousse rien")
	}
	if code, _ = postRep(t, h, "/api/v1/security/tls-reputation/accept", `{}`); code != http.StatusBadRequest {
		t.Fatalf("corps vide : %d", code)
	}
}

func TestAcceptingNeedsAnExistingEphorConfiguration(t *testing.T) {
	h, _ := tlsReputationHandler(t)
	if code, _ := postRep(t, h, "/api/v1/security/tls-reputation/accept", `{"all":true}`); code != http.StatusConflict {
		t.Fatalf("sans configuration d'Ephor : %d, attendu 409", code)
	}
}

func TestAddTLSFingerprintsCreatesTheListWhenAbsent(t *testing.T) {
	merged, added, _, err := addTLSFingerprints(`{"enabled":true}`, []string{toolJA4})
	if err != nil || len(added) != 1 {
		t.Fatalf("%v %v", added, err)
	}
	var cfg threat.Config
	if err := json.Unmarshal(merged, &cfg); err != nil || len(cfg.CustomLists.TLSFingerprints) != 1 {
		t.Fatalf("liste créée : %+v %v", cfg, err)
	}
	if _, _, _, err := addTLSFingerprints(`pas du JSON`, []string{toolJA4}); err == nil {
		t.Fatal("configuration illisible : erreur attendue")
	}
}
