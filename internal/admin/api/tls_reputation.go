// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/engines"
)

// TLSReputation retourne, par passerelle, la réputation apprise de ses empreintes TLS et les empreintes qu'elle propose pour
// custom_lists.tls_fingerprints, avec leurs preuves (ADR 0020, étape 4.c). Les passerelles proposent, l'administrateur accepte.
func TLSReputation(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.TLSReputation(ctx, gatewayName(ctx, db, edgeParam))
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// getTLSReputation : GET /api/v1/security/tls-reputation[?edge=<passerelle>].
func (h *SecurityHandler) getTLSReputation(w http.ResponseWriter, r *http.Request) {
	out, err := TLSReputation(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"))
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}

// acceptTLSReputation : POST /api/v1/security/tls-reputation/accept — ajoute des empreintes proposées à custom_lists.tls_fingerprints
// de la configuration d'Ephor (celle du groupe ou de la passerelle visée par ?edge=, sinon la globale). Seules les empreintes que les
// passerelles proposent à cet instant peuvent être ajoutées ; la configuration doit exister. `all` ajoute toutes les propositions.
func (h *SecurityHandler) acceptTLSReputation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JA4s []string `json:"ja4s"`
		All  bool     `json:"all"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || (!body.All && len(body.JA4s) == 0) {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	scope, ref := h.scope(r)
	proposed, err := currentTLSProposals(r.Context(), h.DB, h.Edge, ref)
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	var want []string
	if body.All {
		for ja4 := range proposed {
			want = append(want, ja4)
		}
		sort.Strings(want)
	} else {
		for _, f := range body.JA4s {
			f = strings.TrimSpace(f)
			if _, ok := proposed[strings.ToLower(f)]; !ok {
				secJSONErr(w, fmt.Errorf("%q n'est pas proposée par les passerelles : seules les propositions actuelles peuvent être ajoutées", f), http.StatusConflict)
				return
			}
			want = append(want, proposed[strings.ToLower(f)])
		}
	}
	raw, ok := readScopedSetting(r.Context(), h.DB, "threat_engine_config", scope, ref)
	if !ok {
		secJSONErr(w, errors.New("Ephor n'a pas de configuration enregistrée pour cette portée : enregistrez-la d'abord"), http.StatusConflict)
		return
	}
	merged, added, already, err := addTLSFingerprints(raw, want)
	if err != nil {
		secJSONErr(w, err, http.StatusBadRequest)
		return
	}
	if len(added) > 0 {
		if err := engines.Validate(engines.Ephor, merged); err != nil {
			secJSONErr(w, err, http.StatusBadRequest)
			return
		}
		if _, err := h.DB.ExecContext(r.Context(),
			`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatConfigKey(scope), string(merged)); err != nil {
			secJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		if h.OnThreatConfigChange != nil {
			h.OnThreatConfigChange(scope, merged)
		}
	}
	jsonOK(w, map[string]any{"added": added, "already": already})
}

// currentTLSProposals rend les empreintes que les passerelles visées proposent à cet instant (clé en minuscules → forme proposée).
func currentTLSProposals(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam string) (map[string]string, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, _, err := edge.TLSReputation(ctx, gatewayName(ctx, db, edgeParam))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, g := range gws {
		for _, p := range g.Reputation.Proposals {
			out[strings.ToLower(p.JA4)] = p.JA4
		}
	}
	return out, nil
}

// addTLSFingerprints ajoute des empreintes à custom_lists.tls_fingerprints d'une configuration d'Ephor en conservant tout le reste
// tel quel. Rend la configuration, les empreintes ajoutées et celles qui y étaient déjà.
func addTLSFingerprints(raw string, want []string) (merged json.RawMessage, added, already []string, err error) {
	var cfg map[string]json.RawMessage
	if err = json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("configuration d'Ephor illisible : %w", err)
	}
	lists := map[string]json.RawMessage{}
	if b, ok := cfg["custom_lists"]; ok {
		if err = json.Unmarshal(b, &lists); err != nil {
			return nil, nil, nil, fmt.Errorf("custom_lists illisible : %w", err)
		}
	}
	var fps []string
	if b, ok := lists["tls_fingerprints"]; ok {
		if err = json.Unmarshal(b, &fps); err != nil {
			return nil, nil, nil, fmt.Errorf("custom_lists.tls_fingerprints illisible : %w", err)
		}
	}
	have := map[string]bool{}
	for _, f := range fps {
		have[strings.ToLower(strings.TrimSpace(f))] = true
	}
	added, already = []string{}, []string{}
	for _, f := range want {
		if have[strings.ToLower(f)] {
			already = append(already, f)
			continue
		}
		have[strings.ToLower(f)] = true
		fps = append(fps, f)
		added = append(added, f)
	}
	b, _ := json.Marshal(fps)
	lists["tls_fingerprints"] = b
	lb, _ := json.Marshal(lists)
	cfg["custom_lists"] = lb
	merged, err = json.Marshal(cfg)
	return merged, added, already, err
}
