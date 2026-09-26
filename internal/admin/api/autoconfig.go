// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// AgentAutoConfigurer compare périodiquement la config déclarée (wizard) de chaque agent
// avec la config rapportée via heartbeat, et pousse un patch de configuration si elles diffèrent.
// Cela permet à un agent fraîchement déployé de se configurer automatiquement
// sans intervention manuelle dans l'UI.
type AgentAutoConfigurer struct {
	DB    *sql.DB
	Log   *slog.Logger
	Nodes *NodesHandler

	mu      sync.Mutex
	pushed  map[string]time.Time // nodeName → dernière tentative de push
}

// Start lance la boucle de vérification en arrière-plan.
func (a *AgentAutoConfigurer) Start(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	// Premier passage immédiat après le démarrage.
	a.run(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.run(ctx)
		}
	}
}

func (a *AgentAutoConfigurer) run(ctx context.Context) {
	// Lire tous les nœuds déclarés avec une config non vide.
	rows, err := a.DB.QueryContext(ctx,
		`SELECT name, config FROM declared_nodes WHERE role='agent' AND config != '' AND config != '{}'`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeName, cfgStr string
		if err := rows.Scan(&nodeName, &cfgStr); err != nil {
			continue
		}
		var declaredCfg map[string]any
		if err := json.Unmarshal([]byte(cfgStr), &declaredCfg); err != nil {
			continue
		}

		// Récupérer la config live de l'agent depuis les passerelles.
		liveAgents := a.Nodes.fetchAgentNodesFromEdges(ctx)
		var liveAgent *nodeRow
		for i, ag := range liveAgents {
			if ag.NodeName == nodeName {
				liveAgent = &liveAgents[i]
				break
			}
		}
		if liveAgent == nil {
			// Agent pas encore en ligne — rien à faire.
			continue
		}

		// Cooldown : ne pas re-pousser si on a déjà tenté dans les 5 dernières minutes.
		a.mu.Lock()
		if a.pushed == nil {
			a.pushed = map[string]time.Time{}
		}
		if since := time.Since(a.pushed[nodeName]); since < 5*time.Minute {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		// Comparer les sections clés de la config déclarée avec la config live.
		if !a.needsPatch(declaredCfg, liveAgent.AgentConfig) {
			continue
		}

		// Construire le patch : sections du declared_config qui diffèrent.
		patch := a.buildPatch(declaredCfg, liveAgent.AgentConfig)
		if len(patch) == 0 {
			continue
		}

		patchJSON, err := json.Marshal(patch)
		if err != nil {
			continue
		}

		a.mu.Lock()
		a.pushed[nodeName] = time.Now()
		a.mu.Unlock()

		// Pousser via relayToAgent (même chemin que le modal configure).
		payload := map[string]any{
			"action": "configure",
			"patch":  json.RawMessage(patchJSON),
		}
		if err := a.Nodes.relayToAgent(ctx, nodeName, payload); err != nil {
			a.Log.Warn("autoconfig: push échoué", "agent", nodeName, "err", err)
			continue
		}
		a.Log.Info("autoconfig: config déclarée poussée à l'agent", "agent", nodeName)
	}
}

// needsPatch retourne true si la config déclarée contient des réglages absents ou différents
// dans la config live de l'agent.
func (a *AgentAutoConfigurer) needsPatch(declared map[string]any, liveRaw json.RawMessage) bool {
	if len(liveRaw) == 0 {
		return true
	}
	var live map[string]any
	if err := json.Unmarshal(liveRaw, &live); err != nil {
		return true
	}

	// Vérifier portainer.enabled
	if dp, ok := declared["portainer"].(map[string]any); ok {
		declEnabled, _ := dp["enabled"].(bool)
		if declEnabled {
			lp, _ := live["portainer"].(map[string]any)
			liveEnabled, _ := lp["enabled"].(bool)
			if !liveEnabled {
				return true
			}
		}
	}

	// Vérifier control_plane.edge_endpoint
	if dcp, ok := declared["control_plane"].(map[string]any); ok {
		declEP, _ := dcp["edge_endpoint"].(string)
		if declEP != "" {
			lcp, _ := live["control_plane"].(map[string]any)
			liveEP, _ := lcp["edge_endpoint"].(string)
			if liveEP != declEP {
				return true
			}
		}
	}

	return false
}

// buildPatch retourne les sections déclarées à pousser.
// Les secrets (api_key, auth_token, password) avec valeur vide sont omis pour
// ne pas écraser les secrets déjà présents dans agent.json.
func (a *AgentAutoConfigurer) buildPatch(declared map[string]any, liveRaw json.RawMessage) map[string]any {
	var live map[string]any
	if len(liveRaw) > 0 {
		json.Unmarshal(liveRaw, &live) //nolint:errcheck
	}

	patch := map[string]any{}
	secretKeys := map[string]bool{"api_key": true, "auth_token": true, "password": true, "password_hash": true}

	for section, declVal := range declared {
		switch section {
		case "portainer", "docker", "control_plane":
			dp, ok := declVal.(map[string]any)
			if !ok {
				continue
			}
			// Ne patcher que si la section diffère.
			sectionPatch := map[string]any{}
			lp, _ := live[section].(map[string]any)
			for k, v := range dp {
				if secretKeys[k] {
					// Ne pas écraser un secret existant par une valeur vide ou masquée.
					if s, ok := v.(string); ok && (s == "" || s == "••••••••") {
						continue
					}
				}
				sectionPatch[k] = v
			}
			if len(sectionPatch) > 0 {
				// Ne patcher la section que si au moins une valeur diffère.
				for k, v := range sectionPatch {
					lv := lp[k]
					if jsonEq(v, lv) {
						delete(sectionPatch, k)
					}
				}
				if len(sectionPatch) > 0 {
					patch[section] = sectionPatch
				}
			}
		}
	}
	return patch
}

func jsonEq(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

// fetchDeclaredConfig lit la declared_config d'un agent depuis la DB.
// Utilisé par l'auto-configurer.
func fetchDeclaredConfig(db *sql.DB, nodeName string) map[string]any {
	var cfgStr string
	db.QueryRow(`SELECT config FROM declared_nodes WHERE name=? AND role='agent'`, nodeName).Scan(&cfgStr) //nolint:errcheck
	if cfgStr == "" {
		return nil
	}
	var cfg map[string]any
	json.Unmarshal([]byte(cfgStr), &cfg) //nolint:errcheck
	return cfg
}
