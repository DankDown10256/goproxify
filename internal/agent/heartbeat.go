// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/agent/wsclient"
)

// heartbeatLoop envoie un heartbeat à la passerelle toutes les 30 s.
// Si ws est non-nil et actif, le heartbeat est envoyé via WS ; sinon, fallback HTTP
// (POST /internal/v1/agent/heartbeat) pour que la passerelle enregistre toujours l'Agent
// dans son nodeStore — sinon l'Admin le laisse en « Non connecté » / declared.
func heartbeatLoop(ctx context.Context, edgeEndpoint, authToken, nodeName, version, internalEndpoint string, containerRuntimes []string, agentConfig any, ws *wsclient.Client, tokenUpdate <-chan string, repairFn func() string, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var send func()
	send = func() {
		var cpuPct, memPct float64
		if prev, err := telemetry.ReadCPUStat(); err == nil {
			time.Sleep(200 * time.Millisecond)
			if cur, err := telemetry.ReadCPUStat(); err == nil {
				cpuPct = telemetry.CPUUsagePct(prev, cur)
			}
		}
		if mem, err := telemetry.ReadMemStat(); err == nil {
			memPct = mem.UsagePct()
		}

		// Priorité WS si le client est connecté
		if ws != nil && ws.IsActive() {
			ws.SendHeartbeat(cpuPct, memPct, containerRuntimes, internalEndpoint, agentConfig)
			return
		}

		// Fallback HTTP — discovery / proxy peuvent fonctionner sans WS ;
		// sans ce heartbeat la passerelle ne listait plus l'Agent comme online.
		if edgeEndpoint == "" || authToken == "" || nodeName == "" {
			return
		}
		payload := map[string]any{
			"node_name":          nodeName,
			"role":               "agent",
			"version":            version,
			"endpoint":           internalEndpoint,
			"cpu_pct":            cpuPct,
			"mem_pct":            memPct,
			"container_runtimes": containerRuntimes,
			"agent_config":       agentConfig,
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			edgeEndpoint+"/internal/v1/agent/heartbeat", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Warn("heartbeat: Passerelle injoignable", "err", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			log.Warn("heartbeat: token révoqué — re-appairage", "status", resp.StatusCode)
			if repairFn != nil {
				if t := repairFn(); t != "" {
					authToken = t
					send() // réessai immédiat avec le nouveau token
				}
			}
			return
		}
		if resp.StatusCode >= 400 {
			log.Warn("heartbeat: Passerelle a refusé", "status", resp.StatusCode)
		}
	}

	send() // envoi immédiat au démarrage
	for {
		select {
		case <-ctx.Done():
			log.Debug("heartbeat: arrêt")
			return
		case t := <-tokenUpdate:
			authToken = t
			send() // heartbeat immédiat avec le nouveau token
		case <-ticker.C:
			send()
		}
	}
}

// reportEvent envoie un événement de lifecycle/santé à la passerelle.
// Priorité WS (message `event`) si le client est actif ; sinon POST HTTP.
func reportEvent(ctx context.Context, edgeEndpoint, authToken, nodeName, containerID, eventType, detail string, ws *wsclient.Client, log *slog.Logger) {
	payload := map[string]any{
		"node_name":    nodeName,
		"container_id": containerID,
		"event_type":   eventType,
		"detail":       detail,
	}
	if ws != nil && ws.IsActive() {
		ws.SendEvent(payload)
		return
	}
	if edgeEndpoint == "" || authToken == "" {
		return
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		edgeEndpoint+"/internal/v1/agent/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warn("reportEvent: Passerelle injoignable", "event", eventType, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Warn("reportEvent: Passerelle a refusé", "event", eventType, "status", resp.StatusCode)
	}
}
