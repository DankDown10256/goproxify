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

// heartbeatLoop envoie un heartbeat au Core toutes les 30 s.
// Si ws est non-nil et actif, le heartbeat est envoyé via WS ; sinon, fallback HTTP
// (POST /internal/v1/agent/heartbeat) pour que le Core enregistre toujours l'Agent
// dans son nodeStore — sinon l'Admin le laisse en « Non connecté » / declared.
func heartbeatLoop(ctx context.Context, coreEndpoint, authToken, nodeName, version, internalEndpoint string, containerRuntimes []string, ws *wsclient.Client, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	send := func() {
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
			ws.SendHeartbeat(cpuPct, memPct, containerRuntimes, internalEndpoint)
			return
		}

		// Fallback HTTP — discovery / proxy peuvent fonctionner sans WS ;
		// sans ce heartbeat le Core ne listait plus l'Agent comme online.
		if coreEndpoint == "" || authToken == "" || nodeName == "" {
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
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			coreEndpoint+"/internal/v1/agent/heartbeat", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Warn("heartbeat: Core injoignable", "err", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			log.Warn("heartbeat: Core a refusé", "status", resp.StatusCode)
		}
	}

	send() // envoi immédiat au démarrage
	for {
		select {
		case <-ctx.Done():
			log.Debug("heartbeat: arrêt")
			return
		case <-ticker.C:
			send()
		}
	}
}

// reportEvent envoie un événement de lifecycle/santé au Core.
// Priorité WS (message `event`) si le client est actif ; sinon POST HTTP.
func reportEvent(ctx context.Context, coreEndpoint, authToken, nodeName, containerID, eventType, detail string, ws *wsclient.Client, log *slog.Logger) {
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
	if coreEndpoint == "" || authToken == "" {
		return
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		coreEndpoint+"/internal/v1/agent/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warn("reportEvent: Core injoignable", "event", eventType, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Warn("reportEvent: Core a refusé", "event", eventType, "status", resp.StatusCode)
	}
}
