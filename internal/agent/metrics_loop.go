// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/agent/wsclient"
	corews "github.com/vincamok/goproxify/internal/core/ws"
)

const metricsInterval = 10 * time.Second

// metricsLoop streame CPU/mem/IO des conteneurs goproxify.enable vers le Core (WS).
func metricsLoop(ctx context.Context, client *agentdocker.Client, agentName string, ws *wsclient.Client, log *slog.Logger) {
	if client == nil || ws == nil {
		return
	}
	var prevBlkio sync.Map // containerID → uint64

	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()

	send := func() {
		if !ws.IsActive() {
			return
		}
		var hostCPU, hostMem float64
		if prev, err := telemetry.ReadCPUStat(); err == nil {
			time.Sleep(150 * time.Millisecond)
			if cur, err := telemetry.ReadCPUStat(); err == nil {
				hostCPU = telemetry.CPUUsagePct(prev, cur)
			}
		}
		if mem, err := telemetry.ReadMemStat(); err == nil {
			hostMem = mem.UsagePct()
		}

		var containers []agentdocker.ContainerSummary
		if err := client.Get(ctx, "/containers/json?all=false", &containers); err != nil {
			log.Debug("metrics: list containers", "err", err)
			return
		}

		payload := corews.AgentMetricsPayload{
			AgentName:  agentName,
			CPUPct:     hostCPU,
			MemPct:     hostMem,
			Containers: make([]corews.ContainerMetric, 0),
		}
		intervalS := metricsInterval.Seconds()
		for _, c := range containers {
			if !enabledLabel(c.Labels) {
				continue
			}
			ip := containerIP(c)
			var prev uint64
			if v, ok := prevBlkio.Load(c.ID); ok {
				prev = v.(uint64)
			}
			st, err := agentdocker.ReadContainerStats(ctx, client, c.ID, prev, intervalS)
			if err != nil {
				continue
			}
			prevBlkio.Store(c.ID, st.BlkioBytes)
			name := ""
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			payload.Containers = append(payload.Containers, corews.ContainerMetric{
				ContainerID: c.ID,
				Name:        name,
				IP:          ip,
				CPUPct:      st.CPUPct,
				MemPct:      st.MemPct,
				DiskIOPCT:   st.DiskIOPCT,
			})
		}
		ws.SendMetrics(payload)
	}

	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func enabledLabel(labels map[string]string) bool {
	if labels == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(labels[agentdocker.LabelEnable]))
	return v == "true" || v == "1" || v == "yes"
}

func containerIP(c agentdocker.ContainerSummary) string {
	for _, net := range c.NetworkSettings.Networks {
		if net.IPAddress != "" {
			return net.IPAddress
		}
	}
	return ""
}
