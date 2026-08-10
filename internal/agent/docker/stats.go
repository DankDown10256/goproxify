// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"math"
)

// ContainerResourceStats est un snapshot CPU/mémoire/IO pour le LB adaptatif.
type ContainerResourceStats struct {
	CPUPct    float64
	MemPct    float64
	DiskIOPCT float64 // 0–100, normalisé depuis le débit blkio
	BlkioBytes uint64 // cumul read+write (pour delta entre polls)
}

// ReadContainerStats lit un snapshot via GET /containers/{id}/stats?stream=false.
// prevBlkio est le cumul blkio du poll précédent (0 si inconnu) ; prevIntervalS
// sert à normaliser le débit disque (ex. 10 s).
func ReadContainerStats(ctx context.Context, client *Client, containerID string, prevBlkio uint64, prevIntervalS float64) (ContainerResourceStats, error) {
	var raw struct {
		CPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage uint64 `json:"system_cpu_usage"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage uint64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage uint64 `json:"usage"`
			Limit uint64 `json:"limit"`
		} `json:"memory_stats"`
		BlkioStats struct {
			IoServiceBytesRecursive []struct {
				Op    string `json:"op"`
				Value uint64 `json:"value"`
			} `json:"io_service_bytes_recursive"`
		} `json:"blkio_stats"`
	}
	if err := client.Get(ctx, "/containers/"+containerID+"/stats?stream=false", &raw); err != nil {
		return ContainerResourceStats{}, err
	}

	out := ContainerResourceStats{}
	deltaCPU := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	deltaSys := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
	if deltaSys > 0 {
		out.CPUPct = deltaCPU / deltaSys * 100
		if out.CPUPct > 100 {
			out.CPUPct = 100
		}
		if out.CPUPct < 0 {
			out.CPUPct = 0
		}
	}
	if raw.MemoryStats.Limit > 0 {
		out.MemPct = float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit) * 100
		if out.MemPct > 100 {
			out.MemPct = 100
		}
	}

	var blkio uint64
	for _, e := range raw.BlkioStats.IoServiceBytesRecursive {
		op := e.Op
		if op == "Read" || op == "Write" || op == "Total" {
			if op == "Total" {
				blkio = e.Value
				break
			}
			blkio += e.Value
		}
	}
	out.BlkioBytes = blkio
	if prevBlkio > 0 && blkio >= prevBlkio && prevIntervalS > 0 {
		// Normalise : 100 MB/s ≈ 100 %
		const full = 100 * 1024 * 1024
		bps := float64(blkio-prevBlkio) / prevIntervalS
		out.DiskIOPCT = math.Min(100, bps/full*100)
	}
	return out, nil
}
