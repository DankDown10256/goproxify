// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry collecte les métriques système depuis /proc et les expose en Prometheus.
package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CPUStat représente les compteurs CPU lus dans /proc/stat.
type CPUStat struct {
	User   uint64
	Nice   uint64
	System uint64
	Idle   uint64
	IOWait uint64
	IRQ    uint64
	SoftIRQ uint64
	Total  uint64
}

// UsagePct calcule le pourcentage CPU utilisé entre deux relevés.
func CPUUsagePct(prev, cur CPUStat) float64 {
	deltaTotal := float64(cur.Total - prev.Total)
	if deltaTotal == 0 {
		return 0
	}
	deltaIdle := float64(cur.Idle - prev.Idle)
	return (1 - deltaIdle/deltaTotal) * 100
}

// ReadCPUStat lit les compteurs CPU depuis /proc/stat (ligne cpu agrégée).
func ReadCPUStat() (CPUStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return CPUStat{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return CPUStat{}, fmt.Errorf("ligne cpu invalide")
		}
		nums := make([]uint64, len(fields)-1)
		for i, s := range fields[1:] {
			nums[i], _ = strconv.ParseUint(s, 10, 64)
		}
		stat := CPUStat{
			User: nums[0], Nice: nums[1], System: nums[2], Idle: nums[3],
			IOWait: nums[4], IRQ: nums[5], SoftIRQ: nums[6],
		}
		stat.Total = stat.User + stat.Nice + stat.System + stat.Idle +
			stat.IOWait + stat.IRQ + stat.SoftIRQ
		return stat, nil
	}
	return CPUStat{}, fmt.Errorf("/proc/stat: ligne cpu introuvable")
}

// MemStat représente les métriques mémoire de /proc/meminfo.
type MemStat struct {
	TotalKB     uint64
	FreeKB      uint64
	AvailableKB uint64
	BuffersKB   uint64
	CachedKB    uint64
}

// UsedKB retourne la mémoire effectivement utilisée (hors buffers/cache).
func (m MemStat) UsedKB() uint64 {
	return m.TotalKB - m.AvailableKB
}

// UsagePct retourne le pourcentage de mémoire utilisée.
func (m MemStat) UsagePct() float64 {
	if m.TotalKB == 0 {
		return 0
	}
	return float64(m.UsedKB()) / float64(m.TotalKB) * 100
}

// ReadMemStat lit les métriques mémoire depuis /proc/meminfo.
func ReadMemStat() (MemStat, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemStat{}, err
	}
	defer f.Close()

	kv := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			val, _ := strconv.ParseUint(parts[1], 10, 64)
			kv[key] = val
		}
	}
	return MemStat{
		TotalKB:     kv["MemTotal"],
		FreeKB:      kv["MemFree"],
		AvailableKB: kv["MemAvailable"],
		BuffersKB:   kv["Buffers"],
		CachedKB:    kv["Cached"],
	}, nil
}
