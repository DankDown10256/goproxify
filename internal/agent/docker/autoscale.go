// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Labels auto-scaling
const (
	LabelScaleMin     = "goproxify.scale.min"      // nb min d'instances, défaut: 1
	LabelScaleMax     = "goproxify.scale.max"      // nb max d'instances, défaut: 1 (désactivé)
	LabelScaleCPUUp   = "goproxify.scale.cpu_up"   // seuil CPU% montée, défaut: 80
	LabelScaleCPUDown = "goproxify.scale.cpu_down" // seuil CPU% descente, défaut: 20
	LabelScaleService = "goproxify.scale.service"  // nom logique du service (groupe d'instances)
)

// ScaleEvent décrit une décision de scaling.
type ScaleEvent struct {
	Service   string
	Direction string // up | down
	From      int
	To        int
	Reason    string
}

// AutoScaler surveille les métriques et fait monter/descendre les instances Docker.
type AutoScaler struct {
	client     *Client
	lifecycle  *LifecycleManager
	log        *slog.Logger
	cpuUp      float64
	cpuDown    float64
	cooldownS  int

	mu        sync.Mutex
	lastScale map[string]time.Time // service → dernière décision
	onEvent   func(ScaleEvent)
}

// NewAutoScaler crée un AutoScaler.
func NewAutoScaler(client *Client, lifecycle *LifecycleManager,
	cpuUp, cpuDown float64, cooldownS int,
	log *slog.Logger, onEvent func(ScaleEvent)) *AutoScaler {

	if cpuUp <= 0 {
		cpuUp = 80
	}
	if cpuDown <= 0 {
		cpuDown = 20
	}
	if cooldownS <= 0 {
		cooldownS = 120
	}
	return &AutoScaler{
		client:    client,
		lifecycle: lifecycle,
		log:       log,
		cpuUp:     cpuUp,
		cpuDown:   cpuDown,
		cooldownS: cooldownS,
		lastScale: make(map[string]time.Time),
		onEvent:   onEvent,
	}
}

// Start lance la boucle de vérification.
func (a *AutoScaler) Start(ctx context.Context, intervalS int) {
	if intervalS <= 0 {
		intervalS = 30
	}
	go func() {
		ticker := time.NewTicker(time.Duration(intervalS) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.check(ctx)
			}
		}
	}()
}

// check parcourt les services scalables et applique les décisions.
func (a *AutoScaler) check(ctx context.Context) {
	services, err := a.discoverServices(ctx)
	if err != nil {
		return
	}
	for svcName, instances := range services {
		if len(instances) == 0 {
			continue
		}
		spec := instances[0]
		min := intLabel(spec.Labels, LabelScaleMin, 1)
		max := intLabel(spec.Labels, LabelScaleMax, 1)
		if max <= 1 || max <= min {
			continue // scaling désactivé pour ce service
		}

		// Lecture CPU via stats Docker (moyenne sur les instances)
		avgCPU := a.avgCPU(ctx, instances)
		cur := len(instances)

		if avgCPU > a.cpuUp && cur < max {
			a.scale(ctx, svcName, spec, cur, cur+1, fmt.Sprintf("CPU %.1f%% > seuil %.0f%%", avgCPU, a.cpuUp))
		} else if avgCPU < a.cpuDown && cur > min {
			a.scale(ctx, svcName, spec, cur, cur-1, fmt.Sprintf("CPU %.1f%% < seuil %.0f%%", avgCPU, a.cpuDown))
		}
	}
}

type serviceInstance struct {
	ID     string
	Name   string
	Image  string
	Labels map[string]string
}

// discoverServices regroupe les conteneurs par service (label goproxify.scale.service).
func (a *AutoScaler) discoverServices(ctx context.Context) (map[string][]serviceInstance, error) {
	var containers []ContainerSummary
	if err := a.client.Get(ctx, "/containers/json?all=false", &containers); err != nil {
		return nil, err
	}
	services := make(map[string][]serviceInstance)
	for _, c := range containers {
		svc := c.Labels[LabelScaleService]
		if svc == "" {
			continue
		}
		services[svc] = append(services[svc], serviceInstance{
			ID:     c.ID,
			Name:   firstName(c.Names),
			Image:  c.Image,
			Labels: c.Labels,
		})
	}
	return services, nil
}

// scale crée ou arrête des instances pour atteindre la cible.
func (a *AutoScaler) scale(ctx context.Context, svcName string, spec serviceInstance, from, to int, reason string) {
	a.mu.Lock()
	if last, ok := a.lastScale[svcName]; ok {
		if time.Since(last) < time.Duration(a.cooldownS)*time.Second {
			a.mu.Unlock()
			return
		}
	}
	a.lastScale[svcName] = time.Now()
	a.mu.Unlock()

	ev := ScaleEvent{Service: svcName, From: from, To: to, Reason: reason}

	if to > from {
		ev.Direction = "up"
		a.log.Info("autoscale: scale up", "service", svcName, "from", from, "to", to, "reason", reason)
		for i := from; i < to; i++ {
			if err := a.createInstance(ctx, spec, svcName, i+1); err != nil {
				a.log.Error("autoscale: création instance", "service", svcName, "err", err)
				break
			}
		}
	} else {
		ev.Direction = "down"
		a.log.Info("autoscale: scale down", "service", svcName, "from", from, "to", to, "reason", reason)
		// Arrête les dernières instances
		instances, _ := a.discoverServices(ctx)
		svcInstances := instances[svcName]
		for i := len(svcInstances) - 1; i >= to; i-- {
			if err := a.client.Post(ctx, "/containers/"+svcInstances[i].ID+"/stop", nil, nil); err != nil {
				a.log.Error("autoscale: arrêt instance", "id", svcInstances[i].ID, "err", err)
			}
		}
	}

	if a.onEvent != nil {
		a.onEvent(ev)
	}
}

// createInstance crée un nouveau conteneur clone pour le service.
func (a *AutoScaler) createInstance(ctx context.Context, spec serviceInstance, svcName string, idx int) error {
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(svcName, "/"), idx)
	body := ContainerCreateBody{
		Image:  spec.Image,
		Labels: spec.Labels,
	}
	body.HostConfig.RestartPolicy.Name = "unless-stopped"

	var created struct{ ID string `json:"Id"` }
	if err := a.client.Post(ctx, "/containers/create?name="+name, body, &created); err != nil {
		return err
	}
	return a.client.Post(ctx, "/containers/"+created.ID+"/start", nil, nil)
}

// avgCPU calcule le CPU moyen d'un groupe d'instances via l'API Docker Stats.
func (a *AutoScaler) avgCPU(ctx context.Context, instances []serviceInstance) float64 {
	if len(instances) == 0 {
		return 0
	}
	total := 0.0
	count := 0
	for _, inst := range instances {
		var stats struct {
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
		}
		// ?stream=false → snapshot instantané (une seule lecture)
		if err := a.client.Get(ctx, "/containers/"+inst.ID+"/stats?stream=false", &stats); err != nil {
			continue
		}
		deltaCPU := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
		deltaSys := float64(stats.CPUStats.SystemCPUUsage - stats.PreCPUStats.SystemCPUUsage)
		if deltaSys > 0 {
			total += deltaCPU / deltaSys * 100
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}
