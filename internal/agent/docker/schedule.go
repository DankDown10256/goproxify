// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// ScheduleWatcher vérifie les labels `goproxify.update.schedule` et déclenche
// les mises à jour selon l'expression cron simplifiée (minute heure * * *).
type ScheduleWatcher struct {
	client    *Client
	lifecycle *LifecycleManager
	log       *slog.Logger
}

// NewScheduleWatcher crée un ScheduleWatcher.
func NewScheduleWatcher(client *Client, lifecycle *LifecycleManager, log *slog.Logger) *ScheduleWatcher {
	return &ScheduleWatcher{client: client, lifecycle: lifecycle, log: log}
}

// Start lance la boucle de vérification toutes les minutes.
func (s *ScheduleWatcher) Start(ctx context.Context) {
	go func() {
		// Aligne sur la prochaine minute entière
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute)
		time.Sleep(time.Until(next))

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				s.check(ctx, t)
			}
		}
	}()
}

// check parcoure les conteneurs et déclenche les mises à jour dont le cron correspond.
func (s *ScheduleWatcher) check(ctx context.Context, now time.Time) {
	var containers []ContainerSummary
	if err := s.client.Get(ctx, "/containers/json?all=false", &containers); err != nil {
		return
	}
	for _, c := range containers {
		sched := c.Labels[LabelUpdateSchedule]
		if sched == "" {
			continue
		}
		if !cronMatch(sched, now) {
			continue
		}
		prune := boolLabel(c.Labels, LabelUpdatePrune)
		s.log.Info("schedule: déclenchement mise à jour", "container", firstName(c.Names), "cron", sched)
		go func(id string, p bool) {
			if err := s.lifecycle.UpdateContainer(ctx, id, p); err != nil {
				s.log.Error("schedule: mise à jour échouée", "id", id[:12], "err", err)
			}
		}(c.ID, prune)
	}
}

// cronMatch vérifie une expression cron simplifiée à 5 champs ("min heure * * *").
// Supporte les valeurs fixes et "*".
func cronMatch(expr string, t time.Time) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	checks := []struct {
		field string
		value int
	}{
		{fields[0], t.Minute()},
		{fields[1], t.Hour()},
		{fields[2], t.Day()},
		{fields[3], int(t.Month())},
		{fields[4], int(t.Weekday())},
	}
	for _, c := range checks {
		if c.field == "*" {
			continue
		}
		n, err := strconv.Atoi(c.field)
		if err != nil || n != c.value {
			return false
		}
	}
	return true
}
