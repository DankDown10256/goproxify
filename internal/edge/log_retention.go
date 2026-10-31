// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

const (
	logInfoEvery = 30 * time.Second
	// maxLogRetentionDays borne une durée poussée par l'Admin : dix ans.
	maxLogRetentionDays = 3650
)

// logRetentionPath est la copie locale chiffrée des durées de conservation poussées par l'Admin. Elle l'emporte sur
// edge.json au démarrage : la passerelle garde sa rétention après un redémarrage, Admin éteint (ADR 0006).
func logRetentionPath() string {
	if p := os.Getenv("GPX_LOG_RETENTION_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/log-retention.gpx"
}

// loadLogRetention lit la rétention poussée par l'Admin ; absente ou illisible, edge.json s'applique.
func (s *Server) loadLogRetention() edgews.LogRetentionPayload {
	var p edgews.LogRetentionPayload
	ok, err := s.cache.LoadFile(logRetentionPath(), &p)
	if err != nil {
		s.log.Warn("logs: rétention locale illisible, la configuration de la passerelle s'applique", "err", err)
		return edgews.LogRetentionPayload{}
	}
	if !ok || validLogRetention(p) != nil {
		return edgews.LogRetentionPayload{}
	}
	return p
}

func validLogRetention(p edgews.LogRetentionPayload) error {
	if p.AccessDays < 1 || p.AccessDays > maxLogRetentionDays || p.SystemDays < 1 || p.SystemDays > maxLogRetentionDays {
		return errors.New("durée de conservation hors limites (1 à 3650 jours)")
	}
	return nil
}

// applyLogRetention enregistre la rétention reçue de l'Admin et l'applique à la base ; la purge horaire s'en sert.
func (s *Server) applyLogRetention(p edgews.LogRetentionPayload) error {
	if err := validLogRetention(p); err != nil {
		return err
	}
	if err := s.cache.SaveFile(logRetentionPath(), p); err != nil {
		s.log.Warn("logs: persistance de la rétention échouée", "err", err)
	}
	if s.logStore != nil {
		s.logStore.SetRetention(logstore.KindAccess, time.Duration(p.AccessDays)*24*time.Hour)
		s.logStore.SetRetention(logstore.KindSystem, time.Duration(p.SystemDays)*24*time.Hour)
	}
	s.log.Info("logs: rétention mise à jour", "access_days", p.AccessDays, "system_days", p.SystemDays)
	s.sendLogInfo()
	return nil
}

// sendLogInfo annonce à l'Admin la rétention réellement appliquée : c'est elle, et non un réglage de l'Admin, qui dit
// jusqu'où remonter dans les accès d'une passerelle.
func (s *Server) sendLogInfo() {
	if s.logStore == nil || s.wsHub == nil {
		return
	}
	days := func(k logstore.Kind) int { return int(s.logStore.Retention(k) / (24 * time.Hour)) }
	msg, err := edgews.NewMessage(0, edgews.TypeLogInfo, edgews.LogInfoPayload{
		NodeName: s.cfg.Identity.NodeName, AccessDays: days(logstore.KindAccess), SystemDays: days(logstore.KindSystem),
		AccessLast: s.logStore.LastID(logstore.KindAccess), SystemLast: s.logStore.LastID(logstore.KindSystem),
		BufferActive: s.logStore.BufferActive(), UnackedDays: unackedDays(s.logStore.OldestUnacked()), BufferMaxDays: int(s.logStore.BufferMax() / (24 * time.Hour)),
	})
	if err == nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}

// logInfoLoop répète l'annonce : c'est un état, un envoi perdu pendant une coupure est remplacé par le suivant.
func (s *Server) logInfoLoop(ctx context.Context) {
	s.sendLogInfo()
	t := time.NewTicker(logInfoEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sendLogInfo()
		}
	}
}

// unackedDays rend l'âge, en jours entiers, de la plus ancienne ligne que l'Admin n'a pas acquittée (0 : tout est acquitté).
func unackedDays(oldest time.Time) int {
	if oldest.IsZero() {
		return 0
	}
	return max(int(time.Since(oldest)/(24*time.Hour)), 0)
}
