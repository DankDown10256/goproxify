// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"path/filepath"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/edgews"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// logVaultDir rend le dossier du volume de logs de l'Admin (ADR 0018) : GPX_ADMIN_LOG_DIR, qui désigne un volume Docker
// à part de celui de la base de gestion, sinon edge-logs sous la racine de stockage. Vide : pas de volume de logs.
func (s *Server) logVaultDir() string {
	if dir := os.Getenv("GPX_ADMIN_LOG_DIR"); dir != "" {
		return dir
	}
	if s.cfg.Storage.BasePath != "" {
		return filepath.Join(s.cfg.Storage.BasePath, "edge-logs")
	}
	return ""
}

// newLogIngestor ouvre le volume de logs, prépare la réception des flux de logs des passerelles et branche la lecture des
// logs sur ce volume. announced rend les derniers identifiants de logs qu'une passerelle a annoncés. Si le volume ne s'ouvre
// pas, l'Admin démarre quand même : sa base ne garde que les événements de sécurité, les lectures vont aux passerelles, qui
// gardent le reste dans leur tampon et le renverront quand le volume sera disponible.
func (s *Server) newLogIngestor(announced func(nodeName string) (access, system int64, ok bool)) *edgews.LogStreamIngestor {
	ing := &edgews.LogStreamIngestor{Store: s.logStore, Log: s.log, SecurityOnly: true}
	dir := s.logVaultDir()
	if dir == "" {
		return ing
	}
	vault, err := edgelogs.Open(dir, s.logKey, s.log)
	if err != nil {
		s.log.Error("logs: volume de logs de l'Admin indisponible", "dir", dir, "err", err)
		return ing
	}
	s.logVault = vault
	vr := api.LoadVaultRetention(s.db)
	s.applyVaultRetention(vr.AccessDays, vr.SystemDays)
	s.log.Info("logs: volume de logs de l'Admin ouvert", "dir", dir)
	ing.Vault, ing.SecurityOnly = vault, false
	edgeproxy.SetLocalLogs(&edgelogs.Reader{
		Vault:     vault,
		Source:    func() string { return admindb.GetSetting(s.db, "logs.read_source", edgelogs.SourceAuto) },
		Announced: announced,
	})
	return ing
}

// closeLogVault débranche la lecture des logs du volume et le ferme.
func (s *Server) closeLogVault() {
	if s.logVault == nil {
		return
	}
	edgeproxy.SetLocalLogs(nil)
	s.logVault.Close()
	s.logVault = nil
}

// applyVaultRetention règle la conservation des accès et des logs système du volume de logs (réglage de l'Admin) ; la purge
// horaire de chaque store l'applique.
func (s *Server) applyVaultRetention(accessDays, systemDays int) {
	if s.logVault == nil {
		return
	}
	s.logVault.SetRetention(logstore.KindAccess, time.Duration(accessDays)*24*time.Hour)
	s.logVault.SetRetention(logstore.KindSystem, time.Duration(systemDays)*24*time.Hour)
}
