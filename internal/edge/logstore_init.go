// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"os"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

const defaultLogStoreDir = "/etc/goproxify/logs"

// logIPKeyPath est la copie locale chiffrée de la clé qui pseudonymise l'IP réelle des logs d'accès. Elle est à
// la racine du volume, donc dans la sauvegarde d'état : le dossier des logs en est exclu, mais sans cette clé les
// lignes pseudonymisées ne se révèlent plus.
func logIPKeyPath() string {
	if p := os.Getenv("GPX_LOG_IP_KEY_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/log-ip-key.gpx"
}

type logIPKeyFile struct {
	Key []byte `json:"key"`
}

// loadOrCreateLogIPKey lit la clé du volume ou en crée une. Un fichier illisible (secret d'appairage changé sans
// PreviousSecretsEnv) n'est jamais écrasé : une clé neuve rendrait définitivement illisible ce que l'ancienne
// aurait encore pu ouvrir. La passerelle journalise alors sans clé, c'est-à-dire sans garder l'IP réelle.
func (s *Server) loadOrCreateLogIPKey() []byte {
	path := logIPKeyPath()
	var kf logIPKeyFile
	ok, err := s.cache.LoadFile(path, &kf)
	if err != nil {
		s.log.Warn("logs: clé de pseudonymisation illisible, l'IP réelle ne sera pas conservée", "err", err)
		return nil
	}
	if ok && len(kf.Key) == ipcrypt.KeySize {
		return kf.Key
	}
	key, err := ipcrypt.NewKey()
	if err != nil {
		s.log.Warn("logs: génération de la clé de pseudonymisation échouée", "err", err)
		return nil
	}
	if err := s.cache.SaveFile(path, logIPKeyFile{Key: key}); err != nil {
		s.log.Warn("logs: enregistrement de la clé de pseudonymisation échoué, l'IP réelle ne sera pas conservée", "err", err)
		return nil
	}
	return key
}

// Tampon de la base de logs (ADR 0018) : voir logstore.Buffer.
const (
	defaultLogBufferDays    = 7
	defaultLogBufferMaxDays = 30
)

// initLogStore ouvre la base de logs locale et y branche le journal d'accès et le journal système. En cas
// d'échec la passerelle sert le trafic quand même : ses logs ne sont alors qu'expédiés à l'Admin.
func (s *Server) initLogStore() {
	dir := s.cfg.Engine.LogStoreDir
	if dir == "" {
		dir = defaultLogStoreDir
	}
	access, system := s.cfg.Engine.LogRetentionDays, s.cfg.Engine.SystemLogRetentionDays
	if p := s.loadLogRetention(); p.AccessDays > 0 {
		access, system = p.AccessDays, p.SystemDays
	}
	st, err := logstore.Open(logstore.Options{
		Dir:   dir,
		IPKey: s.loadOrCreateLogIPKey(),
		Retention: map[logstore.Kind]time.Duration{
			logstore.KindAccess: time.Duration(access) * 24 * time.Hour,
			logstore.KindSystem: time.Duration(system) * 24 * time.Hour,
		},
		OnError: func(err error) { s.log.Warn("logs: écriture dans la base de logs locale échouée", "err", err) },
	})
	if err != nil {
		s.log.Warn("logs: base de logs locale indisponible, les logs ne sont qu'expédiés à l'Admin", "dir", dir, "err", err)
		return
	}
	s.logStore = st
	bufAcked, bufMax := s.cfg.Engine.LogBufferDays, s.cfg.Engine.LogBufferMaxDays
	if bufAcked <= 0 {
		bufAcked = defaultLogBufferDays
	}
	if bufMax <= 0 {
		bufMax = defaultLogBufferMaxDays
	}
	st.SetBuffer(logstore.Buffer{Acked: time.Duration(bufAcked) * 24 * time.Hour, Max: time.Duration(max(bufMax, bufAcked)) * 24 * time.Hour})
	s.accessLog.SetStore(st)
	s.log.SetStore(st)
}
