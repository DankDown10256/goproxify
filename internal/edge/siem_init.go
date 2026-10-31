// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"os"
	"time"

	"github.com/vincamok/goproxify/internal/edge/siem"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

const siemStatusEvery = 30 * time.Second

// siemConfigPath est la copie locale chiffrée de la configuration de l'exporteur SIEM poussée par l'Admin : elle
// contient les jetons des destinations, et l'exporteur repart avec elle sans l'Admin (ADR 0006).
func siemConfigPath() string {
	if p := os.Getenv("GPX_SIEM_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/siem-config.gpx"
}

// siemStatePath garde les curseurs de lecture de chaque destination. Il est à la racine du volume, donc dans la
// sauvegarde d'état : une passerelle restaurée ne réexporte pas des mois de logs.
func siemStatePath() string {
	if p := os.Getenv("GPX_SIEM_STATE_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/siem-state.gpx"
}

type siemStateFile struct {
	Positions map[string]map[string]int64 `json:"positions"`
}

// siemState enregistre les curseurs dans un fichier chiffré.
type siemState struct{ s *Server }

func (st siemState) Load() (map[string]map[string]int64, error) {
	var f siemStateFile
	if _, err := st.s.cache.LoadFile(siemStatePath(), &f); err != nil {
		return nil, err
	}
	return f.Positions, nil
}

func (st siemState) Save(p map[string]map[string]int64) error {
	return st.s.cache.SaveFile(siemStatePath(), siemStateFile{Positions: p})
}

func (s *Server) saveSIEMConfig(cfg siem.Config) error {
	return s.cache.SaveFile(siemConfigPath(), cfg)
}

// loadSIEMConfig relit la configuration au démarrage, sans l'Admin. Une copie illisible laisse l'exporteur éteint : les
// curseurs restent, l'Admin la repousse à la connexion.
func (s *Server) loadSIEMConfig() siem.Config {
	var cfg siem.Config
	if _, err := s.cache.LoadFile(siemConfigPath(), &cfg); err != nil {
		s.log.Warn("siem: config locale illisible, en attente de l'Admin", "err", err)
		return siem.Config{}
	}
	if err := cfg.Validate(); err != nil {
		s.log.Warn("siem: config locale invalide, en attente de l'Admin", "err", err)
		return siem.Config{}
	}
	return cfg
}

// startSIEM démarre l'exporteur avec la configuration locale. Il lit la base de logs de la passerelle avec ses propres
// curseurs : une coupure de l'Admin ou du SIEM ne fait rien perdre tant que la base garde les lignes.
func (s *Server) startSIEM(ctx context.Context) {
	if s.logStore == nil {
		return
	}
	s.siemExporter = siem.New(siem.Options{
		Node: s.cfg.Identity.NodeName, Source: s.logStore, State: siemState{s}, Retention: s.logStore.EffectiveRetention,
		Log: s.log.Logger(),
	})
	s.siemExporter.Apply(s.loadSIEMConfig())
	go s.siemStatusLoop(ctx)
}

func (s *Server) applySIEMConfig(cfg siem.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := s.saveSIEMConfig(cfg); err != nil {
		s.log.Warn("siem: persistance de la config échouée", "err", err)
	}
	if s.siemExporter != nil {
		s.siemExporter.Apply(cfg)
	}
	s.log.Info("siem: config mise à jour", "enabled", cfg.Enabled, "destinations", len(cfg.Destinations))
	return nil
}

// siemStatusLoop envoie à l'Admin l'état de chaque destination : retard, erreur, livraisons. C'est un état, pas un
// journal : un envoi perdu pendant une coupure est remplacé par le suivant.
func (s *Server) siemStatusLoop(ctx context.Context) {
	ticker := time.NewTicker(siemStatusEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st := s.siemExporter.Status()
			if msg, err := edgews.NewMessage(0, edgews.TypeSIEMStatus, edgews.SIEMStatusPayload{NodeName: s.cfg.Identity.NodeName, Destinations: st}); err == nil {
				s.wsHub.BroadcastToAdmins(msg)
			}
		}
	}
}
