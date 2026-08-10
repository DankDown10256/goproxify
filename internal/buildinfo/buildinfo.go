// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo expose les versions injectées au build (ldflags) et un bandeau de démarrage.
package buildinfo

import (
	"log/slog"
)

// Remplies depuis cmd/goproxify via Set (valeurs ldflags).
var (
	Admin   = "dev"
	Core    = "dev"
	Agent   = "dev"
	Webapp  = "dev"
	Landing = "dev"
	Commit  = "unknown"
	Built   = "unknown"
)

// Set enregistre les versions du binaire (appelé une fois depuis main).
func Set(admin, core, agent, webapp, landing, commit, built string) {
	if admin != "" {
		Admin = admin
	}
	if core != "" {
		Core = core
	}
	if agent != "" {
		Agent = agent
	}
	if webapp != "" {
		Webapp = webapp
	}
	if landing != "" {
		Landing = landing
	}
	if commit != "" {
		Commit = commit
	}
	if built != "" {
		Built = built
	}
}

// LogBanner journalise « Goproxify | <service> | v<version> ».
func LogBanner(log *slog.Logger, service, version string) {
	if log == nil {
		log = slog.Default()
	}
	if version == "" {
		version = "dev"
	}
	log.Info("Goproxify  |  " + service + "  |  v" + version)
}
