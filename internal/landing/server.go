// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package landing implémente le serveur de la page de présentation statique.
package landing

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
)

//go:embed ui/index.html
var uiFiles embed.FS

// Server sert la page de présentation statique.
type Server struct {
	cfg    *config.LandingConfig
	logger *slog.Logger
	http   *http.Server
}

func New(cfg *config.LandingConfig, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, logger: logger}
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// config.js généré dynamiquement depuis la config
	mux.HandleFunc("/config.js", s.handleConfigJS)

	// fichiers statiques embarqués
	static, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		return fmt.Errorf("landing: embed sub: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(static)))

	addr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenAddr, s.cfg.Server.Port)
	s.http = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.logger.Info("landing: démarrage", "addr", addr, "version", s.siteVersion())

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutCtx)
	}()

	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("landing: listen: %w", err)
	}
	return nil
}

// siteVersion préfère la version ldflags si elle n'est pas "dev".
func (s *Server) siteVersion() string {
	if buildinfo.Landing != "" && buildinfo.Landing != "dev" {
		return buildinfo.Landing
	}
	if s.cfg.Site.Version != "" {
		return s.cfg.Site.Version
	}
	return buildinfo.Landing
}

func (s *Server) handleConfigJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	goVer := s.cfg.Site.GoVersion
	if goVer == "" {
		goVer = "1.25"
	}
	fmt.Fprintf(w, "const SITE_CONFIG = {\n")
	fmt.Fprintf(w, "  domain: %q,\n", s.cfg.Site.Domain)
	fmt.Fprintf(w, "  version: %q,\n", s.siteVersion())
	fmt.Fprintf(w, "  goVersion: %q,\n", goVer)
	fmt.Fprintf(w, "  githubUrl: %q,\n", s.cfg.Site.GithubURL)
	fmt.Fprintf(w, "  tagline: %q,\n", s.cfg.Site.Tagline)
	fmt.Fprintf(w, "};\n")
}
