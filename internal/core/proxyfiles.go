// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/vincamok/goproxify/internal/core/proxypipeline"
	"github.com/vincamok/goproxify/internal/core/proxystore"
	"github.com/vincamok/goproxify/internal/core/router"
)

// dataRoot returns the Core volume root (/etc/goproxify by default).
func dataRoot() string {
	if p := os.Getenv("GPX_DATA_PATH"); p != "" {
		return p
	}
	if p := os.Getenv("GPX_CORE_CACHE_PATH"); p != "" {
		return filepath.Dir(p)
	}
	return "/etc/goproxify"
}

func (s *Server) initProxyStore() {
	root := dataRoot()
	s.proxyStore = proxystore.New(root)
	s.proxyPipe = proxypipeline.New(s.proxyStore)
	if err := s.proxyStore.EnsureDirs(); err != nil {
		s.log.Error("proxystore: impossible de créer proxies/ et proxies-revisions/",
			"err", err, "root", root)
		return
	}
	if err := os.MkdirAll(s.certsDir(), 0o700); err != nil {
		s.log.Warn("core: impossible de créer certs/", "err", err)
	}
	s.log.Info("proxystore: dossiers prêts",
		"root", root,
		"proxies", s.proxyStore.ProdDir(),
		"revisions", s.proxyStore.RevisionsDir())
}

// loadProductionProxies loads proxies/*.yaml into memory (wins over cache routes).
func (s *Server) loadProductionProxies() {
	if s.proxyStore == nil {
		return
	}
	list, err := s.proxyStore.ListProd()
	if err != nil {
		s.log.Warn("proxystore: list prod", "err", err)
		return
	}
	applied := 0
	for _, env := range list {
		if !env.Enabled {
			continue
		}
		route, err := proxypipeline.ParseRoute(env)
		if err != nil {
			s.log.Warn("proxystore: route invalide ignorée", "id", env.ID, "err", err)
			continue
		}
		s.table.Upsert(route)
		applied++
	}
	s.log.Info("proxystore: proxies production chargés en mémoire",
		"files", len(list), "applied", applied, "dir", s.proxyStore.ProdDir())
}

// certsDir retourne le répertoire de persistance des certificats TLS du Core.
func (s *Server) certsDir() string {
	return filepath.Join(dataRoot(), "certs")
}

// certSafeName convertit un nom de domaine (éventuellement wildcard) en nom de fichier sûr.
func certSafeName(name string) string {
	return strings.ReplaceAll(name, "*", "_")
}

// writeCertToDisk persiste certPEM et keyPEM dans certs/<name>.{crt,key}.
func (s *Server) writeCertToDisk(name string, certPEM, keyPEM []byte) {
	dir := s.certsDir()
	safe := certSafeName(name)
	if err := os.WriteFile(filepath.Join(dir, safe+".crt"), certPEM, 0o600); err != nil {
		s.log.Warn("core: écriture cert disque", "name", name, "err", err)
	}
	if err := os.WriteFile(filepath.Join(dir, safe+".key"), keyPEM, 0o600); err != nil {
		s.log.Warn("core: écriture clé disque", "name", name, "err", err)
	}
}

// deleteCertFromDisk supprime les fichiers disque pour le certificat donné.
func (s *Server) deleteCertFromDisk(name string) {
	dir := s.certsDir()
	safe := certSafeName(name)
	for _, ext := range []string{".crt", ".key"} {
		if err := os.Remove(filepath.Join(dir, safe+ext)); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.log.Warn("core: suppression cert disque", "name", name, "err", err)
		}
	}
}

// loadCertsFromDisk charge les certificats depuis certs/ si le certStore est vide.
// Utilisé au démarrage comme fallback si le cache AES-GCM est absent ou corrompu.
func (s *Server) loadCertsFromDisk() {
	if s.certStore.Len() > 0 {
		return
	}
	dir := s.certsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	restored := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".crt")
		name := strings.ReplaceAll(base, "_", "*")
		certPEM, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		keyPEM, err := os.ReadFile(filepath.Join(dir, base+".key"))
		if err != nil {
			continue
		}
		if err := s.certStore.StorePEM(name, certPEM, keyPEM); err != nil {
			s.log.Warn("core: cert disque invalide", "name", name, "err", err)
			continue
		}
		restored++
	}
	if restored > 0 {
		s.log.Info("core: certificats restaurés depuis le disque", "count", restored, "dir", dir)
	}
}

// ApplyFileProxy upserts a production envelope into the live routing table.
func (s *Server) ApplyFileProxy(env *proxystore.Envelope) error {
	if env == nil {
		return nil
	}
	if !env.Enabled {
		s.table.Delete(env.ID)
		s.invalidateRouteCache(env.ID)
		return nil
	}
	route, err := proxypipeline.ParseRoute(env)
	if err != nil {
		return err
	}
	s.table.Upsert(route)
	s.invalidateRouteCache(env.ID)
	return nil
}

// fileProxyIDs returns the set of proxy IDs present in proxies/.
func (s *Server) fileProxyIDs() map[string]bool {
	out := map[string]bool{}
	if s.proxyStore == nil {
		return out
	}
	list, err := s.proxyStore.ListProd()
	if err != nil {
		return out
	}
	for _, e := range list {
		out[e.ID] = true
	}
	return out
}

// mergePushPreservingFileProxies keeps file-backed and agent routes across Admin push_routes.
// File proxies are re-read from disk (source of truth); Admin payloads for those IDs are ignored.
func (s *Server) mergePushPreservingFileProxies(incoming []*router.Route) []*router.Route {
	fileIDs := s.fileProxyIDs()
	kept := make([]*router.Route, 0, len(incoming))
	seen := map[string]bool{}

	for _, rt := range incoming {
		if rt == nil || fileIDs[rt.ID] {
			continue
		}
		kept = append(kept, rt)
		seen[rt.ID] = true
	}

	for _, rt := range s.table.All() {
		if isAgentRoute(rt.ID) && !seen[rt.ID] {
			kept = append(kept, rt)
			seen[rt.ID] = true
		}
	}

	if s.proxyStore != nil {
		if list, err := s.proxyStore.ListProd(); err == nil {
			for _, env := range list {
				if !env.Enabled {
					continue
				}
				route, err := proxypipeline.ParseRoute(env)
				if err != nil {
					continue
				}
				kept = append(kept, route)
			}
		}
	}
	return kept
}
