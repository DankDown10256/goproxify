// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
)

// internalAPI expose une API HTTP locale sur laquelle la passerelle / l'Admin poussent des commandes.
// Écoute sur :8001 (configurable). Auth Bearer obligatoire (fail-closed).
type internalAPI struct {
	port int
	mu   sync.RWMutex
	// authTokens : valeurs Bearer acceptées (pairing secret et/ou token Agent).
	authTokens []string
	lifecycle  *agentdocker.LifecycleManager
	discovery  *agentdocker.Discovery
	cfgPath    string // chemin vers agent.json, pour l'action configure
	log        *slog.Logger
	srv        *http.Server
}

func newInternalAPI(port int, lifecycle *agentdocker.LifecycleManager, log *slog.Logger) *internalAPI {
	if port == 0 {
		port = 8001
	}
	return &internalAPI{port: port, lifecycle: lifecycle, log: log}
}

// setDiscovery injecte la Discovery après construction (le pairing peut survenir après New).
func (a *internalAPI) setDiscovery(d *agentdocker.Discovery) {
	a.discovery = d
}

// setAuthTokens remplace la liste des Bearer acceptés (chaînes vides ignorées).
func (a *internalAPI) setAuthTokens(tokens ...string) {
	filtered := make([]string, 0, len(tokens))
	seen := map[string]struct{}{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		filtered = append(filtered, t)
	}
	a.mu.Lock()
	a.authTokens = filtered
	a.mu.Unlock()
}

func (a *internalAPI) authorized(r *http.Request) bool {
	a.mu.RLock()
	tokens := a.authTokens
	a.mu.RUnlock()
	if len(tokens) == 0 {
		return false
	}
	provided := bearerFromRequest(r)
	if provided == "" {
		return false
	}
	pb := []byte(provided)
	for _, t := range tokens {
		tb := []byte(t)
		if len(pb) == len(tb) && subtle.ConstantTimeCompare(pb, tb) == 1 {
			return true
		}
	}
	return false
}

func bearerFromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func (a *internalAPI) Start(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/command", a.handleCommand)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	a.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", a.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	a.log.Info("agent: API interne démarrée", "port", a.port)
	go func() {
		if err := a.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error("agent: API interne", "err", err)
		}
	}()
}

// selfContainerID retourne le container ID de l'agent lui-même.
// Essaie /proc/self/cgroup (cgroups v1), puis le hostname Docker (= short container ID).
func selfContainerID() string {
	// cgroups v1 : "12:devices:/docker/<64-char-id>"
	// cgroups v2 : "0::/system.slice/docker-<64-char-id>.scope"
	if f, err := os.Open("/proc/self/cgroup"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			for _, prefix := range []string{"/docker/", "docker-"} {
				if idx := strings.Index(line, prefix); idx != -1 {
					id := line[idx+len(prefix):]
					id = strings.TrimSuffix(id, ".scope")
					if len(id) >= 12 {
						return id[:12]
					}
				}
			}
		}
	}
	// Fallback : hostname Docker = premiers 12 caractères du container ID
	if h, err := os.Hostname(); err == nil && len(h) >= 12 {
		return h
	}
	return ""
}

func (a *internalAPI) Stop(ctx context.Context) {
	if a.srv != nil {
		_ = a.srv.Shutdown(ctx)
	}
}

type commandRequest struct {
	Action    string `json:"action"`    // update | rollback | rescan | configure
	Container string `json:"container"` // ID ou nom
	Prune     bool   `json:"prune"`
	// Pour scale
	ScaleTarget int `json:"scale_target"`
	// Pour configure : patch JSON à merger dans agent.json
	Patch json.RawMessage `json:"patch"`
}

func (a *internalAPI) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorized(r) {
		http.Error(w, "non autorisé", http.StatusUnauthorized)
		return
	}
	var cmd commandRequest
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	switch cmd.Action {
	case "update":
		cid := cmd.Container
		if cid == "" {
			cid = selfContainerID()
		}
		if cid == "" {
			http.Error(w, "container ID requis et auto-détection impossible", http.StatusBadRequest)
			return
		}
		go func() {
			a.log.Info("agent: commande update", "container", cid)
			if err := a.lifecycle.UpdateContainer(context.Background(), cid, cmd.Prune); err != nil {
				a.log.Error("agent: update échoué", "container", cid, "err", err)
			}
		}()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "update_started"})

	case "rollback":
		go func() {
			a.log.Info("agent: commande rollback", "container", cmd.Container)
			if err := a.lifecycle.Rollback(context.Background(), cmd.Container); err != nil {
				a.log.Error("agent: rollback échoué", "container", cmd.Container, "err", err)
			}
		}()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rollback_started"})

	case "rescan":
		if a.discovery == nil {
			http.Error(w, "discovery non initialisée", http.StatusServiceUnavailable)
			return
		}
		go func() {
			a.log.Info("agent: commande rescan — scan Docker forcé")
			a.discovery.ScanAll(context.Background())
		}()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rescan_started"})

	case "configure":
		if a.cfgPath == "" {
			http.Error(w, "chemin config non configuré", http.StatusInternalServerError)
			return
		}
		if len(cmd.Patch) == 0 {
			http.Error(w, "patch JSON requis", http.StatusBadRequest)
			return
		}
		if err := applyConfigPatch(a.cfgPath, cmd.Patch); err != nil {
			a.log.Error("agent: configure échoué", "err", err)
			http.Error(w, fmt.Sprintf("configure échoué : %v", err), http.StatusInternalServerError)
			return
		}
		a.log.Info("agent: configure appliqué — redémarrage")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "configure_applied"})
		go func() {
			// Docker redémarre l'agent après SIGTERM (restart: unless-stopped).
			p, err := os.FindProcess(os.Getpid())
			if err == nil {
				_ = p.Signal(syscall.SIGTERM)
			}
		}()

	default:
		http.Error(w, fmt.Sprintf("action inconnue : %q", cmd.Action), http.StatusBadRequest)
	}
}

// applyConfigPatch lit agent.json, y merge le patch (shallow sur les sections top-level),
// puis réécrit le fichier de façon atomique.
func applyConfigPatch(cfgPath string, patch json.RawMessage) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("lecture %s : %w", cfgPath, err)
	}

	var base map[string]json.RawMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		return fmt.Errorf("parsing %s : %w", cfgPath, err)
	}

	var patchMap map[string]json.RawMessage
	if err := json.Unmarshal(patch, &patchMap); err != nil {
		return fmt.Errorf("parsing patch : %w", err)
	}

	// Merge : pour chaque section du patch, fusionner les clés dans la section base.
	for section, patchVal := range patchMap {
		baseVal, exists := base[section]
		if !exists {
			base[section] = patchVal
			continue
		}
		var baseObj, patchObj map[string]json.RawMessage
		if json.Unmarshal(baseVal, &baseObj) != nil || json.Unmarshal(patchVal, &patchObj) != nil {
			// Remplacement direct si l'une des valeurs n'est pas un objet.
			base[section] = patchVal
			continue
		}
		for k, v := range patchObj {
			// Ne pas écraser un secret existant par une chaîne vide ou masquée ("••••••••").
			if isSecretKey(k) {
				var s string
				if json.Unmarshal(v, &s) == nil && (s == "" || s == "••••••••") {
					continue
				}
			}
			// Merge récursif pour les sous-objets imbriqués (ex: endpoint_edges).
			if baseVal, ok := baseObj[k]; ok {
				var bSub, pSub map[string]json.RawMessage
				if json.Unmarshal(baseVal, &bSub) == nil && json.Unmarshal(v, &pSub) == nil {
					for sk, sv := range pSub {
						// Merge de chaque sous-entrée (ex: un endpoint_edge par nom).
						if bEntry, ok2 := bSub[sk]; ok2 {
							var bEnt, pEnt map[string]json.RawMessage
							if json.Unmarshal(bEntry, &bEnt) == nil && json.Unmarshal(sv, &pEnt) == nil {
								for ek, ev := range pEnt {
									if isSecretKey(ek) {
										var s string
										if json.Unmarshal(ev, &s) == nil && (s == "" || s == "••••••••") {
											continue
										}
									}
									bEnt[ek] = ev
								}
								if merged, err := json.Marshal(bEnt); err == nil {
									bSub[sk] = merged
									continue
								}
							}
						}
						bSub[sk] = sv
					}
					if merged, err := json.Marshal(bSub); err == nil {
						baseObj[k] = merged
						continue
					}
				}
			}
			baseObj[k] = v
		}
		merged, err := json.Marshal(baseObj)
		if err != nil {
			return fmt.Errorf("merge section %q : %w", section, err)
		}
		base[section] = merged
	}

	data, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal : %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(cfgPath), ".cfg-patch-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, cfgPath)
}

var secretKeys = map[string]bool{
	"api_key":    true,
	"auth_token": true,
	"password":   true,
	"join_token": true,
}

func isSecretKey(k string) bool { return secretKeys[k] }

