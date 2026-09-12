// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/audit"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/mfa"
	"github.com/vincamok/goproxify/internal/admin/setup"
)

// --- Login ---------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	initialized := !setup.IsFirstRun(s.db)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"initialized": initialized}) //nolint:errcheck
}

func (s *Server) handleSetupInit(w http.ResponseWriter, r *http.Request) {
	if !setup.IsFirstRun(s.db) {
		http.Error(w, "déjà initialisé", http.StatusConflict)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		http.Error(w, "email et password requis", http.StatusBadRequest)
		return
	}
	if err := setup.CreateFirstAdmin(s.db, req.Email, req.Password); err != nil {
		s.log.Error("setup: création admin", "err", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corps JSON invalide", http.StatusBadRequest)
		return
	}

	ip := clientIP(r.RemoteAddr)
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		ip = strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	key := loginKey(ip, req.Email)
	if blocked, wait := s.loginLimit.blocked(key); blocked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		http.Error(w, "trop de tentatives — réessayez plus tard", http.StatusTooManyRequests)
		return
	}

	var id, hash string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT id, password_hash FROM users WHERE email=?`, req.Email,
	).Scan(&id, &hash)
	if err != nil || !auth.CheckPassword(hash, req.Password) {
		s.loginLimit.fail(key)
		s.auditor.Log(r.Context(), audit.Event{
			Action: "login_failed", Actor: req.Email, IP: audit.IPFrom(r), Severity: audit.Warning,
		})
		s.alertingEngine.Emit(alerting.Event{
			Trigger: alerting.TriggerAdminAuthFailures, Severity: alerting.SevWarning,
			Component: "admin", Detail: map[string]any{"email": req.Email, "ip": audit.IPFrom(r)},
		})
		http.Error(w, "email ou mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	s.loginLimit.success(key)

	s.auditor.Log(r.Context(), audit.Event{
		Action: "login", Actor: req.Email, UserID: id, IP: audit.IPFrom(r), Severity: audit.Info,
	})

	// Vérifier si l'appareil est déjà de confiance (bypass MFA)
	mfaStore := s.mfaStore()
	deviceToken := r.Header.Get("X-Device-Token")
	if deviceToken == "" {
		if c, err := r.Cookie(mfa.TrustedDeviceCookie); err == nil {
			deviceToken = c.Value
		}
	}
	if deviceToken != "" && mfaStore.IsTrustedDevice(r.Context(), id, mfa.HashDeviceToken(deviceToken)) {
		// Appareil de confiance → JWT complet directement
		token, err := auth.SignJWT(id, s.cfg.Security.JWTSecret, 24*time.Hour)
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
		return
	}

	// Vérifier si la MFA est activée pour cet utilisateur
	hasMFA, err := mfaStore.HasVerifiedMFA(r.Context(), id)
	if err == nil && hasMFA {
		// Retourner un token MFA intermédiaire (202)
		pending, err := auth.SignMFAPendingToken(id, s.cfg.Security.JWTSecret)
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		// Lister les méthodes disponibles pour l'UI
		methods, _ := mfaStore.ListMethods(r.Context(), id)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"mfa_required": true,
			"mfa_token":    pending,
			"methods":      methods,
		})
		return
	}

	token, err := auth.SignJWT(id, s.cfg.Security.JWTSecret, 24*time.Hour)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
}

