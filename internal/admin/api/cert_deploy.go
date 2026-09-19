// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

// CertDeployHandler gère les deploy-targets et pull-tokens d'un certificat.
type CertDeployHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	Deployer interface {
		TriggerTarget(ctx context.Context, targetID string) error
	}
}

func (h *CertDeployHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /api/v1/certs/{certID}/deploy-targets[/{targetID}[/trigger|/history]]
	// /api/v1/certs/{certID}/pull-tokens[/{tokenID}]
	// /api/v1/cert-bundle  (public, pas de certID dans le path)
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certs/")
	parts := strings.SplitN(path, "/", 4)

	if len(parts) < 2 {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	certID := parts[0]
	section := parts[1]

	switch section {
	case "deploy-targets":
		targetID := ""
		if len(parts) >= 3 {
			targetID = parts[2]
		}
		action := ""
		if len(parts) >= 4 {
			action = parts[3]
		}
		switch {
		case r.Method == http.MethodGet && targetID == "":
			h.listTargets(w, r, certID)
		case r.Method == http.MethodPost && targetID == "":
			h.createTarget(w, r, certID)
		case r.Method == http.MethodDelete && targetID != "" && action == "":
			h.deleteTarget(w, r, targetID)
		case r.Method == http.MethodPost && targetID != "" && action == "trigger":
			h.triggerTarget(w, r, targetID)
		case r.Method == http.MethodGet && targetID != "" && action == "history":
			h.listHistory(w, r, targetID)
		default:
			writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		}
	case "pull-tokens":
		tokenID := ""
		if len(parts) >= 3 {
			tokenID = parts[2]
		}
		switch {
		case r.Method == http.MethodGet && tokenID == "":
			h.listPullTokens(w, r, certID)
		case r.Method == http.MethodPost && tokenID == "":
			h.createPullToken(w, r, certID)
		case r.Method == http.MethodDelete && tokenID != "":
			h.revokePullToken(w, r, tokenID)
		default:
			writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		}
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

// ── Deploy targets ────────────────────────────────────────────────────────

type deployTarget struct {
	ID         string  `json:"id"`
	CertID     string  `json:"cert_id"`
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Config     any     `json:"config"`
	TriggerOn  string  `json:"trigger_on"`
	LastDeploy *string `json:"last_deploy,omitempty"`
	LastStatus string  `json:"last_status"`
	CreatedAt  string  `json:"created_at"`
}

func (h *CertDeployHandler) listTargets(w http.ResponseWriter, r *http.Request, certID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, cert_id, name, type, config, trigger_on, last_deploy, last_status, created_at
		 FROM cert_deploy_targets WHERE cert_id=? ORDER BY created_at DESC`, certID)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: list targets", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]deployTarget, 0)
	for rows.Next() {
		var dt deployTarget
		var cfgStr string
		var lastDeploy sql.NullString
		if err := rows.Scan(&dt.ID, &dt.CertID, &dt.Name, &dt.Type, &cfgStr,
			&dt.TriggerOn, &lastDeploy, &dt.LastStatus, &dt.CreatedAt); err != nil {
			continue
		}
		if lastDeploy.Valid {
			dt.LastDeploy = &lastDeploy.String
		}
		var cfg any
		if err := json.Unmarshal([]byte(cfgStr), &cfg); err == nil {
			dt.Config = cfg
		} else {
			dt.Config = map[string]any{}
		}
		// masque les secrets dans la config webhook
		if m, ok := dt.Config.(map[string]any); ok {
			if _, has := m["secret"]; has {
				m["secret"] = "***"
			}
		}
		result = append(result, dt)
	}
	jsonOK(w, result)
}

type createTargetReq struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Config    any    `json:"config"`
	TriggerOn string `json:"trigger_on"`
}

func (h *CertDeployHandler) createTarget(w http.ResponseWriter, r *http.Request, certID string) {
	var req createTargetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Type == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if req.TriggerOn == "" {
		req.TriggerOn = "on_renewal"
	}
	cfgBytes, _ := json.Marshal(req.Config)

	var id string
	err := h.DB.QueryRowContext(r.Context(),
		`INSERT INTO cert_deploy_targets (id, cert_id, name, type, config, trigger_on)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?)
		 RETURNING id`,
		certID, req.Name, req.Type, string(cfgBytes), req.TriggerOn).Scan(&id)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: create target", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *CertDeployHandler) deleteTarget(w http.ResponseWriter, r *http.Request, targetID string) {
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM cert_deploy_targets WHERE id=?`, targetID)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: delete target", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *CertDeployHandler) triggerTarget(w http.ResponseWriter, r *http.Request, targetID string) {
	if h.Deployer == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	if err := h.Deployer.TriggerTarget(r.Context(), targetID); err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "triggered"})
}

func (h *CertDeployHandler) listHistory(w http.ResponseWriter, r *http.Request, targetID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, status, message, deployed_at FROM cert_deploy_history
		 WHERE target_id=? ORDER BY deployed_at DESC LIMIT 50`, targetID)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: list history", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	type histRow struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		Message    string `json:"message"`
		DeployedAt string `json:"deployed_at"`
	}
	result := make([]histRow, 0)
	for rows.Next() {
		var h histRow
		if err := rows.Scan(&h.ID, &h.Status, &h.Message, &h.DeployedAt); err == nil {
			result = append(result, h)
		}
	}
	jsonOK(w, result)
}

// ── Pull tokens ───────────────────────────────────────────────────────────

type pullToken struct {
	ID        string  `json:"id"`
	CertID    string  `json:"cert_id"`
	Name      string  `json:"name"`
	Format    string  `json:"format"`
	MaxUses   int     `json:"max_uses"`
	Uses      int     `json:"uses"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	CreatedAt string  `json:"created_at"`
	CreatedBy string  `json:"created_by"`
}

func (h *CertDeployHandler) listPullTokens(w http.ResponseWriter, r *http.Request, certID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, cert_id, name, format, max_uses, uses, expires_at, created_at, created_by
		 FROM cert_pull_tokens WHERE cert_id=? ORDER BY created_at DESC`, certID)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: list tokens", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]pullToken, 0)
	for rows.Next() {
		var pt pullToken
		var exp sql.NullString
		if err := rows.Scan(&pt.ID, &pt.CertID, &pt.Name, &pt.Format,
			&pt.MaxUses, &pt.Uses, &exp, &pt.CreatedAt, &pt.CreatedBy); err != nil {
			continue
		}
		if exp.Valid {
			pt.ExpiresAt = &exp.String
		}
		result = append(result, pt)
	}
	jsonOK(w, result)
}

type createPullTokenReq struct {
	Name    string `json:"name"`
	Format  string `json:"format"`
	MaxUses int    `json:"max_uses"`
	TTLHour int    `json:"ttl_hours"`
}

func (h *CertDeployHandler) createPullToken(w http.ResponseWriter, r *http.Request, certID string) {
	var req createPullTokenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if req.Name == "" {
		req.Name = "token-" + time.Now().Format("20060102-150405")
	}
	if req.Format == "" {
		req.Format = "pem"
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	token := hex.EncodeToString(raw)
	h2 := hmac.New(sha256.New, []byte("goproxify-pull"))
	h2.Write([]byte(token))
	tokenHash := hex.EncodeToString(h2.Sum(nil))

	var expiresAt *time.Time
	if req.TTLHour > 0 {
		t := time.Now().Add(time.Duration(req.TTLHour) * time.Hour)
		expiresAt = &t
	}

	userID := auth.UserIDFromContext(r.Context())

	var id string
	err := h.DB.QueryRowContext(r.Context(),
		`INSERT INTO cert_pull_tokens (id, cert_id, name, token_hash, format, max_uses, expires_at, created_by)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?)
		 RETURNING id`,
		certID, req.Name, tokenHash, req.Format, req.MaxUses, expiresAt, userID).Scan(&id)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: create pull token", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "token": token, "format": req.Format})
}

func (h *CertDeployHandler) revokePullToken(w http.ResponseWriter, r *http.Request, tokenID string) {
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM cert_pull_tokens WHERE id=?`, tokenID)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("cert_deploy: revoke token", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── CertBundleHandler — endpoint public (pull par token) ──────────────────

type CertBundleHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *CertBundleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	token := r.URL.Query().Get("token")
	format := r.URL.Query().Get("format")
	if token == "" {
		http.Error(w, "token requis", http.StatusUnauthorized)
		return
	}
	if format == "" {
		format = "pem"
	}

	h2 := hmac.New(sha256.New, []byte("goproxify-pull"))
	h2.Write([]byte(token))
	tokenHash := hex.EncodeToString(h2.Sum(nil))

	var tokenID, certID string
	var maxUses, uses int
	var expiresAt sql.NullTime
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, cert_id, max_uses, uses, expires_at FROM cert_pull_tokens WHERE token_hash=?`,
		tokenHash).Scan(&tokenID, &certID, &maxUses, &uses, &expiresAt)
	if err != nil {
		http.Error(w, "token invalide ou révoqué", http.StatusUnauthorized)
		return
	}
	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		http.Error(w, "token expiré", http.StatusUnauthorized)
		return
	}
	if maxUses > 0 && uses >= maxUses {
		http.Error(w, "token épuisé", http.StatusUnauthorized)
		return
	}

	var certPEM, keyPEM, domain string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain, cert_pem, key_pem FROM certs WHERE id=?`, certID).
		Scan(&domain, &certPEM, &keyPEM); err != nil {
		http.Error(w, "certificat introuvable", http.StatusNotFound)
		return
	}

	// Incrémente l'usage
	_, _ = h.DB.ExecContext(r.Context(),
		`UPDATE cert_pull_tokens SET uses=uses+1 WHERE id=?`, tokenID)

	switch format {
	case "pem":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+domain+`.pem"`)
		_, _ = w.Write([]byte(certPEM))
	case "key":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+domain+`.key"`)
		_, _ = w.Write([]byte(keyPEM))
	case "fullchain":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+domain+`-fullchain.pem"`)
		_, _ = w.Write([]byte(certPEM + "\n" + keyPEM))
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"domain":   domain,
			"cert_pem": certPEM,
			"key_pem":  keyPEM,
		})
	}
}
