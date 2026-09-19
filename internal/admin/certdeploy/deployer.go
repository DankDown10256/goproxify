// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Deployer déclenche les déploiements de certificats vers les cibles configurées.
type Deployer struct {
	db     *sql.DB
	log    *slog.Logger
	client *http.Client
	// OnDeployFail est appelé quand un déploiement échoue (targetID, domain, typ, message).
	OnDeployFail func(targetID, domain, typ, message string)
}

func New(db *sql.DB, log *slog.Logger) *Deployer {
	return &Deployer{
		db:     db,
		log:    log,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

type webhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

type webhookPayload struct {
	Domain      string `json:"domain"`
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	ChainPEM    string `json:"chain_pem"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
	TriggeredAt string `json:"triggered_at"`
}

// TriggerForCert déclenche tous les targets on_renewal pour un cert donné.
func (d *Deployer) TriggerForCert(ctx context.Context, certID string) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT id, type, config FROM cert_deploy_targets
		 WHERE cert_id=? AND trigger_on='on_renewal'`, certID)
	if err != nil {
		d.log.Error("certdeploy: query targets", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, typ, cfg string
		if err := rows.Scan(&id, &typ, &cfg); err != nil {
			continue
		}
		go d.runTarget(context.Background(), id, certID, typ, cfg)
	}
}

// TriggerTarget déclenche un target spécifique manuellement.
func (d *Deployer) TriggerTarget(ctx context.Context, targetID string) error {
	var certID, typ, cfg string
	err := d.db.QueryRowContext(ctx,
		`SELECT cert_id, type, config FROM cert_deploy_targets WHERE id=?`, targetID).
		Scan(&certID, &typ, &cfg)
	if err != nil {
		return fmt.Errorf("target introuvable: %w", err)
	}
	go d.runTarget(context.Background(), targetID, certID, typ, cfg)
	return nil
}

func (d *Deployer) runTarget(ctx context.Context, targetID, certID, typ, cfgJSON string) {
	var msg string
	var status string

	var certPEM, keyPEM, domain string
	var expiresAt time.Time
	err := d.db.QueryRowContext(ctx,
		`SELECT domain, cert_pem, key_pem, expires_at FROM certs WHERE id=?`, certID).
		Scan(&domain, &certPEM, &keyPEM, &expiresAt)
	if err != nil {
		d.recordHistory(targetID, certID, "error", "cert introuvable: "+err.Error())
		return
	}

	switch typ {
	case "webhook":
		status, msg = d.doWebhook(cfgJSON, domain, certPEM, keyPEM, expiresAt)
	case "ssh_exec":
		status, msg = d.doSSHExec(cfgJSON, domain, certPEM, keyPEM)
	default:
		status, msg = "error", "type non supporté: "+typ
	}

	d.recordHistory(targetID, certID, status, msg)
	_, _ = d.db.ExecContext(ctx,
		`UPDATE cert_deploy_targets SET last_deploy=CURRENT_TIMESTAMP, last_status=? WHERE id=?`,
		status, targetID)
	if status == "error" {
		d.log.Warn("certdeploy: deploy échoué", "target", targetID, "msg", msg)
		if d.OnDeployFail != nil {
			d.OnDeployFail(targetID, domain, typ, msg)
		}
	} else {
		d.log.Info("certdeploy: deploy ok", "target", targetID, "domain", domain)
	}
}

func (d *Deployer) doWebhook(cfgJSON, domain, certPEM, keyPEM string, expiresAt time.Time) (string, string) {
	var cfg webhookConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil || cfg.URL == "" {
		return "error", "config webhook invalide"
	}

	payload := webhookPayload{
		Domain:      domain,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		ChainPEM:    certPEM,
		Fingerprint: certFingerprint([]byte(certPEM)),
		ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
		TriggeredAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return "error", "URL invalide: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-GoProxify-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "error", "requête échouée: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "ok", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "error", fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func (d *Deployer) recordHistory(targetID, certID, status, message string) {
	_, _ = d.db.Exec(
		`INSERT INTO cert_deploy_history (id, target_id, cert_id, status, message)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?)`,
		targetID, certID, status, message)
}

func certFingerprint(certPEM []byte) string {
	h := sha256.Sum256(certPEM)
	return hex.EncodeToString(h[:])
}

// ── SSH exec ──────────────────────────────────────────────────────────────

type sshConfig struct {
	Host       string `json:"host"`        // "10.0.0.1:22"
	User       string `json:"user"`        // "deploy"
	PrivateKey string `json:"private_key"` // PEM de la clé privée Ed25519/RSA
	// Script exécuté sur la cible. Les variables d'env suivantes sont injectées :
	//   GPX_CERT_PEM, GPX_KEY_PEM, GPX_DOMAIN, GPX_EXPIRES_AT
	// Exemple : "echo \"$GPX_CERT_PEM\" > /etc/ssl/certs/$GPX_DOMAIN.pem && nginx -s reload"
	Script string `json:"script"`
}

func (d *Deployer) doSSHExec(cfgJSON, domain, certPEM, keyPEM string) (string, string) {
	var cfg sshConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil || cfg.Host == "" || cfg.User == "" || cfg.Script == "" {
		return "error", "config ssh_exec invalide (host, user, script requis)"
	}

	signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
	if err != nil {
		return "error", "clé privée SSH invalide: " + err.Error()
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — cible interne, pas de TOFU pour le MVP
		Timeout:         20 * time.Second,
	}

	host := cfg.Host
	if !strings.Contains(host, ":") {
		host += ":22"
	}

	conn, err := ssh.Dial("tcp", host, clientCfg)
	if err != nil {
		return "error", "connexion SSH échouée: " + err.Error()
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return "error", "session SSH échouée: " + err.Error()
	}
	defer sess.Close()

	// Injecte les variables d'environnement via le script lui-même (pas SetEnv,
	// souvent désactivé côté serveur). On préfixe le script avec les exports.
	script := fmt.Sprintf(
		"export GPX_DOMAIN=%q GPX_EXPIRES_AT=%q GPX_CERT_PEM GPX_KEY_PEM\nGPX_CERT_PEM=%q\nGPX_KEY_PEM=%q\n%s",
		domain, "", certPEM, keyPEM, cfg.Script,
	)

	var stderr bytes.Buffer
	sess.Stderr = &stderr
	out, err := sess.Output(script)
	if err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "error", "script SSH échoué: " + errMsg
	}

	outStr := strings.TrimSpace(string(out))
	_ = io.Discard // évite import inutilisé
	if len(outStr) > 200 {
		outStr = outStr[:200] + "…"
	}
	if outStr == "" {
		outStr = "ok"
	}
	return "ok", outStr
}
