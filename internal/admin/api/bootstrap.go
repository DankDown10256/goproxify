// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const bootstrapDefaultTTL = 24 * time.Hour

// BootstrapHandler tickets one-shot pour intégration architecture (QR / lien /i/{token}).
// POST /api/v1/bootstrap-tickets (auth) — crée un ticket + QR + install_cmd.
// GET  /api/v1/bootstrap/{token} — JSON public.
// GET  /i/{token} — page HTML publique.
// GET  /i/{token}.sh — script bash (écrit compose/.env et docker compose up -d).
type BootstrapHandler struct {
	DB               *sql.DB
	Log              *slog.Logger
	ResolvePublicURL func(r *http.Request) string
}

type bootstrapTicketRow struct {
	Token        string
	HostName     string
	CoreEndpoint string
	Payload      json.RawMessage
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

func (h *BootstrapHandler) ensureTable() {
	_, _ = h.DB.Exec(`CREATE TABLE IF NOT EXISTS bootstrap_tickets (
		token         TEXT PRIMARY KEY,
		host_name     TEXT NOT NULL DEFAULT '',
		core_endpoint TEXT NOT NULL DEFAULT '',
		payload       TEXT NOT NULL DEFAULT '{}',
		expires_at    DATETIME NOT NULL,
		created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
}

func (h *BootstrapHandler) publicBase(r *http.Request) string {
	if h.ResolvePublicURL != nil {
		if u := strings.TrimRight(strings.TrimSpace(h.ResolvePublicURL(r)), "/"); u != "" {
			return u
		}
	}
	return ""
}

func (h *BootstrapHandler) ServeCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	h.ensureTable()
	var req struct {
		HostName     string          `json:"host_name"`
		CoreEndpoint string          `json:"core_endpoint"`
		Payload      json.RawMessage `json:"payload"`
		TTLHours     int             `json:"ttl_hours"`
		AutoAccept   *bool           `json:"auto_accept"`
		NodeNames    []string        `json:"node_names"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if len(req.Payload) == 0 {
		req.Payload = json.RawMessage(`{}`)
	}
	payloadObj := map[string]any{}
	_ = json.Unmarshal(req.Payload, &payloadObj)
	autoAccept := true
	if req.AutoAccept != nil {
		autoAccept = *req.AutoAccept
	} else if v, ok := payloadObj["auto_accept"].(bool); ok {
		autoAccept = v
	}
	payloadObj["auto_accept"] = autoAccept
	if len(req.NodeNames) > 0 {
		payloadObj["node_names"] = req.NodeNames
	}
	payloadBytes, err := json.Marshal(payloadObj)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	ttl := bootstrapDefaultTTL
	if req.TTLHours > 0 && req.TTLHours <= 168 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}
	tok, err := randomBootstrapToken()
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	exp := time.Now().UTC().Add(ttl)
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO bootstrap_tickets(token, host_name, core_endpoint, payload, expires_at) VALUES(?,?,?,?,?)`,
		tok, strings.TrimSpace(req.HostName), strings.TrimSpace(req.CoreEndpoint), string(payloadBytes), exp,
	)
	if err != nil {
		if h.Log != nil {
			h.Log.Error("bootstrap: insert", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if autoAccept {
		names := req.NodeNames
		if len(names) == 0 {
			if raw, ok := payloadObj["node_names"].([]any); ok {
				for _, v := range raw {
					if s, ok := v.(string); ok {
						names = append(names, s)
					}
				}
			}
		}
		LinkBootstrapToDeclared(h.DB, tok, names)
	}

	base := h.publicBase(r)
	pageURL := base + "/i/" + tok
	scriptURL := pageURL + ".sh"
	if base == "" {
		pageURL = "/i/" + tok
		scriptURL = pageURL + ".sh"
	}
	installCmd := "curl -fsSL " + scriptURL + " | bash"
	qrPNG, err := qrcode.Encode(pageURL, qrcode.Medium, 256)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, map[string]any{
		"token":         tok,
		"url":           pageURL,
		"script_url":    scriptURL,
		"install_cmd":   installCmd,
		"qr_code":       "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG),
		"expires_at":    exp.Format(time.RFC3339),
		"host_name":     req.HostName,
		"core_endpoint": req.CoreEndpoint,
	})
}

func (h *BootstrapHandler) ServePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	tok, wantSh := bootstrapTokenFromPath(r.URL.Path)
	if tok == "" {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if r.URL.Query().Get("format") == "sh" {
		wantSh = true
	}
	row, err := h.load(r, tok)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if time.Now().UTC().After(row.ExpiresAt) {
		writeErr(w, r, http.StatusGone, "api.err.not_found")
		return
	}

	wantJSON := !wantSh && (strings.Contains(r.Header.Get("Accept"), "application/json") ||
		r.URL.Query().Get("format") == "json" ||
		strings.HasPrefix(r.URL.Path, "/api/v1/bootstrap/"))

	if wantSh {
		h.writeScript(w, r, row)
		return
	}
	if wantJSON {
		base := h.publicBase(r)
		scriptURL := base + "/i/" + tok + ".sh"
		if base == "" {
			scriptURL = "/i/" + tok + ".sh"
		}
		jsonOK(w, map[string]any{
			"host_name":     row.HostName,
			"core_endpoint": row.CoreEndpoint,
			"payload":       json.RawMessage(row.Payload),
			"expires_at":    row.ExpiresAt.Format(time.RFC3339),
			"script_url":    scriptURL,
			"install_cmd":   "curl -fsSL " + scriptURL + " | bash",
		})
		return
	}
	h.writeHTML(w, r, row)
}

func (h *BootstrapHandler) load(r *http.Request, tok string) (*bootstrapTicketRow, error) {
	h.ensureTable()
	var row bootstrapTicketRow
	var payload string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT token, host_name, core_endpoint, payload, expires_at, created_at FROM bootstrap_tickets WHERE token=?`, tok,
	).Scan(&row.Token, &row.HostName, &row.CoreEndpoint, &payload, &row.ExpiresAt, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	row.Payload = json.RawMessage(payload)
	return &row, nil
}

func (h *BootstrapHandler) writeHTML(w http.ResponseWriter, r *http.Request, row *bootstrapTicketRow) {
	var payload map[string]any
	_ = json.Unmarshal(row.Payload, &payload)
	compose, _ := payload["compose_text"].(string)
	envText, _ := payload["env_text"].(string)
	cliText, _ := payload["cli_text"].(string)
	note, _ := payload["note"].(string)

	base := h.publicBase(r)
	scriptURL := base + "/i/" + row.Token + ".sh"
	if base == "" {
		scriptURL = "/i/" + row.Token + ".sh"
	}
	installCmd := "curl -fsSL " + scriptURL + " | bash"

	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>GoProxify — bootstrap ` + esc(row.HostName) + `</title>`)
	b.WriteString(`<style>
body{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#0f1419;color:#e7ecf1;line-height:1.45}
h1{font-size:1.25rem;margin:0 0 8px} .muted{color:#9aa4b2;font-size:.9rem;margin-bottom:20px}
pre{background:#1a222c;border-radius:8px;padding:14px;overflow:auto;font-size:12px;white-space:pre-wrap}
.card{background:#151b22;border:1px solid #2a3441;border-radius:10px;padding:16px;margin-bottom:16px}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#9aa4b2;margin-bottom:6px}
code{font-size:12px;word-break:break-all}
.hl{border-color:#3b82f6}
</style></head><body>`)
	b.WriteString(`<h1>Configuration — ` + esc(row.HostName) + `</h1>`)
	b.WriteString(`<p class="muted">Ticket d’intégration vers le Core. Expire le ` + esc(row.ExpiresAt.UTC().Format(time.RFC3339)) + `.</p>`)
	b.WriteString(`<div class="card hl"><label>Sur le serveur (Docker)</label><pre>` + esc(installCmd) + `</pre>`)
	b.WriteString(`<p class="muted" style="margin:8px 0 0">Écrit compose/.env puis lance <code>docker compose up -d</code>.</p></div>`)
	if row.CoreEndpoint != "" {
		b.WriteString(`<div class="card"><label>Core (cible)</label><code>` + esc(row.CoreEndpoint) + `</code></div>`)
	}
	if note != "" {
		b.WriteString(`<div class="card"><label>Note</label><p style="margin:0">` + esc(note) + `</p></div>`)
	}
	if compose != "" {
		b.WriteString(`<div class="card"><label>docker-compose.yml</label><pre>` + esc(compose) + `</pre></div>`)
	}
	if envText != "" {
		b.WriteString(`<div class="card"><label>.env</label><pre>` + esc(envText) + `</pre></div>`)
	}
	if cliText != "" {
		b.WriteString(`<div class="card"><label>CLI</label><pre>` + esc(cliText) + `</pre></div>`)
	}
	if compose == "" && envText == "" && cliText == "" {
		b.WriteString(`<div class="card"><p class="muted" style="margin:0">Payload vide — regénérez le ticket depuis l’Admin.</p></div>`)
	}
	autoNote := "Après démarrage, le nœud est accepté automatiquement s’il a été déclaré depuis le wizard architecture."
	if payload != nil {
		if v, ok := payload["auto_accept"].(bool); ok && !v {
			autoNote = "Après démarrage, acceptez le nœud pending dans Infrastructure (Admin)."
		}
	}
	b.WriteString(`<p class="muted">` + esc(autoNote) + `</p>`)
	b.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (h *BootstrapHandler) writeScript(w http.ResponseWriter, r *http.Request, row *bootstrapTicketRow) {
	var payload map[string]any
	_ = json.Unmarshal(row.Payload, &payload)
	compose, _ := payload["compose_text"].(string)
	envText, _ := payload["env_text"].(string)

	delim := "GPXEOF_" + row.Token[:12]
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString("# GoProxify bootstrap — host: " + shellSingleQuote(row.HostName) + "\n")
	if row.CoreEndpoint != "" {
		b.WriteString("# Core: " + shellSingleQuote(row.CoreEndpoint) + "\n")
	}
	b.WriteString("DIR=\"${GPX_BOOTSTRAP_DIR:-./goproxify-bootstrap}\"\n")
	b.WriteString("mkdir -p \"$DIR\"\n")
	b.WriteString("cd \"$DIR\"\n")
	if compose != "" {
		b.WriteString("cat > docker-compose.yml <<" + delim + "\n")
		b.WriteString(compose)
		if !strings.HasSuffix(compose, "\n") {
			b.WriteString("\n")
		}
		b.WriteString(delim + "\n")
	}
	if envText != "" {
		b.WriteString("cat > .env <<" + delim + "\n")
		b.WriteString(envText)
		if !strings.HasSuffix(envText, "\n") {
			b.WriteString("\n")
		}
		b.WriteString(delim + "\n")
	}
	b.WriteString("echo \"Fichiers écrits dans $DIR\"\n")
	b.WriteString("if ! command -v docker >/dev/null 2>&1; then\n")
	b.WriteString("  echo \"docker introuvable — lancez compose manuellement dans $DIR\" >&2\n")
	b.WriteString("  exit 0\n")
	b.WriteString("fi\n")
	if compose != "" {
		b.WriteString("if docker compose version >/dev/null 2>&1; then\n")
		b.WriteString("  docker compose up -d\n")
		b.WriteString("elif command -v docker-compose >/dev/null 2>&1; then\n")
		b.WriteString("  docker-compose up -d\n")
		b.WriteString("else\n")
		b.WriteString("  echo \"docker compose introuvable — fichiers prêts dans $DIR\" >&2\n")
		b.WriteString("  exit 0\n")
		b.WriteString("fi\n")
		autoOK := true
		if v, ok := payload["auto_accept"].(bool); ok {
			autoOK = v
		}
		if autoOK {
			b.WriteString("echo \"Stack démarrée. Acceptation automatique si le nœud a été déclaré via le wizard.\"\n")
		} else {
			b.WriteString("echo \"Stack démarrée. Acceptez le nœud pending dans l'Admin Infrastructure.\"\n")
		}
	} else {
		b.WriteString("echo \"Pas de compose dans le ticket — rien à démarrer.\" >&2\n")
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="goproxify-bootstrap.sh"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func randomBootstrapToken() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// bootstrapTokenFromPath extrait le token ; wantSh si le chemin se termine par .sh.
func bootstrapTokenFromPath(path string) (tok string, wantSh bool) {
	path = strings.TrimSuffix(path, "/")
	for _, prefix := range []string{"/i/", "/api/v1/bootstrap/"} {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		part := strings.SplitN(rest, "/", 2)[0]
		part = strings.TrimSpace(part)
		if strings.HasSuffix(part, ".sh") {
			wantSh = true
			part = strings.TrimSuffix(part, ".sh")
		}
		if len(part) >= 16 && len(part) <= 64 {
			return part, wantSh
		}
		return "", false
	}
	return "", false
}
