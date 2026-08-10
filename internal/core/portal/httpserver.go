// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	corews "github.com/vincamok/goproxify/internal/core/ws"
	"nhooyr.io/websocket"
)

// HTTPServer sert l'UI portail + API JSON + WS terminal.
type HTTPServer struct {
	cfg               *Config
	store             *Store
	sessions          *SessionManager
	log               *slog.Logger
	audit             func(AuditEvent)
	srv               *http.Server
	shell             *ShellBroker
	providers         AuthProviderLookup
	masterSecret      string
	onInviteCompleted func(userID string)
	challenges        *MFAChallengeStore
	sendEmailOTP      func(email, code string) error
	pageTemplates     *TemplateStore
}

type portalToken struct {
	UserID   string
	Username string
	VaultKey [32]byte
	Expires  time.Time
	Raw      string
}

// NewHTTPServer construit le serveur HTTP portail.
func NewHTTPServer(cfg *Config, store *Store, sessions *SessionManager, log *slog.Logger, audit func(AuditEvent)) *HTTPServer {
	if audit == nil {
		audit = func(AuditEvent) {}
	}
	return &HTTPServer{
		cfg:           cfg,
		store:         store,
		sessions:      sessions,
		log:           log,
		audit:         audit,
		challenges:    NewMFAChallengeStore(),
		pageTemplates: NewTemplateStore(),
	}
}

// Handler retourne le mux HTTP.
func (h *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.serveIndex)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "portal": true})
	})
	mux.HandleFunc("POST /api/register", h.handleRegister)
	mux.HandleFunc("POST /api/login", h.handleLogin)
	mux.HandleFunc("POST /api/complete-invite", h.handleCompleteInvite)
	mux.HandleFunc("GET /api/auth-info", h.handleAuthInfo)
	mux.HandleFunc("GET /api/oidc/start", h.handleOIDCStart)
	mux.HandleFunc("GET /api/oidc/callback", h.handleOIDCCallback)
	mux.HandleFunc("POST /api/2fa/verify", h.handle2FAVerify)
	mux.HandleFunc("POST /api/2fa/email/send", h.handle2FAEmailSend)
	mux.HandleFunc("POST /api/logout", h.auth(h.handleLogout))
	mux.HandleFunc("GET /api/me", h.auth(h.handleMe))
	mux.HandleFunc("GET /api/2fa/status", h.auth(h.handle2FAStatus))
	mux.HandleFunc("POST /api/2fa/totp/setup", h.auth(h.handle2FATOTPSetup))
	mux.HandleFunc("POST /api/2fa/totp/verify", h.auth(h.handle2FATOTPVerifyEnable))
	mux.HandleFunc("DELETE /api/2fa/totp", h.auth(h.handle2FATOTPDisable))
	mux.HandleFunc("POST /api/2fa/email/enable", h.auth(h.handle2FAEmailEnable))
	mux.HandleFunc("DELETE /api/2fa/email", h.auth(h.handle2FAEmailDisable))
	mux.HandleFunc("GET /api/targets", h.auth(h.handleListTargets))
	mux.HandleFunc("POST /api/targets", h.auth(h.handleUpsertTarget))
	mux.HandleFunc("DELETE /api/targets/{id}", h.auth(h.handleDeleteTarget))
	mux.HandleFunc("GET /api/vault", h.auth(h.handleListVault))
	mux.HandleFunc("PUT /api/vault/{id}", h.auth(h.handlePutVault))
	mux.HandleFunc("DELETE /api/vault/{id}", h.auth(h.handleDeleteVault))
	mux.HandleFunc("POST /api/sessions", h.auth(h.handleCreateSession))
	mux.HandleFunc("GET /api/sessions", h.auth(h.handleListSessions))
	mux.HandleFunc("DELETE /api/sessions/{id}", h.auth(h.handleRevokeSession))
	mux.HandleFunc("GET /api/audit", h.auth(h.handleListAudit))
	mux.HandleFunc("GET /api/favorites", h.auth(h.handleListFavorites))
	mux.HandleFunc("PUT /api/favorites", h.auth(h.handlePutFavorites))
	mux.HandleFunc("POST /api/favorites/{id}", h.auth(h.handleToggleFavorite))
	mux.HandleFunc("GET /api/ws/{uuid}", h.handleWS)
	return mux
}

// Start écoute sur addr.
func (h *HTTPServer) Start(addr string) error {
	h.srv = &http.Server{Addr: addr, Handler: h.Handler()}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.log.Info("portal http listen", "addr", addr)
	go func() {
		if err := h.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			h.log.Error("portal http", "err", err)
		}
	}()
	return nil
}

// Stop arrête le serveur HTTP.
func (h *HTTPServer) Stop() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
}

func (h *HTTPServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	vars := PageVars{
		Brand:    "GoProxify Access",
		CoreName: "",
	}
	if h.cfg != nil {
		vars.CoreName = h.cfg.PublicHost
	}
	if htmlOut, useSPA := h.pageTemplates.RenderIndex(vars); !useSPA {
		_, _ = w.Write([]byte(htmlOut))
		return
	}
	_, _ = w.Write([]byte(portalIndexHTML))
}

func (h *HTTPServer) handleAuthInfo(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"local":                  true,
		"register":               false,
		"allow_personal_targets": h.cfg != nil && h.cfg.AllowPersonalTargets,
		"require_2fa":            h.cfg != nil && h.cfg.Require2FA,
	}
	sso, p, err := h.resolveSSO()
	if err != nil {
		out["provider_error"] = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	if p != nil && sso != nil {
		out["provider"] = map[string]any{
			"id":             p.ID,
			"name":           p.Name,
			"type":           sso.Provider,
			"form_login":     providerSupportsForm(sso),
			"oidc":           providerSupportsOIDC(sso),
			"oidc_start":     "/api/oidc/start",
			"local_fallback": true,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *HTTPServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "inscription publique désactivée — invitation Admin requise", http.StatusGone)
}

func (h *HTTPServer) handleCompleteInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" || len(body.Password) < 8 {
		http.Error(w, "token + password (≥8) requis", http.StatusBadRequest)
		return
	}
	hash := HashInviteToken(strings.TrimSpace(body.Token))
	u, ok := h.store.FindUserByInviteHash(hash)
	if !ok {
		http.Error(w, "invitation invalide ou déjà utilisée", http.StatusBadRequest)
		return
	}
	if u.Status == UserStatusDisabled {
		http.Error(w, "compte désactivé", http.StatusForbidden)
		return
	}
	if InviteExpired(u.InviteExpires) {
		http.Error(w, "invitation expirée", http.StatusGone)
		return
	}
	pwHash, err := HashPassword(body.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.store.CompleteInvite(u.ID, pwHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := DeriveVaultKey(u.ID, body.Password)
	if len(h.store.VaultBlob(u.ID)) == 0 {
		sealed, _ := SealVault(key, VaultPayload{})
		_ = h.store.SetVaultBlob(u.ID, sealed)
	}
	if h.onInviteCompleted != nil {
		h.onInviteCompleted(u.ID)
	}
	tok, err := h.issueToken(u.ID, u.Username, key)
	if err != nil {
		http.Error(w, "persistance session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "username": u.Username})
}

func (h *HTTPServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.Username == "" || body.Password == "" {
		http.Error(w, "username + password requis", http.StatusBadRequest)
		return
	}

	// 1) Auth provider (basic / LDAP) si configuré
	sso, _, err := h.resolveSSO()
	if err != nil {
		h.log.Warn("portal: auth_provider", "err", err)
	}
	if sso != nil && providerSupportsForm(sso) {
		ok, aerr := authenticateProvider(sso, body.Username, body.Password)
		if aerr != nil {
			http.Error(w, aerr.Error(), http.StatusBadGateway)
			return
		}
		if ok {
			u, err := h.store.EnsureSSOUser(body.Username)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			key := DeriveSSOVaultKey(h.masterSecret, u.ID)
			if len(h.store.VaultBlob(u.ID)) == 0 {
				sealed, _ := SealVault(key, VaultPayload{})
				_ = h.store.SetVaultBlob(u.ID, sealed)
			}
			h.finishLogin(w, u, key, "provider")
			return
		}
	}

	// 2) Compte local (fallback)
	u, ok := h.store.FindUserByUsername(body.Username)
	if !ok || u.PasswordHash == "" || !CheckPassword(u.PasswordHash, body.Password) {
		http.Error(w, "identifiants invalides", http.StatusUnauthorized)
		return
	}
	if u.Status == UserStatusDisabled {
		http.Error(w, "compte désactivé", http.StatusForbidden)
		return
	}
	if u.Status == UserStatusInvited {
		http.Error(w, "compte non activé — utilisez le lien d'invitation", http.StatusForbidden)
		return
	}
	key := DeriveVaultKey(u.ID, body.Password)
	if blob := h.store.VaultBlob(u.ID); len(blob) > 0 {
		if _, err := OpenVault(key, blob); err != nil {
			http.Error(w, "vault illisible", http.StatusUnauthorized)
			return
		}
	}
	h.finishLogin(w, u, key, "local")
}

// finishLogin émet le token ou un challenge 2FA.
func (h *HTTPServer) finishLogin(w http.ResponseWriter, u UserRecord, key [32]byte, via string) {
	if u.Status == UserStatusDisabled {
		http.Error(w, "compte désactivé", http.StatusForbidden)
		return
	}
	require := h.cfg != nil && h.cfg.Require2FA
	has := UserHas2FA(u)
	if require && !has {
		http.Error(w, "2FA requise — activez TOTP ou OTP email avant de vous connecter", http.StatusForbidden)
		return
	}
	if has {
		ch := newMFAChallenge(u.ID, u.Username, key)
		h.challenges.Put(ch)
		writeJSON(w, http.StatusOK, map[string]any{
			"need_2fa":     true,
			"challenge_id": ch.ID,
			"methods":      User2FAMethods(u),
			"username":     u.Username,
		})
		return
	}
	tok, err := h.issueToken(u.ID, u.Username, key)
	if err != nil {
		http.Error(w, "persistance session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "username": u.Username, "via": via})
}

func (h *HTTPServer) handleMe(w http.ResponseWriter, r *http.Request, pt portalToken) {
	u, _ := h.store.FindUserByID(pt.UserID)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":               pt.Username,
		"user_id":                pt.UserID,
		"allow_personal_targets": h.cfg != nil && h.cfg.AllowPersonalTargets,
		"require_2fa":            h.cfg != nil && h.cfg.Require2FA,
		"totp_enabled":           u.TOTPEnabled,
		"email_otp_enabled":      u.EmailOTPEnabled,
		"favorites":              h.store.Favorites(pt.UserID),
	})
}

func (h *HTTPServer) handleLogout(w http.ResponseWriter, r *http.Request, pt portalToken) {
	if pt.Raw != "" {
		_ = h.store.DeleteAuthSession(pt.Raw)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) issueToken(userID, username string, vaultKey [32]byte) (string, error) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	sess := AuthSession{
		UserID:   userID,
		Username: username,
		VaultKey: hex.EncodeToString(vaultKey[:]),
		Expires:  time.Now().Add(12 * time.Hour),
	}
	if err := h.store.PutAuthSession(tok, sess); err != nil {
		return "", err
	}
	return tok, nil
}

func (h *HTTPServer) auth(next func(http.ResponseWriter, *http.Request, portalToken)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(hdr, "Bearer ")
		sess, ok := h.store.GetAuthSession(tok)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		vk, err := hex.DecodeString(sess.VaultKey)
		if err != nil || len(vk) != 32 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var key [32]byte
		copy(key[:], vk)
		next(w, r, portalToken{
			UserID: sess.UserID, Username: sess.Username, VaultKey: key,
			Expires: sess.Expires, Raw: tok,
		})
	}
}

func (h *HTTPServer) handleListTargets(w http.ResponseWriter, r *http.Request, pt portalToken) {
	type item struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		Kind      TargetKind `json:"kind"`
		Source    string     `json:"source"`
		Host      string     `json:"host,omitempty"`
		Port      int        `json:"port,omitempty"`
		AgentName string     `json:"agent_name,omitempty"`
		Container string     `json:"container,omitempty"`
		Tags      []string   `json:"tags,omitempty"`
	}
	userTags := h.userTags(pt.UserID)
	var out []item
	for _, c := range FilterCatalog(h.store.Catalog(), userTags) {
		out = append(out, item{
			ID: c.ID, Name: c.Name, Kind: c.Kind, Source: "catalog",
			Host: c.Host, Port: c.Port, AgentName: c.AgentName, Container: c.Container,
			Tags: c.Tags,
		})
	}
	if h.cfg != nil && h.cfg.AllowPersonalTargets {
		for _, p := range h.store.PersonalTargets(pt.UserID) {
			out = append(out, item{
				ID: p.ID, Name: p.Name, Kind: p.Kind, Source: "personal",
				Host: p.Host, Port: p.Port, AgentName: p.AgentName, Container: p.Container,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": out})
}

func (h *HTTPServer) userTags(userID string) []string {
	u, ok := h.store.FindUserByID(userID)
	if !ok || u.Tags == nil {
		return nil
	}
	return u.Tags
}

func (h *HTTPServer) handleUpsertTarget(w http.ResponseWriter, r *http.Request, pt portalToken) {
	if h.cfg == nil || !h.cfg.AllowPersonalTargets {
		http.Error(w, "cibles personnelles désactivées", http.StatusForbidden)
		return
	}
	var body struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		Kind       TargetKind `json:"kind"`
		Host       string     `json:"host"`
		Port       int        `json:"port"`
		Username   string     `json:"username"`
		Password   string     `json:"password"`
		PrivateKey string     `json:"private_key"`
		AgentName  string     `json:"agent_name"`
		Container  string     `json:"container"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.Kind == "" {
		body.Kind = TargetSSH
	}
	if body.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	if body.Kind == TargetSSH && body.Host == "" {
		http.Error(w, "name + host requis", http.StatusBadRequest)
		return
	}
	// Docker via cibles personnelles interdit : utiliser le catalogue tagué (authz).
	if body.Kind == TargetDocker {
		http.Error(w, "cibles docker personnelles interdites — utilisez le catalogue", http.StatusForbidden)
		return
	}
	if body.Port <= 0 {
		body.Port = 22
	}
	if body.ID == "" {
		body.ID = uuid.NewString()
	}
	t := PersonalTarget{
		ID: body.ID, Name: body.Name, Kind: body.Kind,
		Host: body.Host, Port: body.Port, Username: body.Username,
		AgentName: body.AgentName, Container: body.Container,
	}
	if err := h.store.UpsertPersonalTarget(pt.UserID, t); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if body.Password != "" || body.PrivateKey != "" {
		if err := PutTargetCreds(h.store, pt.UserID, pt.VaultKey, body.ID, TargetCreds{
			Username: body.Username, Password: body.Password, PrivateKey: body.PrivateKey,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *HTTPServer) handleDeleteTarget(w http.ResponseWriter, r *http.Request, pt portalToken) {
	if h.cfg == nil || !h.cfg.AllowPersonalTargets {
		http.Error(w, "cibles personnelles désactivées", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	_ = h.store.DeletePersonalTarget(pt.UserID, id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) handleListVault(w http.ResponseWriter, r *http.Request, pt portalToken) {
	meta, err := ListVaultMeta(h.store, pt.UserID, pt.VaultKey)
	if err != nil {
		http.Error(w, "vault illisible", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": meta})
}

func (h *HTTPServer) handlePutVault(w http.ResponseWriter, r *http.Request, pt portalToken) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "target id requis", http.StatusBadRequest)
		return
	}
	var body struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	existing, _, err := GetTargetCreds(h.store, pt.UserID, pt.VaultKey, id)
	if err != nil {
		http.Error(w, "vault illisible", http.StatusUnauthorized)
		return
	}
	creds := existing
	if u := strings.TrimSpace(body.Username); u != "" {
		creds.Username = u
	}
	if body.Password != "" {
		creds.Password = body.Password
	}
	if body.PrivateKey != "" {
		creds.PrivateKey = body.PrivateKey
	}
	if strings.TrimSpace(creds.Username) == "" {
		http.Error(w, "login SSH requis", http.StatusBadRequest)
		return
	}
	if creds.Password == "" && creds.PrivateKey == "" {
		http.Error(w, "mot de passe ou clé privée requis", http.StatusBadRequest)
		return
	}
	if err := PutTargetCreds(h.store, pt.UserID, pt.VaultKey, id, creds); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, VaultEntryMeta{
		TargetID: id, Username: creds.Username,
		HasPassword: creds.Password != "", HasPrivateKey: creds.PrivateKey != "",
	})
}

func (h *HTTPServer) handleDeleteVault(w http.ResponseWriter, r *http.Request, pt portalToken) {
	id := r.PathValue("id")
	if err := DeleteTargetCreds(h.store, pt.UserID, pt.VaultKey, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) handleCreateSession(w http.ResponseWriter, r *http.Request, pt portalToken) {
	var body struct {
		TargetID string        `json:"target_id"`
		Source   string        `json:"source"`
		Facade   SessionFacade `json:"facade"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.Facade == "" {
		body.Facade = FacadeSSH
	}

	var dial dialTarget
	switch body.Source {
	case "catalog":
		c, ok := h.store.FindCatalogTarget(body.TargetID)
		if !ok {
			http.Error(w, "cible catalogue introuvable", http.StatusNotFound)
			return
		}
		if !CatalogVisible(h.userTags(pt.UserID), c.Tags) {
			http.Error(w, "cible catalogue introuvable", http.StatusNotFound)
			return
		}
		creds, _, err := GetTargetCreds(h.store, pt.UserID, pt.VaultKey, body.TargetID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		port := c.Port
		if port <= 0 {
			port = 22
		}
		sshUser := strings.TrimSpace(creds.Username)
		dial = dialTarget{
			Kind: c.Kind, Host: c.Host, Port: port,
			Username: sshUser, Password: creds.Password, PrivateKey: creds.PrivateKey,
			AgentName: c.AgentName, Container: c.Container,
		}
		if c.Kind == TargetDocker {
			dial.Username = ""
			if c.AgentName == "" || c.Container == "" {
				http.Error(w, "catalogue docker: agent_name + container requis", http.StatusBadRequest)
				return
			}
		} else {
			if dial.Username == "" {
				http.Error(w, "renseignez le login SSH dans le coffre (pas l'email Access)", http.StatusBadRequest)
				return
			}
			if creds.Password == "" && creds.PrivateKey == "" {
				http.Error(w, "ajoutez mot de passe ou clé privée dans le coffre", http.StatusBadRequest)
				return
			}
		}
	default:
		if h.cfg == nil || !h.cfg.AllowPersonalTargets {
			http.Error(w, "cibles personnelles désactivées", http.StatusForbidden)
			return
		}
		p, ok := h.store.FindPersonalTarget(pt.UserID, body.TargetID)
		if !ok {
			http.Error(w, "cible introuvable", http.StatusNotFound)
			return
		}
		creds, _, err := GetTargetCreds(h.store, pt.UserID, pt.VaultKey, body.TargetID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if p.Kind == TargetDocker {
			http.Error(w, "cibles docker personnelles interdites — utilisez le catalogue", http.StatusForbidden)
			return
		}
		user := strings.TrimSpace(creds.Username)
		if user == "" {
			user = strings.TrimSpace(p.Username)
		}
		if user == "" {
			http.Error(w, "renseignez le login SSH (coffre ou cible)", http.StatusBadRequest)
			return
		}
		if creds.Password == "" && creds.PrivateKey == "" {
			http.Error(w, "ajoutez mot de passe ou clé privée dans le coffre", http.StatusBadRequest)
			return
		}
		dial = dialTarget{
			Kind: p.Kind, Host: p.Host, Port: p.Port, Username: user,
			Password: creds.Password, PrivateKey: creds.PrivateKey,
			AgentName: p.AgentName, Container: p.Container,
		}
	}

	sess := h.sessions.Create(pt.UserID, pt.Username, body.TargetID, dial, body.Facade, h.sessionTTL(), h.sessionMode())
	host := h.cfg.PublicHost
	if host == "" {
		host = "core-host"
	}
	sshCmd := fmt.Sprintf("ssh -p %d %s@%s", h.cfg.SSHPort, sess.ID, host)
	// URL publique via reverse proxy HTTPS du Core (PublicHost → 127.0.0.1:HTTPPort).
	webURL := fmt.Sprintf("https://%s/#term=%s", host, sess.ID)
	if h.cfg.PublicHost == "" {
		webURL = fmt.Sprintf("http://%s:%d/#term=%s", host, h.cfg.HTTPPort, sess.ID)
	}
	h.emitAudit(AuditEvent{
		Actor: pt.Username, TargetID: body.TargetID, Facade: body.Facade,
		Success: true, Detail: "session_created",
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"uuid":       sess.ID,
		"expires_at": sess.ExpiresAt.Format(time.RFC3339),
		"ssh":        sshCmd,
		"web_url":    webURL,
		"ttl_sec":    int(h.sessionTTL().Seconds()),
		"mode":       h.sessionMode(),
	})
}

func (h *HTTPServer) sessionTTL() time.Duration {
	if h.cfg == nil || h.cfg.SessionTTLSec <= 0 {
		return DefaultSessionTTL
	}
	return time.Duration(h.cfg.SessionTTLSec) * time.Second
}

func (h *HTTPServer) sessionMode() string {
	if h.cfg != nil && h.cfg.SessionMode == SessionModeMulti {
		return SessionModeMulti
	}
	return SessionModeOneShot
}

func (h *HTTPServer) handleListSessions(w http.ResponseWriter, r *http.Request, pt portalToken) {
	writeJSON(w, http.StatusOK, map[string]any{"sessions": h.sessions.ListForUser(pt.UserID)})
}

func (h *HTTPServer) handleRevokeSession(w http.ResponseWriter, r *http.Request, pt portalToken) {
	id := r.PathValue("id")
	if !h.sessions.RevokeForUser(id, pt.UserID) {
		http.Error(w, "session introuvable", http.StatusNotFound)
		return
	}
	h.emitAudit(AuditEvent{Actor: pt.Username, TargetID: id, Facade: "", Success: true, Detail: "session_revoked"})
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) handleListAudit(w http.ResponseWriter, r *http.Request, pt portalToken) {
	events := h.store.ListAuditForUser(pt.Username, 100)
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (h *HTTPServer) handleListFavorites(w http.ResponseWriter, r *http.Request, pt portalToken) {
	writeJSON(w, http.StatusOK, map[string]any{"favorites": h.store.Favorites(pt.UserID)})
}

func (h *HTTPServer) handlePutFavorites(w http.ResponseWriter, r *http.Request, pt portalToken) {
	var body struct {
		Favorites []string `json:"favorites"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "json invalide", http.StatusBadRequest)
		return
	}
	if err := h.store.SetFavorites(pt.UserID, body.Favorites); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"favorites": h.store.Favorites(pt.UserID)})
}

func (h *HTTPServer) handleToggleFavorite(w http.ResponseWriter, r *http.Request, pt portalToken) {
	id := r.PathValue("id")
	on, err := h.store.ToggleFavorite(pt.UserID, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "favorite": on, "favorites": h.store.Favorites(pt.UserID)})
}

func (h *HTTPServer) handleWS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	sess, ok := h.sessions.Acquire(id)
	if !ok {
		http.Error(w, "session invalide", http.StatusGone)
		return
	}
	c, err := websocket.Accept(w, r, corews.AcceptOpts())
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	rw := &wsRW{ctx: ctx, c: c}

	if sess.Target.Kind == TargetDocker {
		if h.shell == nil {
			_ = c.Write(ctx, websocket.MessageText, []byte("docker: shell broker indisponible\n"))
			return
		}
		if sess.Target.AgentName == "" || sess.Target.Container == "" {
			_ = c.Write(ctx, websocket.MessageText, []byte("docker: agent_name + container requis\n"))
			return
		}
		remote, err := h.shell.Open(sess.Target.AgentName, sess.Target.Container)
		if err != nil {
			_ = c.Write(ctx, websocket.MessageText, []byte("docker exec: "+err.Error()+"\n"))
			h.emitAudit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeWeb, Success: false, Detail: err.Error()})
			return
		}
		h.emitAudit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeWeb, Success: true, Detail: "docker start"})
		_ = BridgeWebIO(remote, rw)
		h.emitAudit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeWeb, Success: true, Detail: "docker end"})
		return
	}

	if sess.Target.Kind != TargetSSH {
		_ = c.Write(ctx, websocket.MessageText, []byte("type de cible inconnu\n"))
		return
	}

	h.emitAudit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeWeb, Success: true, Detail: "start"})
	err = BridgeWebSSH(sess.Target, rw)
	h.emitAudit(AuditEvent{
		Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeWeb,
		Success: err == nil || err == io.EOF, Detail: "end",
	})
}

type wsRW struct {
	ctx context.Context
	c   *websocket.Conn
}

func (w *wsRW) Read(p []byte) (int, error) {
	_, data, err := w.c.Read(w.ctx)
	if err != nil {
		return 0, err
	}
	return copy(p, data), nil
}

func (w *wsRW) Write(p []byte) (int, error) {
	err := w.c.Write(w.ctx, websocket.MessageBinary, p)
	return len(p), err
}

func (w *wsRW) Close() error {
	return w.c.Close(websocket.StatusNormalClosure, "")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
