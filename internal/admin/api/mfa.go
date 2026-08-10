// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	qrcode "github.com/skip2/go-qrcode"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mailer"
	"github.com/vincamok/goproxify/internal/admin/mfa"
	"github.com/vincamok/goproxify/internal/i18n"
)

// MFAHandler gère l'ensemble des routes /api/v1/auth/mfa/...
type MFAHandler struct {
	DB        *sql.DB
	Log       *slog.Logger
	Store     *mfa.Store
	JWTSecret string
	// WebAuthn est instancié au démarrage avec rpID/rpOrigin depuis les settings.
	WebAuthn *webauthn.WebAuthn
}

// webAuthnUser implémente webauthn.User pour un utilisateur Goproxify.
type webAuthnUser struct {
	id          string
	email       string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *webAuthnUser) WebAuthnName() string                       { return u.email }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.email }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (h *MFAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/auth/mfa")
	path = strings.TrimPrefix(path, "/")

	// Routes publiques (pendant le flow login — vérification du challenge)
	if path == "challenge" && r.Method == http.MethodPost {
		h.challenge(w, r)
		return
	}
	if path == "webauthn/login/begin" && r.Method == http.MethodPost {
		h.webAuthnLoginBegin(w, r)
		return
	}
	if path == "webauthn/login/finish" && r.Method == http.MethodPost {
		h.webAuthnLoginFinish(w, r)
		return
	}

	// Routes protégées (nécessitent JWT complet — profil utilisateur)
	userID := adminauth.UserIDFromContext(r.Context())
	if userID == "" {
		writeErr(w, r, http.StatusUnauthorized, "api.err.unauth")
		return
	}

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.listMethods(w, r, userID)

	// TOTP
	case path == "totp/setup" && r.Method == http.MethodPost:
		h.totpSetup(w, r, userID)
	case path == "totp/verify" && r.Method == http.MethodPost:
		h.totpVerify(w, r, userID)

	// Email OTP
	case path == "email/setup" && r.Method == http.MethodPost:
		h.emailSetup(w, r, userID)
	case path == "email/verify" && r.Method == http.MethodPost:
		h.emailVerify(w, r, userID)

	// SMS OTP
	case path == "sms/setup" && r.Method == http.MethodPost:
		h.smsSetup(w, r, userID)
	case path == "sms/verify" && r.Method == http.MethodPost:
		h.smsVerify(w, r, userID)

	// Push (ntfy / Gotify)
	case path == "push/setup" && r.Method == http.MethodPost:
		h.pushSetup(w, r, userID)
	case path == "push/verify" && r.Method == http.MethodPost:
		h.pushVerify(w, r, userID)

	// WebAuthn
	case path == "webauthn/register/begin" && r.Method == http.MethodPost:
		h.webAuthnRegisterBegin(w, r, userID)
	case path == "webauthn/register/finish" && r.Method == http.MethodPost:
		h.webAuthnRegisterFinish(w, r, userID)

	// Backup codes
	case path == "backup-codes" && r.Method == http.MethodGet:
		h.backupCodesStatus(w, r, userID)
	case path == "backup-codes/generate" && r.Method == http.MethodPost:
		h.backupCodesGenerate(w, r, userID)

	// Trusted devices
	case path == "trusted-devices" && r.Method == http.MethodGet:
		h.listDevices(w, r, userID)
	case strings.HasPrefix(path, "trusted-devices/") && r.Method == http.MethodDelete:
		deviceID := strings.TrimPrefix(path, "trusted-devices/")
		h.deleteDevice(w, r, userID, deviceID)

	// Suppression d'une méthode
	case r.Method == http.MethodDelete && !strings.Contains(path, "/"):
		h.deleteMethod(w, r, userID, mfa.Method(path))

	default:
		http.Error(w, "route MFA inconnue", http.StatusNotFound)
	}
}

// --- Listing des méthodes ---

func (h *MFAHandler) listMethods(w http.ResponseWriter, r *http.Request, userID string) {
	methods, err := h.Store.ListMethods(r.Context(), userID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	left := h.Store.BackupCodesLeft(r.Context(), userID)
	jsonOK(w, map[string]any{
		"methods":           methods,
		"backup_codes_left": left,
	})
}

// --- TOTP ---

type totpSetupResp struct {
	Secret       string `json:"secret"`
	ProvisionURI string `json:"provision_uri"`
	QRCode       string `json:"qr_code"`
}

func (h *MFAHandler) totpSetup(w http.ResponseWriter, r *http.Request, userID string) {
	email := h.userEmail(r.Context(), userID)
	secret, err := mfa.TOTPSecret()
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.totp_gen")
		return
	}
	provisionURI := mfa.TOTPProvisionURI(secret, email, "Goproxify")
	qrCode, err := qrcode.Encode(provisionURI, qrcode.Medium, 256)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.totp_qr")
		return
	}
	if err := h.Store.UpsertMethod(r.Context(), userID, mfa.MethodTOTP, map[string]string{"secret": secret}, false); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, totpSetupResp{
		Secret:       secret,
		ProvisionURI: provisionURI,
		QRCode:       "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrCode),
	})
}

func (h *MFAHandler) totpVerify(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	var cfg struct {
		Secret string `json:"secret"`
	}
	if err := h.Store.GetMethodConfig(r.Context(), userID, mfa.MethodTOTP, &cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.totp_missing")
		return
	}
	if !mfa.TOTPVerify(cfg.Secret, req.Code) {
		http.Error(w, "code TOTP invalide", http.StatusUnauthorized)
		return
	}
	h.Store.MarkVerified(r.Context(), userID, mfa.MethodTOTP) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// --- Email OTP ---

func (h *MFAHandler) emailSetup(w http.ResponseWriter, r *http.Request, userID string) {
	email := h.userEmail(r.Context(), userID)
	if email == "" {
		http.Error(w, "email utilisateur introuvable", http.StatusInternalServerError)
		return
	}
	code, err := mfa.GenerateOTP(6)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.otp_gen")
		return
	}
	if _, err := h.Store.CreateChallenge(r.Context(), userID, mfa.MethodEmail, code, nil); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err := h.sendEmailOTP(email, code); err != nil {
		h.Log.Error("mfa: envoi email OTP", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.email_send")
		return
	}
	if err := h.Store.UpsertMethod(r.Context(), userID, mfa.MethodEmail, map[string]string{"email": email}, false); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *MFAHandler) emailVerify(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if _, ok := h.Store.VerifyChallenge(r.Context(), userID, mfa.MethodEmail, req.Code); !ok {
		writeErr(w, r, http.StatusUnauthorized, "api.err.code_invalid")
		return
	}
	h.Store.MarkVerified(r.Context(), userID, mfa.MethodEmail) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// --- SMS OTP ---

func (h *MFAHandler) smsSetup(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Phone == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.phone_required")
		return
	}
	cfg := h.smsCfg()
	if !cfg.Enabled {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.sms_unconfigured")
		return
	}
	code, err := mfa.GenerateOTP(6)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.otp_gen")
		return
	}
	if _, err := h.Store.CreateChallenge(r.Context(), userID, mfa.MethodSMS, code, nil); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	msg := "Goproxify — Code de vérification : " + code + " (valable 5 min)"
	if err := mfa.SendSMS(r.Context(), cfg, req.Phone, msg); err != nil {
		h.Log.Error("mfa: envoi SMS", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.sms_send")
		return
	}
	h.Store.UpsertMethod(r.Context(), userID, mfa.MethodSMS, map[string]string{"phone": req.Phone}, false) //nolint:errcheck
	w.WriteHeader(http.StatusAccepted)
}

func (h *MFAHandler) smsVerify(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if _, ok := h.Store.VerifyChallenge(r.Context(), userID, mfa.MethodSMS, req.Code); !ok {
		writeErr(w, r, http.StatusUnauthorized, "api.err.code_invalid")
		return
	}
	h.Store.MarkVerified(r.Context(), userID, mfa.MethodSMS) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// --- Push ---

func (h *MFAHandler) pushSetup(w http.ResponseWriter, r *http.Request, userID string) {
	var cfg mfa.PushConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if cfg.Provider == "" || (cfg.Provider == "ntfy" && cfg.Topic == "") {
		http.Error(w, "provider et topic requis", http.StatusBadRequest)
		return
	}
	// Test d'envoi
	if err := mfa.SendPushMFA(r.Context(), cfg, "123456", "test", "setup"); err != nil {
		h.Log.Error("mfa: test push", "err", err)
		http.Error(w, "push injoignable : "+err.Error(), http.StatusBadGateway)
		return
	}
	method := mfa.MethodPushNtfy
	if cfg.Provider == "gotify" {
		method = mfa.MethodPushGotify
	}
	h.Store.UpsertMethod(r.Context(), userID, method, cfg, true) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

func (h *MFAHandler) pushVerify(w http.ResponseWriter, r *http.Request, userID string) {
	// La vérification push se fait via le même endpoint challenge (le code est envoyé par push puis saisi)
	// Ici on envoie le code et l'utilisateur le saisit dans l'UI
	var req struct {
		Method mfa.Method `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Method = mfa.MethodPushNtfy
	}
	var cfg mfa.PushConfig
	if err := h.Store.GetMethodConfig(r.Context(), userID, req.Method, &cfg); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.push_unconfigured")
		return
	}
	code, err := mfa.GenerateOTP(6)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.otp_gen")
		return
	}
	h.Store.CreateChallenge(r.Context(), userID, req.Method, code, nil) //nolint:errcheck
	if err := mfa.SendPushMFA(r.Context(), cfg, code, r.UserAgent(), r.RemoteAddr); err != nil {
		http.Error(w, "push injoignable", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// --- WebAuthn ---

func (h *MFAHandler) webAuthnRegisterBegin(w http.ResponseWriter, r *http.Request, userID string) {
	if h.WebAuthn == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.webauthn_unconfigured")
		return
	}
	email := h.userEmail(r.Context(), userID)
	user := &webAuthnUser{id: userID, email: email}
	creation, session, err := h.WebAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "WebAuthn begin: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Store.CreateWebAuthnChallenge(r.Context(), userID, session) //nolint:errcheck
	jsonOK(w, creation)
}

func (h *MFAHandler) webAuthnRegisterFinish(w http.ResponseWriter, r *http.Request, userID string) {
	if h.WebAuthn == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.webauthn_unconfigured")
		return
	}
	challengeID := r.URL.Query().Get("challenge")
	var session webauthn.SessionData
	if err := h.Store.GetWebAuthnChallenge(r.Context(), challengeID, &session); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.webauthn_session")
		return
	}
	email := h.userEmail(r.Context(), userID)
	user := &webAuthnUser{id: userID, email: email}
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.webauthn_response")
		return
	}
	credential, err := h.WebAuthn.CreateCredential(user, session, parsedResponse)
	if err != nil {
		http.Error(w, "WebAuthn finish: "+err.Error(), http.StatusUnauthorized)
		return
	}
	h.Store.UpsertMethod(r.Context(), userID, mfa.MethodWebAuthn, credential, true) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// mfaPendingUserID exige un token MFA intermédiaire (body mfa_token ou Bearer).
func (h *MFAHandler) mfaPendingUserID(r *http.Request, bodyToken string) (string, error) {
	tok := strings.TrimSpace(bodyToken)
	if tok == "" {
		auth := r.Header.Get("Authorization")
		if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
			tok = strings.TrimSpace(auth[7:])
		}
	}
	if tok == "" {
		return "", errMFAPendingRequired
	}
	return adminauth.VerifyMFAPendingToken(tok, h.JWTSecret)
}

var errMFAPendingRequired = errors.New("mfa_token requis")

func (h *MFAHandler) webAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MFAToken string `json:"mfa_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	userID, err := h.mfaPendingUserID(r, body.MFAToken)
	if err != nil {
		http.Error(w, "token MFA invalide ou expiré", http.StatusUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.webauthn_unconfigured")
		return
	}
	// Refuser tout uid arbitraire en query (premier facteur déjà prouvé via mfa_pending).
	if q := r.URL.Query().Get("uid"); q != "" && q != userID {
		http.Error(w, "uid invalide", http.StatusUnauthorized)
		return
	}
	var cred webauthn.Credential
	if err := h.Store.GetMethodConfig(r.Context(), userID, mfa.MethodWebAuthn, &cred); err != nil {
		http.Error(w, "WebAuthn non configuré pour cet utilisateur", http.StatusBadRequest)
		return
	}
	email := h.userEmail(r.Context(), userID)
	user := &webAuthnUser{id: userID, email: email, credentials: []webauthn.Credential{cred}}
	assertion, session, err := h.WebAuthn.BeginLogin(user)
	if err != nil {
		http.Error(w, "WebAuthn begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	chalID, err := h.Store.CreateWebAuthnChallenge(r.Context(), userID, session)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, map[string]any{"options": assertion, "user_id": userID, "challenge_id": chalID})
}

func (h *MFAHandler) webAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MFAToken    string          `json:"mfa_token"`
		UserID      string          `json:"user_id"`
		ChallengeID string          `json:"challenge_id"`
		Response    json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	userID, err := h.mfaPendingUserID(r, body.MFAToken)
	if err != nil {
		http.Error(w, "token MFA invalide ou expiré", http.StatusUnauthorized)
		return
	}
	if body.UserID != "" && body.UserID != userID {
		http.Error(w, "uid invalide", http.StatusUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.webauthn_unconfigured")
		return
	}
	var session webauthn.SessionData
	if err := h.Store.GetWebAuthnChallenge(r.Context(), body.ChallengeID, &session); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.webauthn_session")
		return
	}
	var cred webauthn.Credential
	if err := h.Store.GetMethodConfig(r.Context(), userID, mfa.MethodWebAuthn, &cred); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.webauthn_unconfigured")
		return
	}
	email := h.userEmail(r.Context(), userID)
	user := &webAuthnUser{id: userID, email: email, credentials: []webauthn.Credential{cred}}
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(string(body.Response)))
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.webauthn_response")
		return
	}
	if _, err := h.WebAuthn.ValidateLogin(user, session, parsedResponse); err != nil {
		http.Error(w, "WebAuthn login invalide", http.StatusUnauthorized)
		return
	}
	token, err := adminauth.SignJWT(userID, h.JWTSecret, 24*time.Hour)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, map[string]string{"token": token})
}

// --- Challenge MFA pendant le login ---

func (h *MFAHandler) challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string     `json:"mfa_token"`
		Method   mfa.Method `json:"method"`
		Code     string     `json:"code"`
		Trust    bool       `json:"trust_device"`
		DevName  string     `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	// Valider le mfa_pending_token
	userID, err := adminauth.VerifyMFAPendingToken(req.MFAToken, h.JWTSecret)
	if err != nil {
		http.Error(w, "token MFA invalide ou expiré", http.StatusUnauthorized)
		return
	}

	ok := false
	switch req.Method {
	case mfa.MethodTOTP:
		var cfg struct {
			Secret string `json:"secret"`
		}
		if err := h.Store.GetMethodConfig(r.Context(), userID, mfa.MethodTOTP, &cfg); err == nil {
			ok = mfa.TOTPVerify(cfg.Secret, req.Code)
		}
	case mfa.MethodEmail, mfa.MethodSMS, mfa.MethodPushNtfy, mfa.MethodPushGotify:
		_, ok = h.Store.VerifyChallenge(r.Context(), userID, req.Method, req.Code)
	case mfa.MethodBackup:
		ok = h.Store.VerifyBackupCode(r.Context(), userID, req.Code)
	default:
		http.Error(w, "méthode MFA inconnue", http.StatusBadRequest)
		return
	}

	if !ok {
		http.Error(w, "code MFA invalide", http.StatusUnauthorized)
		return
	}

	token, err := adminauth.SignJWT(userID, h.JWTSecret, 24*time.Hour)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	resp := map[string]any{"token": token}

	if req.Trust {
		plain, hash, err := mfa.GenerateDeviceToken()
		if err == nil {
			name := req.DevName
			if name == "" {
				name = r.UserAgent()
				if len(name) > 80 {
					name = name[:80]
				}
			}
			if _, err := h.Store.CreateTrustedDevice(r.Context(), userID, hash, name); err == nil {
				resp["device_token"] = plain
			}
		}
	}

	jsonOK(w, resp)
}

// --- Backup codes ---

func (h *MFAHandler) backupCodesStatus(w http.ResponseWriter, r *http.Request, userID string) {
	left := h.Store.BackupCodesLeft(r.Context(), userID)
	jsonOK(w, map[string]int{"codes_left": left})
}

func (h *MFAHandler) backupCodesGenerate(w http.ResponseWriter, r *http.Request, userID string) {
	plain, hashes, err := mfa.GenerateBackupCodes()
	if err != nil {
		http.Error(w, "erreur génération", http.StatusInternalServerError)
		return
	}
	if err := h.Store.SaveBackupCodes(r.Context(), userID, hashes); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	h.Store.UpsertMethod(r.Context(), userID, mfa.MethodBackup, map[string]int{"count": mfa.BackupCodeCount}, true) //nolint:errcheck
	jsonOK(w, map[string]any{"codes": plain, "count": len(plain)})
}

// --- Trusted devices ---

func (h *MFAHandler) listDevices(w http.ResponseWriter, r *http.Request, userID string) {
	devices, err := h.Store.ListTrustedDevices(r.Context(), userID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, devices)
}

func (h *MFAHandler) deleteDevice(w http.ResponseWriter, r *http.Request, userID, deviceID string) {
	h.Store.DeleteTrustedDevice(r.Context(), userID, deviceID) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// --- Suppression méthode ---

func (h *MFAHandler) deleteMethod(w http.ResponseWriter, r *http.Request, userID string, method mfa.Method) {
	h.Store.DeleteMethod(r.Context(), userID, method) //nolint:errcheck
	if method == mfa.MethodBackup {
		h.Store.SaveBackupCodes(r.Context(), userID, nil) //nolint:errcheck
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Helpers ---

func (h *MFAHandler) userEmail(ctx context.Context, userID string) string {
	var email string
	h.DB.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, userID).Scan(&email) //nolint:errcheck
	return email
}

func (h *MFAHandler) smsCfg() mfa.SMSConfig {
	raw := admindb.GetSetting(h.DB, "mfa.sms", "{}")
	var cfg mfa.SMSConfig
	json.Unmarshal([]byte(raw), &cfg) //nolint:errcheck
	return cfg
}

func (h *MFAHandler) sendEmailOTP(to, code string) error {
	loc := i18n.Default
	subj := i18n.T(loc, "email.mfa.subject")
	msg := i18n.T(loc, "email.mfa.body", code)
	err := mailer.Send(h.DB, to, "[Goproxify] "+subj, msg)
	if err == mailer.ErrNotConfigured {
		return nil // pas de SMTP — ne bloque pas le challenge MFA en dev
	}
	return err
}
