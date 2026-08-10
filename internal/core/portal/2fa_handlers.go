// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

func (h *HTTPServer) handle2FAStatus(w http.ResponseWriter, r *http.Request, pt portalToken) {
	u, ok := h.store.FindUserByID(pt.UserID)
	if !ok {
		http.Error(w, "user introuvable", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totp_enabled":      u.TOTPEnabled,
		"email_otp_enabled": u.EmailOTPEnabled,
		"require_2fa":       h.cfg != nil && h.cfg.Require2FA,
		"methods":           User2FAMethods(u),
	})
}

func (h *HTTPServer) handle2FATOTPSetup(w http.ResponseWriter, r *http.Request, pt portalToken) {
	secret, err := TOTPSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.store.UpdateUser2FA(pt.UserID, func(u *UserRecord) {
		u.TOTPPendingSecret = secret
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uri := TOTPProvisionURI(secret, pt.Username, "GoProxify Access")
	qrPNG, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "génération QR TOTP: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_uri": uri,
		"qr_code":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG),
	})
}

func (h *HTTPServer) handle2FATOTPVerifyEnable(w http.ResponseWriter, r *http.Request, pt portalToken) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		http.Error(w, "code requis", http.StatusBadRequest)
		return
	}
	u, ok := h.store.FindUserByID(pt.UserID)
	if !ok || u.TOTPPendingSecret == "" {
		http.Error(w, "setup TOTP manquant — appelez /api/2fa/totp/setup", http.StatusBadRequest)
		return
	}
	if !TOTPVerify(u.TOTPPendingSecret, body.Code) {
		http.Error(w, "code TOTP invalide", http.StatusUnauthorized)
		return
	}
	if err := h.store.UpdateUser2FA(pt.UserID, func(rec *UserRecord) {
		rec.TOTPSecret = rec.TOTPPendingSecret
		rec.TOTPPendingSecret = ""
		rec.TOTPEnabled = true
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"totp_enabled": true})
}

func (h *HTTPServer) handle2FATOTPDisable(w http.ResponseWriter, r *http.Request, pt portalToken) {
	if h.cfg != nil && h.cfg.Require2FA {
		u, _ := h.store.FindUserByID(pt.UserID)
		if u.TOTPEnabled && !u.EmailOTPEnabled {
			http.Error(w, "impossible de désactiver la dernière méthode 2FA (require_2fa)", http.StatusBadRequest)
			return
		}
	}
	_ = h.store.UpdateUser2FA(pt.UserID, func(u *UserRecord) {
		u.TOTPEnabled = false
		u.TOTPSecret = ""
		u.TOTPPendingSecret = ""
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) handle2FAEmailEnable(w http.ResponseWriter, r *http.Request, pt portalToken) {
	_ = h.store.UpdateUser2FA(pt.UserID, func(u *UserRecord) {
		u.EmailOTPEnabled = true
	})
	writeJSON(w, http.StatusOK, map[string]any{"email_otp_enabled": true})
}

func (h *HTTPServer) handle2FAEmailDisable(w http.ResponseWriter, r *http.Request, pt portalToken) {
	if h.cfg != nil && h.cfg.Require2FA {
		u, _ := h.store.FindUserByID(pt.UserID)
		if u.EmailOTPEnabled && !u.TOTPEnabled {
			http.Error(w, "impossible de désactiver la dernière méthode 2FA (require_2fa)", http.StatusBadRequest)
			return
		}
	}
	_ = h.store.UpdateUser2FA(pt.UserID, func(u *UserRecord) {
		u.EmailOTPEnabled = false
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) handle2FAEmailSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ChallengeID == "" {
		http.Error(w, "challenge_id requis", http.StatusBadRequest)
		return
	}
	ch, ok := h.challenges.Get(body.ChallengeID)
	if !ok {
		http.Error(w, "challenge invalide ou expiré", http.StatusGone)
		return
	}
	u, ok := h.store.FindUserByID(ch.UserID)
	if !ok || !u.EmailOTPEnabled {
		http.Error(w, "OTP email non activé", http.StatusBadRequest)
		return
	}
	code, err := NewEmailOTPCode()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ch.EmailOTPHash = HashEmailOTP(code)
	ch.EmailOTPExpires = time.Now().UTC().Add(EmailOTPTTL)
	h.challenges.Update(ch)
	if h.sendEmailOTP == nil {
		http.Error(w, "envoi OTP indisponible (Admin non relié)", http.StatusBadGateway)
		return
	}
	if err := h.sendEmailOTP(u.Username, code); err != nil {
		http.Error(w, "envoi email: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPServer) handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string `json:"challenge_id"`
		Method      string `json:"method"` // totp | email
		Code        string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	body.Method = strings.TrimSpace(strings.ToLower(body.Method))
	body.Code = strings.TrimSpace(body.Code)
	if body.ChallengeID == "" || body.Code == "" || (body.Method != "totp" && body.Method != "email") {
		http.Error(w, "challenge_id + method + code requis", http.StatusBadRequest)
		return
	}
	ch, ok := h.challenges.Get(body.ChallengeID)
	if !ok {
		http.Error(w, "challenge invalide ou expiré", http.StatusGone)
		return
	}
	u, ok := h.store.FindUserByID(ch.UserID)
	if !ok {
		http.Error(w, "utilisateur introuvable", http.StatusNotFound)
		return
	}
	switch body.Method {
	case "totp":
		if !u.TOTPEnabled || !TOTPVerify(u.TOTPSecret, body.Code) {
			http.Error(w, "code TOTP invalide", http.StatusUnauthorized)
			return
		}
	case "email":
		if !u.EmailOTPEnabled || ch.EmailOTPHash == "" || time.Now().After(ch.EmailOTPExpires) {
			http.Error(w, "OTP email expiré ou manquant — renvoyez un code", http.StatusUnauthorized)
			return
		}
		if HashEmailOTP(body.Code) != ch.EmailOTPHash {
			http.Error(w, "code OTP invalide", http.StatusUnauthorized)
			return
		}
	}
	vk, err := hex.DecodeString(ch.VaultKeyHex)
	if err != nil || len(vk) != 32 {
		http.Error(w, "challenge corrompu", http.StatusInternalServerError)
		return
	}
	var key [32]byte
	copy(key[:], vk)
	h.challenges.Delete(ch.ID)
	tok, err := h.issueToken(u.ID, u.Username, key)
	if err != nil {
		http.Error(w, "persistance session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "username": u.Username})
}
