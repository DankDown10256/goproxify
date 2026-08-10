// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package auth fournit les primitives d'authentification pour l'Administration.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// GenerateToken produit un token d'appairage au format gpx_<role>_<32-hex>.
// Le rôle "agent" émet un JOIN_TOKEN `gpx_join_*` (usage unique au premier handshake WS).
func GenerateToken(role, node string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: génération token : %v", err))
	}
	_ = node // utilisé pour l'enregistrement en DB, pas dans le token lui-même
	prefix := role
	if role == "agent" {
		prefix = "join"
	}
	return fmt.Sprintf("gpx_%s_%s", prefix, hex.EncodeToString(b))
}

// HashPassword retourne le hash bcrypt du mot de passe en clair.
func HashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash : %w", err)
	}
	return string(h), nil
}

// CheckPassword valide un mot de passe en clair contre le hash bcrypt.
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// SecureEqual compare deux chaînes en temps constant (si longueurs égales).
// Utilisé pour les secrets d'appairage et équivalents.
func SecureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// jwtClaims est la structure des claims JWT de session UI.
// Pending est lu pour rejeter les tokens MFA intermédiaires (mfa_pending).
type jwtClaims struct {
	UserID  string `json:"uid"`
	Pending bool   `json:"mfa_pending,omitempty"`
	jwt.RegisteredClaims
}

// SignJWT signe un JWT pour la session UI avec l'identifiant utilisateur.
func SignJWT(userID, secret string, ttl time.Duration) (string, error) {
	claims := jwtClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("jwt sign : %w", err)
	}
	return signed, nil
}

// VerifyJWT valide un JWT de session et retourne l'identifiant utilisateur.
// Les tokens MFA intermédiaires (claim mfa_pending=true) sont rejetés.
func VerifyJWT(tokenStr, secret string) (string, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature inattendue : %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("jwt verify : %w", err)
	}
	claims, ok := parsed.Claims.(*jwtClaims)
	if !ok || !parsed.Valid {
		return "", errors.New("jwt: claims invalides")
	}
	if claims.Pending {
		return "", errors.New("jwt: token MFA pending non autorisé")
	}
	if claims.UserID == "" {
		return "", errors.New("jwt: uid manquant")
	}
	return claims.UserID, nil
}

// mfaPendingClaims est la structure des claims du token MFA intermédiaire.
type mfaPendingClaims struct {
	UserID  string `json:"uid"`
	Pending bool   `json:"mfa_pending"`
	jwt.RegisteredClaims
}

// SignMFAPendingToken signe un JWT court (5 min) indiquant que le mot de passe est validé
// mais que la 2FA reste à vérifier. Ce token ne donne aucun accès aux API protégées.
func SignMFAPendingToken(userID, secret string) (string, error) {
	claims := mfaPendingClaims{
		UserID:  userID,
		Pending: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("jwt mfa pending sign : %w", err)
	}
	return signed, nil
}

// VerifyMFAPendingToken valide un token MFA intermédiaire et retourne l'userID.
func VerifyMFAPendingToken(tokenStr, secret string) (string, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &mfaPendingClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature inattendue")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("jwt mfa pending verify : %w", err)
	}
	claims, ok := parsed.Claims.(*mfaPendingClaims)
	if !ok || !parsed.Valid || !claims.Pending {
		return "", errors.New("jwt: token MFA invalide")
	}
	return claims.UserID, nil
}

// contextKey est le type des clés de contexte HTTP.
type contextKey string

const ctxUserID contextKey = "userID"

// RequireJWT est un middleware HTTP qui valide le JWT dans le header Authorization.
// Pour l'API Admin préférer RequireAuth (JWT ou PAT).
func RequireJWT(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				http.Error(w, "Authorization manquant", http.StatusUnauthorized)
				return
			}
			userID, err := VerifyJWT(tokenStr, secret)
			if err != nil {
				http.Error(w, "Token invalide", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUserID, userID)
			ctx = context.WithValue(ctx, ctxAuthKind, AuthKindJWT)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext extrait l'identifiant utilisateur du contexte.
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

// RequireBearerToken est un middleware HTTP qui valide un token d'appairage Core/Agent depuis la DB.
func RequireBearerToken(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				http.Error(w, "Token d'appairage manquant", http.StatusUnauthorized)
				return
			}

			var revoked int
			hash := HashNodeToken(tokenStr)
			err := db.QueryRowContext(r.Context(),
				`SELECT revoked FROM tokens WHERE (token_hash = ? OR token = ?) AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
				hash, tokenStr,
			).Scan(&revoked)
			if err != nil || revoked != 0 {
				http.Error(w, "Token invalide ou révoqué", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerToken extrait le token du header Authorization: Bearer <token>.
// Le paramètre query `_auth` n'est accepté que pour SSE/MCP (EventSource ne peut
// pas envoyer de header) — pas pour les routes API génériques (L2).
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	if t := r.URL.Query().Get("_auth"); t != "" && allowAuthQueryParam(r) {
		return t
	}
	return ""
}

func allowAuthQueryParam(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/mcp") {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream")
}
