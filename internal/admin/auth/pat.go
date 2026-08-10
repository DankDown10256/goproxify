// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	PATPrefix          = "gpx_pat_"
	AuthKindJWT        = "jwt"
	AuthKindPAT        = "pat"
	ctxAuthKind        contextKey = "authKind"
	ctxPATID           contextKey = "patID"
	ctxPATScopes       contextKey = "patScopes"
)

// GeneratePAT produit un token utilisateur au format gpx_pat_<32-hex>.
func GeneratePAT() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: génération PAT : %v", err))
	}
	return PATPrefix + hex.EncodeToString(b)
}

// HashPAT retourne le hash SHA-256 hexadécimal du secret en clair.
func HashPAT(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// PATPreview retourne un aperçu sûr pour l'UI (préfixe + 4 derniers caractères).
func PATPreview(plain string) string {
	if len(plain) < 12 {
		return PATPrefix + "…"
	}
	return plain[:len(PATPrefix)+4] + "…" + plain[len(plain)-4:]
}

// IsPATToken indique si la chaîne ressemble à un PAT utilisateur.
func IsPATToken(token string) bool {
	return strings.HasPrefix(token, PATPrefix)
}

// LookupPAT résout un PAT valide (non révoqué, non expiré) et retourne userID, tokenID, scopes.
func LookupPAT(ctx context.Context, db *sql.DB, plain string) (userID, tokenID string, scopes []string, err error) {
	if !IsPATToken(plain) {
		return "", "", nil, errors.New("pas un PAT")
	}
	hash := HashPAT(plain)
	var expires sql.NullTime
	var revoked int
	err = db.QueryRowContext(ctx, `
		SELECT id, user_id, revoked, expires_at
		FROM user_api_tokens
		WHERE token_hash = ?`, hash).Scan(&tokenID, &userID, &revoked, &expires)
	if err != nil {
		return "", "", nil, fmt.Errorf("PAT inconnu")
	}
	if revoked != 0 {
		return "", "", nil, errors.New("PAT révoqué")
	}
	if expires.Valid && !expires.Time.After(time.Now().UTC()) {
		return "", "", nil, errors.New("PAT expiré")
	}
	rows, err := db.QueryContext(ctx,
		`SELECT scope FROM user_api_token_scopes WHERE token_id = ? ORDER BY scope`, tokenID)
	if err != nil {
		return "", "", nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			scopes = append(scopes, s)
		}
	}
	if scopes == nil {
		scopes = []string{}
	}
	// last_used_at best-effort
	_, _ = db.ExecContext(ctx,
		`UPDATE user_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, tokenID)
	return userID, tokenID, scopes, nil
}

// RequireAuth accepte un JWT de session UI ou un PAT utilisateur.
func RequireAuth(secret string, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				http.Error(w, "Authorization manquant", http.StatusUnauthorized)
				return
			}
			ctx, err := authenticateBearer(r.Context(), secret, db, tokenStr)
			if err != nil {
				http.Error(w, "Token invalide", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePAT n'accepte que les tokens utilisateur (gpx_pat_*) — utilisé pour le MCP.
func RequirePAT(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				http.Error(w, "Authorization manquant", http.StatusUnauthorized)
				return
			}
			if !IsPATToken(tokenStr) {
				http.Error(w, "MCP : un token API utilisateur (gpx_pat_*) est requis", http.StatusUnauthorized)
				return
			}
			userID, patID, scopes, err := LookupPAT(r.Context(), db, tokenStr)
			if err != nil {
				http.Error(w, "Token invalide", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUserID, userID)
			ctx = context.WithValue(ctx, ctxAuthKind, AuthKindPAT)
			ctx = context.WithValue(ctx, ctxPATID, patID)
			ctx = context.WithValue(ctx, ctxPATScopes, scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authenticateBearer(ctx context.Context, secret string, db *sql.DB, tokenStr string) (context.Context, error) {
	if IsPATToken(tokenStr) {
		userID, patID, scopes, err := LookupPAT(ctx, db, tokenStr)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, ctxUserID, userID)
		ctx = context.WithValue(ctx, ctxAuthKind, AuthKindPAT)
		ctx = context.WithValue(ctx, ctxPATID, patID)
		ctx = context.WithValue(ctx, ctxPATScopes, scopes)
		return ctx, nil
	}
	userID, err := VerifyJWT(tokenStr, secret)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxAuthKind, AuthKindJWT)
	return ctx, nil
}

// AuthKindFromContext retourne "jwt", "pat" ou "".
func AuthKindFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxAuthKind).(string)
	return v
}

// IsPATAuth indique si la requête est authentifiée via PAT.
func IsPATAuth(ctx context.Context) bool {
	return AuthKindFromContext(ctx) == AuthKindPAT
}

// PATIDFromContext retourne l'ID du PAT courant (vide si JWT).
func PATIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxPATID).(string)
	return v
}

// PATScopesFromContext retourne les scopes déclarés sur le PAT (nil si JWT).
func PATScopesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(ctxPATScopes).([]string)
	return v
}

// ActorFromContext formate l'acteur d'audit (indique un PAT le cas échéant).
func ActorFromContext(ctx context.Context) string {
	uid := UserIDFromContext(ctx)
	if IsPATAuth(ctx) {
		return uid + " via pat:" + PATIDFromContext(ctx)
	}
	return uid
}
