// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package rbac implémente le contrôle d'accès basé sur les rôles pour l'Admin.
//
// Hiérarchie des rôles plateforme :
//
//	superadmin : accès total, protégé (non supprimable), premier compte créé
//	admin      : CRUD plateforme ; proxies = tous si aucun grant, sinon match des grants
//	user       : proxies uniquement via grants effectifs (user_scopes ∪ team_scopes)
//
// Grant = (scope_type, scope_value, access_mode read|write) :
//
//	core   : glob sur node_name du Core → accès à toutes ses ressources
//	domain : glob sur Route.Host
//	proxy  : identifiant exact d'un proxy
//	server : glob sur Backend.URL
package rbac

import (
	"context"
	"database/sql"
	"net/http"
	"path"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/core/router"
)

// Access modes pour un grant.
const (
	AccessRead  = "read"
	AccessWrite = "write"
)

// Scope représente un périmètre d'accès (tokens Core / match route).
type Scope struct {
	Type  string // "domain" | "server" | "proxy" | "core"
	Value string
}

// Grant est un scope avec mode lecture/écriture (user_scopes / team_scopes).
type Grant struct {
	Type  string
	Value string
	Mode  string // "read" | "write"
}

// Scope projette le grant sans le mode (compat MatchRoute / tokens).
func (g Grant) Scope() Scope { return Scope{Type: g.Type, Value: g.Value} }

// match retourne true si la route correspond à ce scope.
func (s Scope) match(route *router.Route) bool {
	switch s.Type {
	case "proxy":
		return s.Value == route.ID
	case "domain":
		if hostMatchesDomainScope(s.Value, route.Host) {
			return true
		}
		for _, a := range route.Aliases {
			if hostMatchesDomainScope(s.Value, a) {
				return true
			}
		}
		return false
	case "server":
		for _, b := range route.Backends {
			if ok, _ := path.Match(s.Value, b.URL); ok {
				return true
			}
		}
	case "core":
		// Un scope core donne accès à toutes les routes (push global vers tous les Cores).
		// La restriction de visibilité Core se fait au niveau de la nav, pas des routes.
		return true
	}
	return false
}

// hostMatchesDomainScope aligne HostCoveredByPattern (wildcard DNS 1 label).
// path.Match n'est utilisé que pour les motifs non-wildcard DNS (ex. "api.*.fr").
func hostMatchesDomainScope(pattern, host string) bool {
	if router.HostCoveredByPattern(host, pattern) {
		return true
	}
	p := strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(p, "*.") {
		return false
	}
	ok, _ := path.Match(p, strings.ToLower(host))
	return ok
}

// MatchRoute retourne true si au moins un scope correspond à la route.
func MatchRoute(scopes []Scope, route *router.Route) bool {
	for _, s := range scopes {
		if s.match(route) {
			return true
		}
	}
	return false
}

// RouteAllowedByToken indique si une route est dans le périmètre d'un token Core.
// Même sémantique que FilterRoutesByScopes : admin sans scope → tout ; sinon match.
func RouteAllowedByToken(role string, scopes []Scope, route *router.Route) bool {
	if route == nil {
		return false
	}
	if IsSuperAdminRole(role) || (IsAdminRole(role) && len(scopes) == 0) {
		return true
	}
	if len(scopes) == 0 {
		return false
	}
	return MatchRoute(scopes, route)
}

// FilterRoutesByScopes retourne les routes accessibles selon le rôle et les scopes.
func FilterRoutesByScopes(role string, scopes []Scope, routes []router.Route) []router.Route {
	filtered := make([]router.Route, 0, len(routes))
	for i := range routes {
		if RouteAllowedByToken(role, scopes, &routes[i]) {
			filtered = append(filtered, routes[i])
		}
	}
	return filtered
}

// ResolveCoreToken résout un token Core par UUID ou node_name.
// Préfère l'ID exact, puis un token avec endpoint, puis le plus récent.
// Sans périmètre (scopes vides) + rôle admin → accès à tous les domaines.
func ResolveCoreToken(ctx context.Context, db *sql.DB, ref string) (tokenID, rbacRole string) {
	acc := ResolveCoreAccess(ctx, db, ref)
	return acc.TokenID, acc.Role
}

// CoreAccess est le rôle + scopes effectifs pour un Core (push / UI).
type CoreAccess struct {
	TokenID string
	Role    string
	Scopes  []Scope
}

// ResolveCoreAccess résout le meilleur token Core pour une référence (uuid ou node_name).
func ResolveCoreAccess(ctx context.Context, db *sql.DB, ref string) CoreAccess {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return CoreAccess{}
	}
	var id, role string
	err := db.QueryRowContext(ctx, `
		SELECT t.id, COALESCE(t.rbac_role,'admin')
		FROM tokens t
		WHERE t.role='core' AND t.revoked=0
		  AND (t.expires_at IS NULL OR t.expires_at > CURRENT_TIMESTAMP)
		  AND (t.id=? OR t.node_name=?)
		ORDER BY
		  CASE WHEN t.id=? THEN 0 ELSE 1 END,
		  CASE WHEN COALESCE(t.node_endpoint,'') != '' THEN 0 ELSE 1 END,
		  t.created_at DESC
		LIMIT 1`, ref, ref, ref).Scan(&id, &role)
	if err != nil || id == "" {
		return CoreAccess{}
	}
	scopes, _ := TokenScopes(ctx, db, id)
	return CoreAccess{TokenID: id, Role: role, Scopes: scopes}
}

// LoadCoreAccess charge le rôle et les scopes du token indiqué.
// Scopes vides + admin = tous les domaines (pas de bascule vers un autre token).
func LoadCoreAccess(ctx context.Context, db *sql.DB, tokenID, nodeName string) CoreAccess {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		if nodeName = strings.TrimSpace(nodeName); nodeName != "" {
			return ResolveCoreAccess(ctx, db, nodeName)
		}
		return CoreAccess{}
	}
	role := "admin"
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(rbac_role,'admin') FROM tokens WHERE id=?`, tokenID).Scan(&role)
	scopes, _ := TokenScopes(ctx, db, tokenID)
	return CoreAccess{TokenID: tokenID, Role: role, Scopes: scopes}
}

// ShouldReceiveCert indique si un Core doit recevoir le certificat nommé certName
// (ex: "*.dankdown.fr" ou "api.example.fr").
// Même sémantique que les routes : admin sans périmètre → tout ; sinon match domaine/core.
func ShouldReceiveCert(role string, scopes []Scope, certName string) bool {
	if IsSuperAdminRole(role) || (IsAdminRole(role) && len(scopes) == 0) {
		return true
	}
	if len(scopes) == 0 {
		return false
	}
	return MatchCertName(scopes, certName)
}

// MatchCertName retourne true si au moins un scope couvre le nom de certificat.
func MatchCertName(scopes []Scope, certName string) bool {
	certName = strings.TrimSpace(certName)
	if certName == "" {
		return false
	}
	candidates := []string{certName}
	if strings.HasPrefix(certName, "*.") {
		candidates = append(candidates, certName[2:])
	} else {
		candidates = append(candidates, "*."+certName)
	}
	for _, s := range scopes {
		switch s.Type {
		case "core":
			// Comme pour les routes : un scope core donne accès global aux ressources poussées.
			return true
		case "domain":
			for _, c := range candidates {
				if ok, _ := path.Match(s.Value, c); ok {
					return true
				}
			}
			// Scope "*.dankdown.fr" vs cert name exact stocké sans wildcard
			if ok, _ := path.Match(s.Value, certName); ok {
				return true
			}
		}
	}
	return false
}

// --- Fonctions de rôle ---

// IsSuperAdminRole retourne true pour le rôle superadmin.
func IsSuperAdminRole(role string) bool { return role == "superadmin" }

// IsAdminRole retourne true pour admin et superadmin.
func IsAdminRole(role string) bool { return role == "admin" || role == "superadmin" }

// UserRole retourne le rôle global de l'utilisateur.
func UserRole(ctx context.Context, db *sql.DB, userID string) string {
	var role string
	_ = db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, userID).Scan(&role)
	return role
}

// IsSuperAdmin retourne true si l'utilisateur est superadmin.
func IsSuperAdmin(ctx context.Context, db *sql.DB, userID string) bool {
	return IsSuperAdminRole(UserRole(ctx, db, userID))
}

// IsAdmin retourne true si l'utilisateur est admin ou superadmin.
func IsAdmin(ctx context.Context, db *sql.DB, userID string) bool {
	return IsAdminRole(UserRole(ctx, db, userID))
}

// --- Scopes / grants utilisateur ---

// IsGlobalAdmin retourne true si l'utilisateur est admin/superadmin sans aucun grant.
func IsGlobalAdmin(ctx context.Context, db *sql.DB, userID string) bool {
	if !IsAdmin(ctx, db, userID) {
		return false
	}
	grants, _ := UserEffectiveGrants(ctx, db, userID)
	return len(grants) == 0
}

// UserEffectiveGrants union user_scopes + team_scopes ; même (type,value) → max(mode) (write > read).
func UserEffectiveGrants(ctx context.Context, db *sql.DB, userID string) ([]Grant, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT scope_type, scope_value, access_mode FROM (
			SELECT scope_type, scope_value, access_mode FROM user_scopes WHERE user_id = ?
			UNION ALL
			SELECT ts.scope_type, ts.scope_value, ts.access_mode
			FROM team_scopes ts
			JOIN team_members tm ON tm.team_id = ts.team_id
			WHERE tm.user_id = ?
		)`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	merged := map[string]Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.Type, &g.Value, &g.Mode); err != nil {
			continue
		}
		if g.Mode != AccessWrite {
			g.Mode = AccessRead
		}
		key := g.Type + "\x00" + g.Value
		if prev, ok := merged[key]; ok {
			if prev.Mode == AccessWrite || g.Mode == AccessWrite {
				g.Mode = AccessWrite
			}
		}
		merged[key] = g
	}
	out := make([]Grant, 0, len(merged))
	for _, g := range merged {
		out = append(out, g)
	}
	return out, rows.Err()
}

// GrantsAsScopes extrait les Scope (sans mode) pour MatchRoute.
func GrantsAsScopes(grants []Grant) []Scope {
	out := make([]Scope, len(grants))
	for i, g := range grants {
		out[i] = g.Scope()
	}
	return out
}

// WriteGrants filtre les grants en écriture.
func WriteGrants(grants []Grant) []Grant {
	var out []Grant
	for _, g := range grants {
		if g.Mode == AccessWrite {
			out = append(out, g)
		}
	}
	return out
}

// UserHasWriteGrant indique si l'utilisateur a au moins un grant write.
func UserHasWriteGrant(ctx context.Context, db *sql.DB, userID string) bool {
	grants, err := UserEffectiveGrants(ctx, db, userID)
	if err != nil {
		return false
	}
	return len(WriteGrants(grants)) > 0
}

// UserTeamScopes retourne les scopes effectifs (lecture) — compat. Préférer UserEffectiveGrants.
func UserTeamScopes(ctx context.Context, db *sql.DB, userID string) ([]Scope, error) {
	grants, err := UserEffectiveGrants(ctx, db, userID)
	if err != nil {
		return nil, err
	}
	return GrantsAsScopes(grants), nil
}

// UserWriteScopes retourne les scopes en écriture — compat. Préférer UserEffectiveGrants.
func UserWriteScopes(ctx context.Context, db *sql.DB, userID string) ([]Scope, error) {
	grants, err := UserEffectiveGrants(ctx, db, userID)
	if err != nil {
		return nil, err
	}
	return GrantsAsScopes(WriteGrants(grants)), nil
}

// UserAdminScopes : delete scopé non supporté en v1 grants — réservé admin plateforme (voir CanDeleteProxy).
func UserAdminScopes(ctx context.Context, db *sql.DB, userID string) ([]Scope, error) {
	return nil, nil
}

func scanScopes(rows *sql.Rows) ([]Scope, error) {
	defer rows.Close()
	var scopes []Scope
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Type, &s.Value); err == nil {
			scopes = append(scopes, s)
		}
	}
	return scopes, rows.Err()
}

// --- Vérifications d'accès ---

// CanReadProxy retourne true si l'utilisateur peut voir ce proxy.
func CanReadProxy(ctx context.Context, db *sql.DB, userID string, route *router.Route) bool {
	role := UserRole(ctx, db, userID)
	if IsSuperAdminRole(role) {
		return true
	}
	grants, err := UserEffectiveGrants(ctx, db, userID)
	if err != nil {
		return false
	}
	if IsAdminRole(role) && len(grants) == 0 {
		return true
	}
	return len(grants) > 0 && MatchRoute(GrantsAsScopes(grants), route)
}

// CanWriteProxy retourne true si l'utilisateur peut créer/modifier/désactiver ce proxy.
func CanWriteProxy(ctx context.Context, db *sql.DB, userID string, route *router.Route) bool {
	role := UserRole(ctx, db, userID)
	if IsSuperAdminRole(role) {
		return true
	}
	grants, err := UserEffectiveGrants(ctx, db, userID)
	if err != nil {
		return false
	}
	if IsAdminRole(role) && len(grants) == 0 {
		return true
	}
	write := WriteGrants(grants)
	return len(write) > 0 && MatchRoute(GrantsAsScopes(write), route)
}

// CanDeleteProxy retourne true si l'utilisateur peut supprimer ce proxy.
// Réservé aux admins plateforme (superadmin, admin global ou admin sans restriction de grant delete en v1).
func CanDeleteProxy(ctx context.Context, db *sql.DB, userID string, route *router.Route) bool {
	role := UserRole(ctx, db, userID)
	if IsSuperAdminRole(role) {
		return true
	}
	if !IsAdminRole(role) {
		return false
	}
	grants, err := UserEffectiveGrants(ctx, db, userID)
	if err != nil {
		return false
	}
	if len(grants) == 0 {
		return true
	}
	// Admin scopé : peut supprimer dans son périmètre de lecture (v1).
	return MatchRoute(GrantsAsScopes(grants), route)
}

// UserScopedCoreGlobs retourne les globs de Cores accessibles via scope type "core".
// Retourne nil si l'utilisateur a un accès global (superadmin ou admin sans grants).
func UserScopedCoreGlobs(ctx context.Context, db *sql.DB, userID string) []string {
	role := UserRole(ctx, db, userID)
	grants, _ := UserEffectiveGrants(ctx, db, userID)
	if IsSuperAdminRole(role) || (IsAdminRole(role) && len(grants) == 0) {
		return nil // accès global
	}
	var globs []string
	for _, g := range grants {
		if g.Type == "core" {
			globs = append(globs, g.Value)
		}
	}
	return globs
}

// --- Droits token (Core/Agent) ---

// TokenScopes retourne les scopes associés à un token (par ID de token).
func TokenScopes(ctx context.Context, db *sql.DB, tokenID string) ([]Scope, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT scope_type, scope_value FROM token_scopes WHERE token_id=?`, tokenID)
	if err != nil {
		return nil, err
	}
	return scanScopes(rows)
}

// TokenRBACRole retourne le rbac_role d'un token (valeur brute du token Bearer).
func TokenRBACRole(ctx context.Context, db *sql.DB, bearerToken string) (tokenID, rbacRole string) {
	db.QueryRowContext(ctx,
		`SELECT id, rbac_role FROM tokens WHERE token=? AND revoked=0
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
		bearerToken,
	).Scan(&tokenID, &rbacRole) //nolint:errcheck
	return
}

// --- Middlewares ---

// RequireAdmin autorise uniquement superadmin et admin (global ou scopé).
func RequireAdmin(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			if !IsAdmin(r.Context(), db, userID) {
				http.Error(w, "accès réservé aux administrateurs", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSuperAdmin autorise uniquement le superadmin.
func RequireSuperAdmin(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			if !IsSuperAdmin(r.Context(), db, userID) {
				http.Error(w, "accès réservé au super administrateur", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOperator autorise admin/superadmin, ou tout user disposant d'au moins un grant write.
func RequireOperator(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromContext(r.Context())
			if IsAdmin(r.Context(), db, userID) || UserHasWriteGrant(r.Context(), db, userID) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "accès insuffisant", http.StatusForbidden)
		})
	}
}
