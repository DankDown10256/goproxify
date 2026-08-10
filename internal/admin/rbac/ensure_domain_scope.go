// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// DomainScopePattern dérive le motif de périmètre à partir du domaine saisi
// (aligné sur le wizard infra : apex → *.apex ; déjà wildcard → tel quel).
func DomainScopePattern(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if strings.Contains(domain, "*") {
		return domain
	}
	apex := strings.TrimPrefix(domain, "*.")
	labels := strings.Split(apex, ".")
	n := 0
	for _, l := range labels {
		if l != "" {
			n++
		}
	}
	if n <= 2 {
		return "*." + apex
	}
	return domain
}

// EnsureDomainScope ajoute un périmètre domain sur le token Core si nécessaire.
//
// - Admin/superadmin sans aucun scope → no-op (accès global déjà OK).
// - Sinon, si aucun scope ne couvre le domaine → INSERT du motif DomainScopePattern.
// - Scope type "core" existant → déjà couvert (MatchCertName) → no-op.
//
// Retourne (motif ajouté, true) si un scope a été créé ; ("", false) sinon.
func EnsureDomainScope(ctx context.Context, db *sql.DB, tokenID, domain string) (addedValue string, added bool, err error) {
	tokenID = strings.TrimSpace(tokenID)
	domain = strings.TrimSpace(domain)
	if tokenID == "" || domain == "" {
		return "", false, nil
	}

	role := "admin"
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(rbac_role,'admin') FROM tokens WHERE id=?`, tokenID).Scan(&role)

	scopes, err := TokenScopes(ctx, db, tokenID)
	if err != nil {
		return "", false, fmt.Errorf("token scopes: %w", err)
	}

	// Admin sans périmètre = accès global : ne pas ajouter un premier scope
	// (passerait le token en mode restreint).
	if (IsAdminRole(role) || IsSuperAdminRole(role)) && len(scopes) == 0 {
		return "", false, nil
	}

	pattern := DomainScopePattern(domain)
	if pattern == "" {
		return "", false, nil
	}

	if MatchCertName(scopes, domain) || MatchCertName(scopes, pattern) {
		return "", false, nil
	}

	id := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO token_scopes (id, token_id, scope_type, scope_value) VALUES (?, ?, 'domain', ?)`,
		id, tokenID, pattern)
	if err != nil {
		// Course ou doublon UNIQUE → déjà couvert
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", false, nil
		}
		return "", false, fmt.Errorf("insert domain scope: %w", err)
	}
	return pattern, true, nil
}
