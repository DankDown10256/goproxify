// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"sort"
)

// DeployMarker annote un changement de configuration sur la période. Trois sources, sans nouvelle
// table : proxy_history (alimentée à chaque création/modification de proxy — voir api/proxies.go),
// domains.updated_at (un seul horodatage par domaine, pas un historique complet) et
// cert_deploy_history (chaque livraison de certificat vers une cible de déploiement).
type DeployMarker struct {
	At     string `json:"at"` // horodatage tel qu'enregistré (UTC, format SQLite)
	Kind   string `json:"kind"` // proxy | domain | cert
	Proxy  string `json:"proxy"`
	Domain string `json:"domain"`
	Note   string `json:"note"` // "création", "modification", statut de déploiement, …
}

func deployTimeArgs(p Params) []any {
	return []any{p.From.UTC().Format("2006-01-02 15:04:05"), p.To.UTC().Format("2006-01-02 15:04:05")}
}

func getProxyDeploys(ctx context.Context, db *sql.DB, p Params) ([]DeployMarker, error) {
	args := deployTimeArgs(p)
	filter := ""
	if p.Proxy != "" {
		filter = " AND json_extract(h.config,'$.host') = ?"
		args = append(args, p.Proxy)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT h.created_at, COALESCE(pr.name, h.proxy_id), COALESCE(json_extract(h.config,'$.host'), ''), h.note
		 FROM proxy_history h
		 LEFT JOIN proxies pr ON pr.id = h.proxy_id
		 WHERE h.created_at >= ? AND h.created_at <= ?`+filter, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeployMarker
	for rows.Next() {
		m := DeployMarker{Kind: "proxy"}
		if rows.Scan(&m.At, &m.Proxy, &m.Domain, &m.Note) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// getDomainDeploys : domains.updated_at n'est pas un historique (une seule ligne par domaine), donc
// au plus un marqueur par domaine et par fenêtre — pas les changements intermédiaires.
func getDomainDeploys(ctx context.Context, db *sql.DB, p Params) ([]DeployMarker, error) {
	args := deployTimeArgs(p)
	filter := ""
	if p.Proxy != "" {
		filter = " AND domain = ?"
		args = append(args, p.Proxy)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT updated_at, domain FROM domains WHERE updated_at >= ? AND updated_at <= ?`+filter, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeployMarker
	for rows.Next() {
		m := DeployMarker{Kind: "domain", Note: "domaine"}
		if rows.Scan(&m.At, &m.Domain) == nil {
			m.Proxy = m.Domain
			out = append(out, m)
		}
	}
	return out, nil
}

func getCertDeploys(ctx context.Context, db *sql.DB, p Params) ([]DeployMarker, error) {
	args := deployTimeArgs(p)
	filter := ""
	if p.Proxy != "" {
		filter = " AND c.domain = ?"
		args = append(args, p.Proxy)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT h.deployed_at, c.domain, h.status
		 FROM cert_deploy_history h
		 JOIN certs c ON c.id = h.cert_id
		 WHERE h.deployed_at >= ? AND h.deployed_at <= ?`+filter, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeployMarker
	for rows.Next() {
		m := DeployMarker{Kind: "cert"}
		if rows.Scan(&m.At, &m.Domain, &m.Note) == nil {
			m.Proxy = m.Domain
			out = append(out, m)
		}
	}
	return out, nil
}

// GetDeployMarkers retourne les changements de configuration (proxys, domaines, certificats) sur
// [p.From, p.To], les plus anciens en premier. p.Proxy filtre sur le domaine ; p.NodeName est
// ignoré (une configuration n'est pas propre à une passerelle). Limité à 300 entrées au total.
func GetDeployMarkers(ctx context.Context, db *sql.DB, p Params) ([]DeployMarker, error) {
	proxies, err := getProxyDeploys(ctx, db, p)
	if err != nil {
		return nil, err
	}
	domains, err := getDomainDeploys(ctx, db, p)
	if err != nil {
		return nil, err
	}
	certs, err := getCertDeploys(ctx, db, p)
	if err != nil {
		return nil, err
	}
	out := make([]DeployMarker, 0, len(proxies)+len(domains)+len(certs))
	out = append(out, proxies...)
	out = append(out, domains...)
	out = append(out, certs...)
	sort.Slice(out, func(i, j int) bool { return out[i].At < out[j].At })
	if len(out) > 300 {
		out = out[len(out)-300:]
	}
	return out, nil
}
