// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ipprofile gère les profils de filtrage IP avec mise à jour automatique
// depuis des sources publiques (Tor, Cloudflare, Spamhaus, FireHOL, etc.).
package ipprofile

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Profile est un profil de filtrage IP stocké en DB.
type Profile struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	ProfileType     string   `json:"profile_type"`
	Mode            string   `json:"mode"`             // allow | deny
	FeedURLs        []string `json:"feed_urls"`
	FeedFormat      string   `json:"feed_format"`      // plain | json-aws | json-gcp | json-fastly | tsv-dshield
	RefreshIntervalH int     `json:"refresh_interval_h"`
	CIDRs           []string `json:"cidrs"`
	LastUpdatedAt   *string  `json:"last_updated_at,omitempty"`
	Enabled         bool     `json:"enabled"`
	CreatedAt       string   `json:"created_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

type seedProfile struct {
	Name             string
	ProfileType      string
	Mode             string
	FeedURLs         []string
	FeedFormat       string
	RefreshIntervalH int
}

// predefined contient les profils publics pré-définis, semés au premier démarrage.
var predefined = []seedProfile{
	{
		Name: "Tor Exit Nodes", ProfileType: "tor", Mode: "deny",
		FeedURLs:         []string{"https://check.torproject.org/torbulkexitlist"},
		FeedFormat:       "plain",
		RefreshIntervalH: 1,
	},
	{
		Name: "Cloudflare CDN (IPv4)", ProfileType: "cloudflare", Mode: "allow",
		FeedURLs:         []string{"https://www.cloudflare.com/ips-v4"},
		FeedFormat:       "plain",
		RefreshIntervalH: 24,
	},
	{
		Name: "Cloudflare CDN (IPv6)", ProfileType: "cloudflare", Mode: "allow",
		FeedURLs:         []string{"https://www.cloudflare.com/ips-v6"},
		FeedFormat:       "plain",
		RefreshIntervalH: 24,
	},
	{
		Name: "Fastly CDN", ProfileType: "fastly", Mode: "allow",
		FeedURLs:         []string{"https://api.fastly.com/public-ip-list"},
		FeedFormat:       "json-fastly",
		RefreshIntervalH: 24,
	},
	{
		Name: "AWS IP Ranges", ProfileType: "aws", Mode: "allow",
		FeedURLs:         []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"},
		FeedFormat:       "json-aws",
		RefreshIntervalH: 12,
	},
	{
		Name: "Google Cloud IP Ranges", ProfileType: "gcp", Mode: "allow",
		FeedURLs:         []string{"https://www.gstatic.com/ipranges/cloud.json"},
		FeedFormat:       "json-gcp",
		RefreshIntervalH: 24,
	},
	{
		Name: "Spamhaus DROP", ProfileType: "spamhaus-drop", Mode: "deny",
		FeedURLs:         []string{"https://www.spamhaus.org/drop/drop.txt"},
		FeedFormat:       "plain",
		RefreshIntervalH: 24,
	},
	{
		Name: "FireHOL Level 1", ProfileType: "firehol-l1", Mode: "deny",
		FeedURLs:         []string{"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
		FeedFormat:       "plain",
		RefreshIntervalH: 1,
	},
	{
		Name: "Feodo C2 (abuse.ch)", ProfileType: "feodo", Mode: "deny",
		FeedURLs:         []string{"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
		FeedFormat:       "plain",
		RefreshIntervalH: 1,
	},
	{
		Name: "DShield Top Attackers", ProfileType: "dshield", Mode: "deny",
		FeedURLs:         []string{"https://feeds.dshield.org/block.txt"},
		FeedFormat:       "tsv-dshield",
		RefreshIntervalH: 24,
	},
	{
		Name: "Emerging Threats Compromised", ProfileType: "et-compromised", Mode: "deny",
		FeedURLs:         []string{"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
		FeedFormat:       "plain",
		RefreshIntervalH: 12,
	},
}

// Updater gère la mise à jour périodique des profils IP depuis leurs feeds.
type Updater struct {
	db     *sql.DB
	log    *slog.Logger
	client *http.Client
}

// New crée un Updater.
func New(db *sql.DB, log *slog.Logger) *Updater {
	return &Updater{
		db:  db,
		log: log,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start démarre la boucle de mise à jour en arrière-plan.
func (u *Updater) Start(ctx context.Context) {
	go u.loop(ctx)
}

func (u *Updater) loop(ctx context.Context) {
	u.seed(ctx)
	u.refreshDue(ctx)

	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.refreshDue(ctx)
		}
	}
}

// seed insère les profils pré-définis s'ils n'existent pas encore.
func (u *Updater) seed(ctx context.Context) {
	for _, p := range predefined {
		furlsJSON, _ := json.Marshal(p.FeedURLs)
		u.db.ExecContext(ctx, //nolint:errcheck
			`INSERT OR IGNORE INTO ip_profiles
			 (id, name, profile_type, mode, feed_urls, feed_format, refresh_interval_h, cidrs, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?, '[]', 1)`,
			uuid.New().String(), p.Name, p.ProfileType, p.Mode,
			string(furlsJSON), p.FeedFormat, p.RefreshIntervalH,
		)
	}
}

// refreshDue recharge les profils dont la mise à jour est échue.
func (u *Updater) refreshDue(ctx context.Context) {
	rows, err := u.db.QueryContext(ctx,
		`SELECT id, name, feed_urls, feed_format, refresh_interval_h
		 FROM ip_profiles
		 WHERE enabled=1
		   AND (last_updated_at IS NULL
		     OR datetime(last_updated_at, '+' || refresh_interval_h || ' hours') < datetime('now'))`)
	if err != nil {
		u.log.Warn("ipprofile: lecture profils à rafraîchir", "err", err)
		return
	}
	defer rows.Close()

	type todo struct {
		id, name, feedURLsJSON, feedFormat string
		intervalH                          int
	}
	var todos []todo
	for rows.Next() {
		var t todo
		rows.Scan(&t.id, &t.name, &t.feedURLsJSON, &t.feedFormat, &t.intervalH) //nolint:errcheck
		todos = append(todos, t)
	}
	rows.Close()

	for _, t := range todos {
		var feedURLs []string
		json.Unmarshal([]byte(t.feedURLsJSON), &feedURLs) //nolint:errcheck
		cidrs, err := u.fetchAndParse(ctx, feedURLs, t.feedFormat)
		if err != nil {
			u.log.Warn("ipprofile: fetch échoué", "name", t.name, "err", err)
			continue
		}
		cidrsJSON, _ := json.Marshal(cidrs)
		u.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE ip_profiles SET cidrs=?, last_updated_at=datetime('now'), updated_at=datetime('now')
			 WHERE id=?`,
			string(cidrsJSON), t.id,
		)
		u.log.Info("ipprofile: mis à jour", "name", t.name, "cidrs", len(cidrs))
	}
}

// RefreshProfile force la mise à jour d'un profil par ID.
func (u *Updater) RefreshProfile(ctx context.Context, id string) error {
	var feedURLsJSON, feedFormat string
	err := u.db.QueryRowContext(ctx,
		`SELECT feed_urls, feed_format FROM ip_profiles WHERE id=?`, id).
		Scan(&feedURLsJSON, &feedFormat)
	if err != nil {
		return fmt.Errorf("profil introuvable: %w", err)
	}
	var feedURLs []string
	json.Unmarshal([]byte(feedURLsJSON), &feedURLs) //nolint:errcheck

	cidrs, err := u.fetchAndParse(ctx, feedURLs, feedFormat)
	if err != nil {
		return err
	}
	cidrsJSON, _ := json.Marshal(cidrs)
	_, err = u.db.ExecContext(ctx,
		`UPDATE ip_profiles SET cidrs=?, last_updated_at=datetime('now'), updated_at=datetime('now')
		 WHERE id=?`,
		string(cidrsJSON), id,
	)
	return err
}

func (u *Updater) fetchAndParse(ctx context.Context, feedURLs []string, format string) ([]string, error) {
	var all []string
	for _, url := range feedURLs {
		body, err := u.fetch(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", url, err)
		}
		cidrs, err := parseFeed(body, format)
		if err != nil {
			return nil, fmt.Errorf("parse %s (%s): %w", url, format, err)
		}
		all = append(all, cidrs...)
	}
	return all, nil
}

func (u *Updater) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "goproxify-ipprofile/1.0")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB max
}

// parseFeed extrait les CIDRs depuis le contenu brut selon le format.
func parseFeed(body []byte, format string) ([]string, error) {
	switch format {
	case "plain":
		return parsePlain(string(body)), nil
	case "json-aws":
		return parseAWS(body)
	case "json-gcp":
		return parseGCP(body)
	case "json-fastly":
		return parseFastly(body)
	case "tsv-dshield":
		return parseDShield(string(body)), nil
	default:
		return parsePlain(string(body)), nil
	}
}

// parsePlain parse un fichier texte : une IP ou CIDR par ligne, commentaires # et ;.
func parsePlain(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		// Strip inline comments (Spamhaus uses "; comment")
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Bare IP → /32 or /128
		if !strings.Contains(line, "/") {
			if strings.Contains(line, ":") {
				line += "/128"
			} else {
				line += "/32"
			}
		}
		out = append(out, line)
	}
	return out
}

func parseAWS(body []byte) ([]string, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range doc.Prefixes {
		if p.IPPrefix != "" {
			out = append(out, p.IPPrefix)
		}
	}
	for _, p := range doc.IPv6Prefixes {
		if p.IPv6Prefix != "" {
			out = append(out, p.IPv6Prefix)
		}
	}
	return out, nil
}

func parseGCP(body []byte) ([]string, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range doc.Prefixes {
		if p.IPv4Prefix != "" {
			out = append(out, p.IPv4Prefix)
		}
		if p.IPv6Prefix != "" {
			out = append(out, p.IPv6Prefix)
		}
	}
	return out, nil
}

func parseFastly(body []byte) ([]string, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := append(doc.Addresses, doc.IPv6Addresses...)
	return out, nil
}

// parseDShield parse le format TSV de DShield (col0=start IP, col2=prefix len).
func parseDShield(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		cidr := fields[0] + "/" + fields[2]
		out = append(out, cidr)
	}
	return out
}

// LoadActiveProfiles retourne les profils actifs avec leurs CIDRs compilés.
func LoadActiveProfiles(ctx context.Context, db *sql.DB) ([]*Profile, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, profile_type, mode, cidrs, enabled
		 FROM ip_profiles WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Profile
	for rows.Next() {
		var p Profile
		var cidrsJSON string
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.ProfileType, &p.Mode, &cidrsJSON, &enabled); err != nil {
			continue
		}
		p.Enabled = enabled == 1
		json.Unmarshal([]byte(cidrsJSON), &p.CIDRs) //nolint:errcheck
		out = append(out, &p)
	}
	return out, nil
}
