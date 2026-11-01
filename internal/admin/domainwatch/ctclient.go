// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package domainwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const ctMaxBody = 8 << 20

// HTTPCT lit un journal de transparence qui répond comme crt.sh : GET /?q=<nom>&output=json.
type HTTPCT struct {
	Client *http.Client
}

type ctRow struct {
	ID         int64  `json:"id"`
	Serial     string `json:"serial_number"`
	IssuerName string `json:"issuer_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

var ctTimeLayouts = []string{"2006-01-02T15:04:05", time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}

func parseCTTime(s string) time.Time {
	for _, l := range ctTimeLayouts {
		if t, err := time.Parse(l, strings.TrimSpace(s)); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Fetch rend les certificats non expirés que le journal connaît pour le nom.
func (h HTTPCT) Fetch(ctx context.Context, endpoint, domain string) ([]CTEntry, error) {
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	u := endpoint + "/?q=" + url.QueryEscape(domain) + "&output=json&exclude=expired"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "goproxify-domainwatch")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("journal de transparence : HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ctMaxBody))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}
	var rows []ctRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("journal de transparence : réponse illisible : %w", err)
	}
	out := make([]CTEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, CTEntry{Serial: r.Serial, Issuer: r.IssuerName, Names: strings.Split(r.NameValue, "\n"),
			NotBefore: parseCTTime(r.NotBefore), NotAfter: parseCTTime(r.NotAfter), ID: r.ID})
	}
	return out, nil
}
