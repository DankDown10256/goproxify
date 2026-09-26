// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package edgeproxy appelle l'API fichiers proxies de la passerelle (/internal/v1/proxies).
package edgeproxy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
)

// FilesEnabled is always true — YAML files are the only proxy store.
func FilesEnabled() bool { return true }

// Target is an Edge control-plane endpoint + bearer token.
type Target struct {
	ID       string
	NodeName string
	Endpoint string
	Token    string
}

// ListTargets loads Edge tokens with a non-empty endpoint.
func ListTargets(ctx context.Context, db *sql.DB) ([]Target, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, node_name, node_endpoint, token
		FROM tokens
		WHERE role='edge' AND revoked=0 AND node_endpoint != ''
		ORDER BY node_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	out := make([]Target, 0)
	for rows.Next() {
		var t Target
		var rawTok string
		if err := rows.Scan(&t.ID, &t.NodeName, &t.Endpoint, &rawTok); err != nil {
			continue
		}
		t.Endpoint = strings.TrimRight(t.Endpoint, "/")
		if seen[t.Endpoint] {
			continue
		}
		seen[t.Endpoint] = true
		t.Token = auth.PlainNodeToken(rawTok)
		out = append(out, t)
	}
	return out, nil
}

// Client talks to one Edge.
type Client struct {
	HTTP *http.Client
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type listResponse struct {
	Production []*proxystore.Envelope `json:"production"`
	Revisions  []*proxystore.Envelope `json:"revisions"`
}

func (c *Client) List(ctx context.Context, t Target) (*listResponse, error) {
	var out listResponse
	if err := c.do(ctx, t, http.MethodGet, "/internal/v1/proxies", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Get(ctx context.Context, t Target, id string) (*proxystore.Envelope, error) {
	var out proxystore.Envelope
	if err := c.do(ctx, t, http.MethodGet, "/internal/v1/proxies/"+id, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateRevision(ctx context.Context, t Target, body map[string]any) (*proxystore.Envelope, error) {
	var out proxystore.Envelope
	if err := c.do(ctx, t, http.MethodPost, "/internal/v1/proxies/revisions", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DryRun(ctx context.Context, t Target, id, rev string) (*proxystore.Envelope, error) {
	var out proxystore.Envelope
	path := fmt.Sprintf("/internal/v1/proxies/%s/revisions/%s/dry-run", id, rev)
	if err := c.do(ctx, t, http.MethodPost, path, nil, &out); err != nil {
		return &out, err
	}
	return &out, nil
}

func (c *Client) Promote(ctx context.Context, t Target, id, rev string) (*proxystore.Envelope, error) {
	var out proxystore.Envelope
	path := fmt.Sprintf("/internal/v1/proxies/%s/revisions/%s/promote", id, rev)
	if err := c.do(ctx, t, http.MethodPost, path, nil, &out); err != nil {
		return &out, err
	}
	return &out, nil
}

func (c *Client) Reject(ctx context.Context, t Target, id, rev, reason string) (*proxystore.Envelope, error) {
	var out proxystore.Envelope
	path := fmt.Sprintf("/internal/v1/proxies/%s/revisions/%s/reject", id, rev)
	body := map[string]string{"reason": reason}
	if err := c.do(ctx, t, http.MethodPost, path, body, &out); err != nil {
		return &out, err
	}
	return &out, nil
}

func (c *Client) Delete(ctx context.Context, t Target, id string) error {
	return c.do(ctx, t, http.MethodDelete, "/internal/v1/proxies/"+id, nil, nil)
}

func (c *Client) ListRevisions(ctx context.Context, t Target, id string) ([]*proxystore.Envelope, error) {
	var out []*proxystore.Envelope
	path := fmt.Sprintf("/internal/v1/proxies/%s/revisions", id)
	if err := c.do(ctx, t, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Publish runs create revision → dry-run → promote on one Edge (UI-compatible).
func (c *Client) Publish(ctx context.Context, t Target, id string, host string, enabled bool, config json.RawMessage, createdBy string) (*proxystore.Envelope, error) {
	body := map[string]any{
		"id":         id,
		"host":       host,
		"enabled":    enabled,
		"created_by": createdBy,
		"config":     config,
	}
	rev, err := c.CreateRevision(ctx, t, body)
	if err != nil {
		return nil, fmt.Errorf("create revision: %w", err)
	}
	dry, err := c.DryRun(ctx, t, rev.ID, rev.Revision)
	if err != nil {
		return dry, fmt.Errorf("dry-run: %w", err)
	}
	prod, err := c.Promote(ctx, t, rev.ID, rev.Revision)
	if err != nil {
		return prod, fmt.Errorf("promote: %w", err)
	}
	return prod, nil
}

// HTTPError carries a non-2xx status from Edge.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("edgeproxy: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) do(ctx context.Context, t Target, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.Endpoint+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Status: resp.StatusCode, Body: string(data)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
