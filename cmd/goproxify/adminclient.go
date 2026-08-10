// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// adminClient appelle l'API Admin avec Bearer (JWT session ou PAT).
type adminClient struct {
	base   string
	token  string
	client *http.Client
}

func newAdminClient(args map[string]string) (*adminClient, error) {
	base := flagValue(args, "-admin-url", os.Getenv("GPX_CONTROLPLANE_ADMIN_ENDPOINT"))
	tok := flagValue(args, "-token", os.Getenv("GPX_CONTROLPLANE_AUTH_TOKEN"))
	if base == "" {
		return nil, fmt.Errorf("-admin-url ou GPX_CONTROLPLANE_ADMIN_ENDPOINT requis")
	}
	if tok == "" {
		return nil, fmt.Errorf("-token ou GPX_CONTROLPLANE_AUTH_TOKEN requis")
	}
	return &adminClient{
		base:   strings.TrimRight(base, "/"),
		token:  tok,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (c *adminClient) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.base + path
}

// DoJSON envoie une requête JSON et décode la réponse dans out (peut être nil).
// acceptStatus liste les codes HTTP acceptés (défaut: 200).
func (c *adminClient) DoJSON(method, path string, body any, out any, acceptStatus ...int) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.url(path), rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	ok := false
	if len(acceptStatus) == 0 {
		ok = resp.StatusCode == http.StatusOK
	} else {
		for _, s := range acceptStatus {
			if resp.StatusCode == s {
				ok = true
				break
			}
		}
	}
	if !ok {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d : %s", resp.StatusCode, msg)
	}
	if out != nil && len(data) > 0 && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("décodage JSON : %w", err)
		}
	}
	return resp.StatusCode, nil
}

// DoRaw envoie une requête et retourne le corps brut (téléchargements).
func (c *adminClient) DoRaw(method, path string, body []byte, contentType string, acceptStatus ...int) ([]byte, string, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.url(path), rdr)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	ok := false
	if len(acceptStatus) == 0 {
		ok = resp.StatusCode == http.StatusOK
	} else {
		for _, s := range acceptStatus {
			if resp.StatusCode == s {
				ok = true
				break
			}
		}
	}
	if !ok {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return nil, "", resp.StatusCode, fmt.Errorf("HTTP %d : %s", resp.StatusCode, msg)
	}
	fname := ""
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if i := strings.Index(cd, "filename="); i >= 0 {
			fname = strings.Trim(cd[i+len("filename="):], `"' `)
		}
	}
	return data, fname, resp.StatusCode, nil
}

func adminAuthHint() string {
	return "       -admin-url  URL Admin (ou GPX_CONTROLPLANE_ADMIN_ENDPOINT)\n" +
		"       -token      Token/PAT (ou GPX_CONTROLPLANE_AUTH_TOKEN)"
}
