// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestIPProfilesExposeRefreshState(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ip_profiles (id, name, mode, last_error, consecutive_failures, next_attempt_at)
		VALUES ('p', 'p', 'deny', 'HTTP 503', 3, '2030-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	h := &api.IPProfilesHandler{DB: db}

	for _, path := range []string{"/api/v1/ip-profiles", "/api/v1/ip-profiles/p"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", path, rec.Code)
		}
		var got struct {
			LastError           string `json:"last_error"`
			ConsecutiveFailures int    `json:"consecutive_failures"`
			NextAttemptAt       string `json:"next_attempt_at"`
		}
		body := rec.Body.Bytes()
		if body[0] == '[' {
			var list []struct {
				LastError           string `json:"last_error"`
				ConsecutiveFailures int    `json:"consecutive_failures"`
				NextAttemptAt       string `json:"next_attempt_at"`
			}
			if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 {
				t.Fatalf("%s: %v %s", path, err, body)
			}
			got = list[0]
		} else if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got.LastError != "HTTP 503" || got.ConsecutiveFailures != 3 || got.NextAttemptAt == "" {
			t.Fatalf("%s: état absent: %+v", path, got)
		}
	}
}
