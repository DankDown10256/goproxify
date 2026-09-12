// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ssrf

import (
	"testing"
)

func TestValidateHTTPURL_Schemes(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://example.com/path", false},
		{"https://example.com/path", false},
		{"ftp://example.com", true},
		{"file:///etc/passwd", true},
		{"//example.com", true},
		{"", true},
	}
	for _, tc := range cases {
		err := ValidateHTTPURL(tc.url, true)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", tc.url, err, tc.wantErr)
		}
	}
}

func TestValidateHTTPURL_BlockedHosts(t *testing.T) {
	blocked := []string{
		"http://localhost/",
		"http://localhost:8080/",
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.253/",
		"http://metadata.google.internal/",
	}
	for _, u := range blocked {
		if err := ValidateHTTPURL(u, false); err == nil {
			t.Errorf("expected block for %q", u)
		}
	}
}

func TestValidateHTTPURL_PrivateAllowed(t *testing.T) {
	// Loopback allowed when allowPrivate=true
	if err := ValidateHTTPURL("http://127.0.0.1:8080/", true); err != nil {
		t.Errorf("loopback with allowPrivate should pass: %v", err)
	}
}

func TestValidateHTTPURL_RFC1918(t *testing.T) {
	private := []string{
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"http://172.16.0.1/",
	}
	for _, u := range private {
		if err := ValidateHTTPURL(u, false); err == nil {
			t.Errorf("RFC1918 %q should be blocked when allowPrivate=false", u)
		}
		if err := ValidateHTTPURL(u, true); err != nil {
			t.Errorf("RFC1918 %q should pass when allowPrivate=true: %v", u, err)
		}
	}
}

func TestAllowPrivateEnv(t *testing.T) {
	cases := []struct{ val, want string }{
		{"1", "true"}, {"true", "true"}, {"yes", "true"},
		{"TRUE", "true"}, {"YES", "true"},
		{"0", "false"}, {"", "false"}, {"no", "false"},
	}
	for _, tc := range cases {
		t.Setenv("GPX_TEST_PRIV", tc.val)
		got := AllowPrivateEnv("GPX_TEST_PRIV")
		want := tc.want == "true"
		if got != want {
			t.Errorf("AllowPrivateEnv(%q)=%v want %v", tc.val, got, want)
		}
	}
}
