// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"testing"
)

func TestValidateProbeURL_DeniesSSRF(t *testing.T) {
	cases := []struct {
		url  string
		priv bool
		ok   bool
	}{
		{"http://8.8.8.8/x", false, true},
		{"https://1.1.1.1", true, true},
		{"ftp://8.8.8.8", false, false},
		{"http://127.0.0.1/", false, false},
		{"http://localhost/", false, false},
		{"http://169.254.169.254/latest", false, false},
		{"http://10.0.0.5:3000", false, false},
		{"http://10.0.0.5:3000", true, true},
		{"http://203.0.113.10/", false, false},
		{"http://[::1]/", false, false},
	}
	for _, c := range cases {
		err := validateProbeURLOpts(c.url, c.priv)
		if c.ok && err != nil {
			t.Fatalf("%s allowPrivate=%v: unexpected err %v", c.url, c.priv, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%s allowPrivate=%v: want deny", c.url, c.priv)
		}
	}
}
