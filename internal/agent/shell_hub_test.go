// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

func TestShellCmdAllowed(t *testing.T) {
	cases := []struct {
		cmd  []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"/bin/sh"}, true},
		{[]string{"/bin/bash"}, true},
		{[]string{"sh"}, true},
		{[]string{"bash"}, true},
		{[]string{"/bin/sh", "-c", "id"}, false},
		{[]string{"/usr/bin/python"}, false},
		{[]string{"curl", "http://x"}, false},
	}
	for _, tc := range cases {
		if got := shellCmdAllowed(tc.cmd); got != tc.want {
			t.Errorf("shellCmdAllowed(%v)=%v want %v", tc.cmd, got, tc.want)
		}
	}
}
