// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// L'appairage écrit le jeton de l'Agent dans /etc/goproxify/agent.token. Sous Windows ce chemin est C:\etc\goproxify,
// le dossier d'état d'un environnement de développement : un test qui appaire y laissait un faux jeton, que la passerelle
// ne connaît pas (401). Aucun test du paquet n'écrit donc dans le vrai dossier.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agent-tests-")
	if err != nil {
		panic(err)
	}
	agentTokenPath = filepath.Join(dir, "agent.token")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
