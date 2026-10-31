// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import "time"

// setLast retient les derniers identifiants de logs qu'une passerelle a annoncés (logInfo.mu tenu).
func (s *logInfoState) setLast(node string, access, system int64) {
	if s.last == nil {
		s.last = map[string][2]int64{}
	}
	s.last[node] = [2]int64{access, system}
}

// AnnouncedLast rend les derniers identifiants que la passerelle a annoncés pour ses accès et ses logs système. ok est faux
// si elle n'a rien annoncé depuis trois envois : le chiffre n'est plus un repère.
func (m *Manager) AnnouncedLast(nodeName string) (access, system int64, ok bool) {
	m.logInfo.mu.Lock()
	defer m.logInfo.mu.Unlock()
	at, found := m.logInfo.at[nodeName]
	if !found || time.Since(at) > logInfoStale {
		return 0, 0, false
	}
	last := m.logInfo.last[nodeName]
	return last[0], last[1], true
}
