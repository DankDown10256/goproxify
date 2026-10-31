// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Désactivation des routes issues des conteneurs (Docker, Portainer, Podman, Kubernetes, annuaires). L'Admin garde la
// liste des hôtes désactivés et la pousse en entier aux passerelles, qui la retiennent et se la répliquent : l'Admin
// n'est pas dans le chemin du trafic, il décide seulement.

const settingDisabledRoutes = "discovered.disabled_hosts"

// DisabledRoutesPusher publie la liste des hôtes désactivés sur les passerelles.
type DisabledRoutesPusher interface {
	PushDisabledRoutes(ctx context.Context)
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// LoadDisabledRoutes lit les hôtes désactivés, triés. Le payload poussé en est la copie exacte.
func LoadDisabledRoutes(db *sql.DB) []string {
	var hosts []string
	_ = json.Unmarshal([]byte(admindb.GetSetting(db, settingDisabledRoutes, "[]")), &hosts)
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h = normalizeHost(h); h != "" {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func saveDisabledRoutes(db *sql.DB, hosts []string) error {
	b, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	return admindb.SetSetting(db, settingDisabledRoutes, string(b))
}

var ErrContainerRouteOutOfScope = errors.New("hôte hors de la portée de l'utilisateur")

// SetEnabled active ou désactive la route d'un hôte. L'hôte est celui que la liste des conteneurs affiche ; désactiver
// un hôte que personne n'annonce est refusé (ErrContainerNotFound), pour qu'une faute de frappe ne laisse pas une
// désactivation orpheline. Réactiver est toujours permis.
func (h *DiscoveredContainersHandler) SetEnabled(ctx context.Context, userID, actor, host string, enabled bool) error {
	host = normalizeHost(host)
	if host == "" {
		return ErrContainerNotFound
	}
	if !rbac.CanWriteProxy(ctx, h.DB, userID, &router.Route{Host: host}) {
		return ErrContainerRouteOutOfScope
	}
	next := make([]string, 0, 1)
	for _, d := range LoadDisabledRoutes(h.DB) {
		if d != host {
			next = append(next, d)
		}
	}
	if !enabled {
		if !h.announces(ctx, host) {
			return ErrContainerNotFound
		}
		next = append(next, host)
		sort.Strings(next)
	}
	if err := saveDisabledRoutes(h.DB, next); err != nil {
		return err
	}
	state := "désactivée"
	if enabled {
		state = "activée"
	}
	_ = admindb.WriteAudit(h.DB, actor, "patch", "container-route:"+host, state)
	if h.Pusher != nil {
		go h.Pusher.PushDisabledRoutes(context.Background())
	}
	return nil
}

// setEnabled : PUT /api/v1/discovered-containers/enabled.
func (h *DiscoveredContainersHandler) setEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string `json:"host"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil || normalizeHost(body.Host) == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	switch err := h.SetEnabled(r.Context(), userID, userID, body.Host, *body.Enabled); {
	case errors.Is(err, ErrContainerRouteOutOfScope):
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope_domain")
	case errors.Is(err, ErrContainerNotFound):
		writeErr(w, r, http.StatusNotFound, "api.err.container_not_found")
	case err != nil:
		if h.Log != nil {
			h.Log.Error("discovered-containers: enregistrement des routes désactivées", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// announces dit si une passerelle annonce une route (active, désactivée ou arrêtée) pour cet hôte.
func (h *DiscoveredContainersHandler) announces(ctx context.Context, host string) bool {
	for _, c := range h.FetchFromEdges(ctx) {
		if normalizeHost(c.Host) == host {
			return true
		}
	}
	return false
}

// withDisabled complète la liste des passerelles : un hôte désactivé que plus aucune passerelle n'annonce (Agent absent
// depuis le redémarrage) reste visible, pour qu'on puisse le réactiver.
func withDisabled(items []DiscoveredContainer, disabled []string) []DiscoveredContainer {
	seen := map[string]bool{}
	for _, c := range items {
		if c.Disabled {
			seen[normalizeHost(c.Host)] = true
		}
	}
	for _, host := range disabled {
		if !seen[host] {
			items = append(items, DiscoveredContainer{ID: "disabled:" + host, Host: host, Backends: []string{}, Disabled: true})
		}
	}
	return items
}
