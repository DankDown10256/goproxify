// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/deploy"
)

// UpdateAPI est ce que la mise à jour demande au démon : l'API du moteur de déploiement, plus les en-têtes pour tirer une
// image ; *docker.Client la satisfait.
type UpdateAPI interface {
	deploy.API
	PostWithHeaders(ctx context.Context, path string, body any, out any, headers map[string]string) error
}

// UpdateOptions règle une mise à jour. Tout est facultatif.
type UpdateOptions struct {
	// DryRun liste ce qui serait vérifié, sans tirer d'image ni toucher à un conteneur.
	DryRun bool
	Out    io.Writer
	// HealthTimeout borne l'attente d'un conteneur recréé (2 minutes par défaut) ; PollInterval en est l'intervalle.
	HealthTimeout time.Duration
	PollInterval  time.Duration
}

// UpdateReport dit ce qu'une mise à jour a fait.
type UpdateReport struct {
	Updated []string
	Current []string
}

// installedContainers sont les conteneurs que le launcher crée, dans l'ordre où il les démarre.
var installedContainers = []string{"goproxify-admin", "goproxify-edge", "goproxify-agent"}

type installedContainer struct {
	name    string
	id      string
	ref     string // image désignée par le conteneur (registre/composant:étiquette)
	imageID string // image réellement utilisée
}

// Update recrée avec leur image la plus récente les conteneurs GoProxify de cet hôte, sans toucher à leurs volumes
// (état de l'Admin, de la passerelle, de l'Agent : comptes, certificats, architecture.json, clés). Chaque conteneur garde
// sa configuration complète, variables comprises ; seule l'image change. Les images sont toutes tirées avant d'arrêter
// quoi que ce soit, puis les conteneurs sont recréés un à un : un qui ne devient pas sain retrouve son ancienne image.
//
// Une image qui ne peut pas être tirée (registre privé, le démon n'a pas d'identifiants) n'arrête pas la mise à jour si une
// image locale existe : on peut l'avoir tirée à la main avec `docker pull`.
func Update(ctx context.Context, api UpdateAPI, opt UpdateOptions) (*UpdateReport, error) {
	out := opt.Out
	if out == nil {
		out = io.Discard
	}
	if opt.HealthTimeout <= 0 {
		opt.HealthTimeout = 2 * time.Minute
	}
	if opt.PollInterval <= 0 {
		opt.PollInterval = time.Second
	}

	var found []installedContainer
	for _, name := range installedContainers {
		var raw struct {
			ID     string `json:"Id"`
			Image  string `json:"Image"`
			Config struct {
				Image string `json:"Image"`
			} `json:"Config"`
		}
		if err := api.Get(ctx, "/containers/"+name+"/json", &raw); err != nil {
			if docker.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		found = append(found, installedContainer{name: name, id: raw.ID, ref: raw.Config.Image, imageID: raw.Image})
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("aucune installation GoProxify sur cet hôte (conteneurs %s introuvables)", strings.Join(installedContainers, ", "))
	}
	if opt.DryRun {
		for _, c := range found {
			fmt.Fprintf(out, "  %-16s %s\n", c.name, c.ref)
		}
		return &UpdateReport{}, nil
	}

	engine := deploy.New(api, deploy.Options{})
	latest := map[string]string{} // image → identifiant de l'image locale après le pull
	for _, c := range found {
		if _, done := latest[c.ref]; done {
			continue
		}
		fmt.Fprintf(out, "  %-9s %s\n", "pull", c.ref)
		pullErr := engine.Pull(ctx, c.ref)
		var img struct {
			ID string `json:"Id"`
		}
		if err := api.Get(ctx, "/images/"+c.ref+"/json", &img); err != nil {
			if pullErr != nil {
				return nil, pullErr
			}
			return nil, fmt.Errorf("image %s : %w", c.ref, err)
		}
		if pullErr != nil {
			fmt.Fprintf(out, "  attention : %s\n              l'image locale est utilisée\n", strings.TrimSpace(pullErr.Error()))
		}
		latest[c.ref] = img.ID
	}

	rep := &UpdateReport{}
	lm := docker.NewLifecycleManager(api, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, c := range found {
		if latest[c.ref] == c.imageID {
			fmt.Fprintf(out, "  %-9s %s (déjà à jour)\n", "ok", c.name)
			rep.Current = append(rep.Current, c.name)
			continue
		}
		fmt.Fprintf(out, "  %-9s %s\n", "recreate", c.name)
		if err := lm.RecreateContainer(ctx, c.id, c.ref, false); err != nil {
			return rep, fmt.Errorf("recréation de %s : %w", c.name, err)
		}
		if err := awaitRunning(ctx, api, c.name, opt.HealthTimeout, opt.PollInterval); err != nil {
			// L'ancien conteneur a disparu : on recrée l'ancienne image, retrouvée par son identifiant.
			var cur struct {
				ID string `json:"Id"`
			}
			if gerr := api.Get(ctx, "/containers/"+c.name+"/json", &cur); gerr != nil {
				return rep, fmt.Errorf("%w (retour à l'ancienne image impossible : %v)", err, gerr)
			}
			fmt.Fprintf(out, "  %-9s %s : retour à l'ancienne image\n", "rollback", c.name)
			// L'étiquette est remise sur l'ancienne image : sans cela le conteneur ne porterait plus qu'un identifiant et
			// la mise à jour suivante ne saurait plus quelle image tirer.
			target := c.imageID
			if repo, tag, ok := splitRef(c.ref); ok {
				if terr := api.Post(ctx, "/images/"+c.imageID+"/tag?repo="+url.QueryEscape(repo)+"&tag="+url.QueryEscape(tag), nil, nil); terr == nil {
					target = c.ref
				}
			}
			if rerr := lm.RecreateContainer(ctx, cur.ID, target, false); rerr != nil {
				return rep, fmt.Errorf("%w (retour à l'ancienne image impossible : %v)", err, rerr)
			}
			return rep, fmt.Errorf("mise à jour de %s annulée : %w", c.name, err)
		}
		rep.Updated = append(rep.Updated, c.name)
	}
	return rep, nil
}

// splitRef sépare `registre/composant:étiquette` ; une image sans étiquette est `latest`, une image désignée par son
// condensat ne peut pas être étiquetée.
func splitRef(ref string) (repo, tag string, ok bool) {
	if strings.Contains(ref, "@") {
		return "", "", false
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i], ref[i+1:], true
	}
	return ref, "latest", true
}

// awaitRunning attend qu'un conteneur recréé soit sain, ou, sans contrôle de santé, qu'il reste démarré quelques secondes.
func awaitRunning(ctx context.Context, api deploy.API, name string, timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	stable := 0
	for {
		var st struct {
			State struct {
				Status string `json:"Status"`
				Health *struct {
					Status string `json:"Status"`
				} `json:"Health"`
			} `json:"State"`
		}
		if err := api.Get(ctx, "/containers/"+name+"/json", &st); err != nil {
			return fmt.Errorf("état de %s : %w", name, err)
		}
		switch {
		case st.State.Health != nil && st.State.Health.Status == "healthy":
			return nil
		case st.State.Status == "exited" || st.State.Status == "dead":
			return fmt.Errorf("%s s'est arrêté", name)
		case st.State.Health == nil && st.State.Status == "running":
			if stable++; stable >= 3 {
				return nil
			}
		default:
			stable = 0
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s n'est pas sain après %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Summary est ce que le terminal affiche à la fin d'une mise à jour.
func (r *UpdateReport) Summary() string {
	switch {
	case len(r.Updated) == 0:
		return "\nTout est déjà à jour.\n"
	case len(r.Current) == 0:
		return fmt.Sprintf("\nMise à jour terminée : %s.\n", strings.Join(r.Updated, ", "))
	}
	return fmt.Sprintf("\nMise à jour terminée : %s (déjà à jour : %s).\n", strings.Join(r.Updated, ", "), strings.Join(r.Current, ", "))
}
