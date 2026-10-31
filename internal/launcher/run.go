// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/deploy"
)

// DefaultAdminEmail est le compte créé quand aucun courriel n'est donné.
const DefaultAdminEmail = "admin@goproxify.local"

// Options règle une exécution du launcher.
type Options struct {
	Topology      *Topology
	AdminEmail    string
	AdminPassword string
	Registry      string
	Tag           string
	TZ            string
	// Restore reconstruit l'Admin d'une sauvegarde : son secret racine, son certificat, sa clé de sauvegarde et son
	// architecture.json au lieu d'en générer de nouveaux. Les données se restaurent ensuite dans l'Admin.
	Restore *Restored
	// DryRun valide, planifie et affiche, sans rien créer.
	DryRun bool
	Out    io.Writer
	// Now sert aux tests ; time.Now par défaut.
	Now func() time.Time
}

// Report est ce que l'utilisateur doit retenir à la fin : l'adresse de l'Admin, l'empreinte à comparer, le compte, et
// les hôtes qui attendent encore.
type Report struct {
	AdminURL      string
	Fingerprint   string
	AdminEmail    string
	AdminPassword string
	BackupKey     string
	// Diagram est le schéma Mermaid de la topologie installée.
	Diagram       string
	// Restored : l'Admin vient d'une sauvegarde ; KeptCertificate : son certificat (donc son empreinte) est celui de l'ancien.
	Restored        bool
	KeptCertificate bool
	Pending         []Host
	Containers    []string
	Plan          *deploy.Plan
}

// Run installe l'hôte local de la topologie : secrets, certificat de l'Admin, architecture.json, puis la description
// de l'hôte appliquée par le moteur (avec retour arrière si une étape échoue). Il ne laisse rien derrière lui.
func Run(ctx context.Context, api deploy.API, opt Options) (*Report, error) {
	t := opt.Topology
	if t == nil {
		return nil, fmt.Errorf("topologie manquante")
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	out := opt.Out
	if out == nil {
		out = io.Discard
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	local, _ := t.host(t.Local)
	email := opt.AdminEmail
	if email == "" {
		email = DefaultAdminEmail
		if opt.Restore != nil {
			email = RestoreAdminEmail
		}
	}

	secrets, err := NewSecrets(opt.AdminPassword)
	if err != nil {
		return nil, err
	}
	var cert *AdminCert
	env := Env{Secrets: secrets, Registry: opt.Registry, Tag: opt.Tag, TZ: opt.TZ, AdminEmail: email}
	if r := opt.Restore; r != nil {
		secrets.Root, secrets.Backup = r.Root, r.BackupKey
		env.RootPrevious, env.ArchitectureJSON, cert = r.RootPrevious, r.ArchitectureJSON, r.Cert
	}
	if cert == nil {
		if cert, err = NewAdminCert([]string{local.Addr, "localhost", "127.0.0.1", "goproxify-admin"}, now()); err != nil {
			return nil, err
		}
	}
	env.AdminCert = cert
	spec, err := t.HostSpec(t.Local, env)
	if err != nil {
		return nil, err
	}

	id, err := randomHex(6)
	if err != nil {
		return nil, err
	}
	engine := deploy.New(api, deploy.Options{
		DeployID: id,
		Progress: func(e deploy.Event) { fmt.Fprintf(out, "  %-9s %s\n", e.Step, e.Name) },
	})

	fmt.Fprintf(out, "Hôte local : %s (%s), rôles : %s\n", local.Name, local.Addr, strings.Join(local.Roles, ", "))
	plan, err := engine.Plan(ctx, spec)
	if err != nil {
		return nil, err
	}
	rep := &Report{
		AdminURL: fmt.Sprintf("https://%s:%d", local.Addr, adminPort), Fingerprint: cert.Fingerprint,
		AdminEmail: email, AdminPassword: secrets.AdminPassword, BackupKey: secrets.Backup, Plan: plan,
		Diagram: t.Mermaid(),
		Restored: opt.Restore != nil, KeptCertificate: opt.Restore != nil && opt.Restore.Cert != nil,
	}
	for _, h := range t.Hosts {
		if h.Name != t.Local {
			rep.Pending = append(rep.Pending, h)
		}
	}
	if opt.DryRun {
		fmt.Fprintf(out, "À tirer : %s\nRéseaux : %s\nVolumes : %s\n",
			join(plan.Pull), join(plan.Networks), join(plan.Volumes))
		return rep, nil
	}

	res, err := engine.Apply(ctx, spec)
	if err != nil {
		return nil, err
	}
	for _, c := range res.Containers {
		rep.Containers = append(rep.Containers, c.Name)
	}
	return rep, nil
}

// Summary est ce que le terminal affiche à la fin d'une installation : l'Admin, l'empreinte à comparer, le compte et les
// hôtes qui attendent encore.
func (r *Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, `
Installation terminée.

  Admin      %s
  Empreinte  %s
             (comparez-la à celle que votre navigateur affiche : le certificat est auto-signé)
  Compte     %s
  Mot de passe  %s
             (affiché une seule fois ; il reste dans l'environnement du conteneur de l'Admin)
  Clé de sauvegarde  %s
             (chiffre la partie secrets des sauvegardes de l'Admin : notez-la ailleurs que sur cet hôte,
              sans elle une sauvegarde ne se relit pas)
`, r.AdminURL, r.Fingerprint, r.AdminEmail, r.AdminPassword, r.BackupKey)
	if r.Restored {
		cert := "nouveau (nouvelle empreinte, la sauvegarde n'avait pas le certificat de l'Admin)"
		if r.KeptCertificate {
			cert = "celui de l'ancien Admin (même empreinte)"
		}
		fmt.Fprintf(&b, `
Admin reconstruit depuis une sauvegarde : le secret racine, la topologie et la clé de sauvegarde sont ceux de l'ancien
Admin, certificat : %s. Les passerelles et Agents déjà en place se reconnectent d'eux-mêmes.
Il reste à restaurer les données (comptes, proxys, règles…) :
  1. Connectez-vous à l'Admin avec le compte temporaire ci-dessus.
  2. Sauvegardes › Restaurer › fichier : choisissez le même fichier, cochez « Secrets ».
  3. Redémarrez l'Admin (docker restart goproxify-admin), connectez-vous avec vos comptes habituels, puis supprimez
     le compte temporaire (%s).
`, cert, r.AdminEmail)
	}
	if len(r.Pending) > 0 {
		b.WriteString("\nHôtes déclarés dans l'Admin, à installer ensuite :\n")
		for _, h := range r.Pending {
			fmt.Fprintf(&b, "  - %s (%s) : %s\n", h.Name, h.Addr, strings.Join(h.Roles, ", "))
		}
		b.WriteString("\nIls apparaissent dans la vue Infrastructure de l'Admin, à l'état déclaré.\n")
	}
	return b.String()
}

func join(s []string) string {
	if len(s) == 0 {
		return "aucun"
	}
	return strings.Join(s, ", ")
}
