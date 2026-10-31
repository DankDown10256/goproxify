// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/deploy"
	"github.com/vincamok/goproxify/internal/launcher"
)

// hostFlags range chaque --host, répétable.
type hostFlags []string

func (h *hostFlags) String() string     { return strings.Join(*h, " ") }
func (h *hostFlags) Set(v string) error { *h = append(*h, v); return nil }

// runLauncher installe GoProxify sur l'hôte local d'après une topologie donnée en ligne de commande (ADR 0019).
// L'image ghcr.io/vincamok/goproxify/launcher lance cette commande puis disparaît (docker run --rm).
func runLauncher() {
	if len(os.Args) > 2 && os.Args[2] == "join" {
		runLauncherJoin(os.Args[3:])
		return
	}
	if len(os.Args) > 2 && os.Args[2] == "update" {
		runLauncherUpdate(os.Args[3:])
		return
	}
	fs := flag.NewFlagSet("launcher", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, launcherUsage); fs.PrintDefaults() }
	var (
		admin    = fs.Bool("admin", false, "installe l'Admin sur cet hôte")
		edge     = fs.Bool("edge", false, "installe une passerelle sur cet hôte")
		agent    = fs.Bool("agent", false, "installe un Agent sur cet hôte")
		addr     = fs.String("addr", "", "adresse (IP ou nom) de cet hôte, joignable par les autres (défaut : localhost s'il est seul)")
		name     = fs.String("name", "", "nom de cet hôte (défaut : déduit de l'adresse)")
		group    = fs.String("group", "", "groupe HA de la passerelle de cet hôte")
		topoFile = fs.String("topology", "", "fichier JSON de topologie, à la place des indicateurs ci-dessus et de --host")
		email    = fs.String("email", "", "courriel du premier compte administrateur (défaut : "+launcher.DefaultAdminEmail+")")
		registry = fs.String("registry", launcher.DefaultRegistry, "registre des images")
		tag      = fs.String("tag", launcher.DefaultTag, "étiquette des images")
		tz       = fs.String("tz", "", "fuseau horaire des conteneurs (défaut : Europe/Paris)")
		socket   = fs.String("socket", "", "socket Docker (défaut : détecté)")
		restore  = fs.String("restore", "", "reconstruit l'Admin d'une sauvegarde (fichier de snapshot) : secret racine, certificat, topologie ; avec --name (hôte de cette machine dans la sauvegarde) ou --addr")
		bkKey    = fs.String("backup-key", "", "clé de sauvegarde pour --restore (défaut : GPX_BACKUP_KEY)")
		dryRun   = fs.Bool("dry-run", false, "valide et affiche le plan sans rien créer")
		ui       = fs.Bool("ui", false, "ouvre l'interface de conception (code d'accès dans la sortie), préremplie avec les indicateurs donnés, au lieu d'installer")
		listen   = fs.String("listen", launcher.DefaultListenAddr, "mode attente : adresse d'écoute")
		window   = fs.Duration("window", launcher.DefaultListenWindow, "mode attente : durée de la fenêtre d'écoute")
		expAdmin = fs.String("expect-admin", "", "mode attente : n'accepter que cet Admin (https://hôte:port)")
		expFP    = fs.String("expect-fingerprint", "", "mode attente : n'accepter que ce certificat d'Admin (SHA-256) ; avec --expect-admin, le lien n'attend pas de clic")
		hosts    hostFlags
	)
	fs.Var(&hosts, "host", "autre hôte : [nom=]adresse[:rôles][@groupe], répétable (rôles par défaut : agent)")
	_ = fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := docker.NewClient(docker.AutoDetectSocket("docker", *socket))

	if *restore != "" {
		if *admin || *edge || *agent || *topoFile != "" || *group != "" || len(hosts) > 0 || *ui {
			fmt.Fprintln(os.Stderr, "erreur : --restore prend la topologie de la sauvegarde ; il ne se combine pas avec --admin, --edge, --agent, --group, --host, --topology ni --ui")
			os.Exit(1)
		}
		key := *bkKey
		if key == "" {
			key = os.Getenv("GPX_BACKUP_KEY")
		}
		rep, err := launcherRestore(ctx, client, *restore, key, *name, *addr, *email, *registry, *tag, *tz, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		printLauncherReport(rep, *dryRun)
		return
	}

	// Sans rôle, sans topologie et sans hôte, le launcher n'a pas de quoi installer : il attend qu'un lien d'installation
	// de l'Admin le déclenche, ou qu'on dessine l'infrastructure dans son interface (ADR 0019, sections 1 et 8).
	listenOpts := launcher.ListenOptions{
		Addr: *listen, Window: *window, PinnedAdmin: *expAdmin, PinnedFingerprint: *expFP, API: client, Out: os.Stdout,
		AdminPassword: os.Getenv("GPX_FIRST_ADMIN_PASSWORD"), InitialEmail: *email, Registry: *registry, Tag: *tag, TZ: *tz,
	}
	runListen := func() {
		if err := launcher.Listen(ctx, listenOpts); err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
	}
	noSpec := *topoFile == "" && !*admin && !*edge && !*agent && len(hosts) == 0 && *addr == "" && *name == "" && *group == ""
	if noSpec {
		runListen()
		return
	}

	topo, err := launcherTopology(*topoFile, *admin, *edge, *agent, *addr, *name, *group, hosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	// Une information manque : plutôt que de refuser, le launcher ouvre son interface, préremplie avec ce qui est donné.
	if verr := topo.Validate(); *ui || verr != nil {
		listenOpts.Initial = topo
		if verr != nil {
			listenOpts.InitialNote = "Topologie à compléter : " + verr.Error()
		}
		runListen()
		return
	}

	rep, err := launcher.Run(ctx, client, launcher.Options{
		Topology: topo, AdminEmail: *email, AdminPassword: os.Getenv("GPX_FIRST_ADMIN_PASSWORD"),
		Registry: *registry, Tag: *tag, TZ: *tz, DryRun: *dryRun, Out: os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	printLauncherReport(rep, *dryRun)
}

const launcherUsage = `Usage : goproxify launcher [options]
        goproxify launcher                                  (sans rôle : attend un lien d'installation de l'Admin)
        goproxify launcher join <spec_url> [--fingerprint <empreinte>]
        goproxify launcher update [--dry-run]               (met à jour les conteneurs de cet hôte, volumes conservés)
        goproxify launcher --restore <fichier> --name <hôte> [--backup-key <clé>]   (reconstruit l'Admin d'une sauvegarde)

Installe GoProxify sur cet hôte (Admin, passerelle, Agent) et déclare les autres hôtes dans l'Admin.

Exemple, premier hôte :
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview \
    --admin --edge --agent --addr 192.168.1.10 \
    --host 192.168.1.50=agent --host nas=192.168.1.60:edge,agent

Exemple, hôte suivant (attend le QR code de sa fiche dans l'Admin, 15 minutes) :
  docker run --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview

Sans rôle (ou avec --ui, ou si la topologie donnée est incomplète), le launcher sert aussi une interface de conception sur
http://<hôte>:8080/design, protégée par un code d'accès affiché dans sa sortie.

Le mot de passe du premier compte vient de GPX_FIRST_ADMIN_PASSWORD, ou est généré et affiché une seule fois.

`

// runLauncherJoin installe cet hôte tout de suite d'après un ticket de l'Admin (`goproxify hosts join-ticket`), sans
// attendre de déclenchement : c'est la variante en ligne de commande du QR code.
func runLauncherJoin(args []string) {
	fs := flag.NewFlagSet("launcher join", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage : goproxify launcher join <spec_url> [--fingerprint <empreinte>] [--socket <chemin>]\n\n")
		fs.PrintDefaults()
	}
	fp := fs.String("fingerprint", "", "empreinte SHA-256 du certificat de l'Admin (donnée avec le ticket) ; sans elle, le certificat doit être public")
	socket := fs.String("socket", "", "socket Docker (défaut : détecté)")
	specURL := ""
	// L'adresse peut précéder ou suivre les options.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		specURL, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if specURL == "" {
		specURL = fs.Arg(0)
	}
	if specURL == "" {
		fs.Usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := docker.NewClient(docker.AutoDetectSocket("docker", *socket))
	rep, err := launcher.Join(ctx, client, specURL, *fp, func(e deploy.Event) {
		fmt.Printf("  %-9s %s\n", e.Step, e.Name)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nInstallation terminée : %s\nLes composants rejoignent l'Admin d'eux-mêmes.\n", strings.Join(rep.Containers, ", "))
}

// launcherRestore reconstruit l'Admin de cette machine d'après le fichier d'une sauvegarde (ADR 0019, étape 9).
func launcherRestore(ctx context.Context, api deploy.API, file, key, name, addr, email, registry, tag, tz string, dryRun bool) (*launcher.Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	rst, err := launcher.ReadBackup(data, key)
	if err != nil {
		return nil, err
	}
	topo, err := rst.TopologyFromBackup(name, addr)
	if err != nil {
		return nil, err
	}
	return launcher.Run(ctx, api, launcher.Options{
		Topology: topo, Restore: rst, AdminEmail: email, AdminPassword: os.Getenv("GPX_FIRST_ADMIN_PASSWORD"),
		Registry: registry, Tag: tag, TZ: tz, DryRun: dryRun, Out: os.Stdout,
	})
}

// runLauncherUpdate recrée les conteneurs GoProxify de cet hôte avec leur image la plus récente, volumes conservés.
func runLauncherUpdate(args []string) {
	fs := flag.NewFlagSet("launcher update", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage : goproxify launcher update [--dry-run] [--socket <chemin>]\n\n")
		fs.PrintDefaults()
	}
	socket := fs.String("socket", "", "socket Docker (défaut : détecté)")
	dryRun := fs.Bool("dry-run", false, "liste les conteneurs concernés sans rien tirer ni recréer")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := docker.NewClient(docker.AutoDetectSocket("docker", *socket))
	rep, err := launcher.Update(ctx, client, launcher.UpdateOptions{DryRun: *dryRun, Out: os.Stdout})
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	if *dryRun {
		fmt.Println("\nSimulation : rien n'a été tiré ni recréé.")
		return
	}
	fmt.Print(rep.Summary())
}

// launcherTopology construit la topologie depuis un fichier, ou depuis les indicateurs : l'hôte local est le premier.
func launcherTopology(file string, admin, edge, agent bool, addr, name, group string, others []string) (*launcher.Topology, error) {
	if file != "" {
		if admin || edge || agent || len(others) > 0 || addr != "" || name != "" || group != "" {
			return nil, errors.New("--topology remplace --admin, --edge, --agent, --addr, --name, --group et --host")
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var t launcher.Topology
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("%s : %w", file, err)
		}
		return &t, nil
	}

	var roles []string
	for _, r := range []struct {
		on   bool
		name string
	}{{admin, launcher.RoleAdmin}, {edge, launcher.RoleEdge}, {agent, launcher.RoleAgent}} {
		if r.on {
			roles = append(roles, r.name)
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("aucun rôle pour cet hôte : indiquez --admin, --edge et/ou --agent (ou --topology)")
	}
	if addr == "" {
		if len(others) > 0 {
			return nil, errors.New("--addr (adresse de cet hôte, joignable par les autres) est requis avec --host")
		}
		addr = "localhost"
	}
	if name == "" {
		name = launcher.DefaultHostName(addr)
	}
	t := &launcher.Topology{Local: name, Hosts: []launcher.Host{{Name: name, Addr: addr, Roles: roles, Group: group}}}
	for _, o := range others {
		h, err := launcher.ParseHost(o)
		if err != nil {
			return nil, err
		}
		t.Hosts = append(t.Hosts, h)
	}
	return t, nil
}

func printLauncherReport(rep *launcher.Report, dryRun bool) {
	if dryRun {
		fmt.Println("\nSimulation : rien n'a été créé.")
		if rep.Diagram != "" {
			fmt.Printf("\nSchéma de l'infrastructure (Mermaid) :\n\n%s", rep.Diagram)
		}
		return
	}
	fmt.Print(rep.Summary())
}
