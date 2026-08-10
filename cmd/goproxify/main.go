// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// Embed zoneinfo pour que TZ fonctionne même sans /usr/share/zoneinfo (image scratch).
	_ "time/tzdata"

	"github.com/vincamok/goproxify/internal/admin"
	"github.com/vincamok/goproxify/internal/agent"
	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/core"
	corecache "github.com/vincamok/goproxify/internal/core/cache"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	coretokens "github.com/vincamok/goproxify/internal/core/tokens"
	"github.com/vincamok/goproxify/internal/landing"
	"github.com/vincamok/goproxify/internal/tz"
)

func main() {
	buildinfo.Set(VersionAdmin, VersionCore, VersionAgent, VersionWebapp, VersionLanding, GitCommit, BuildTime)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "admin":
		runAdmin()
	case "core":
		runCore()
	case "agent":
		runAgent()
	case "landing":
		runLanding()
	case "token":
		runToken()
	case "backup":
		runBackup()
	case "import":
		runImport()
	case "alert":
		runAlert()
	case "update":
		runUpdate()
	case "status":
		runStatus()
	case "access":
		runAccess()
	case "nodes":
		runNodes()
	case "declared":
		runDeclared()
	case "bootstrap":
		runBootstrap()
	case "version":
		fmt.Printf("goproxify\n")
		fmt.Printf("  admin    %s\n", VersionAdmin)
		fmt.Printf("  core     %s\n", VersionCore)
		fmt.Printf("  agent    %s\n", VersionAgent)
		fmt.Printf("  webapp   %s\n", VersionWebapp)
		fmt.Printf("  landing  %s\n", VersionLanding)
		fmt.Printf("  commit   %s\n", GitCommit)
		fmt.Printf("  built    %s\n", BuildTime)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "sous-commande inconnue : %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// Aide
// -----------------------------------------------------------------------------

func usage() {
	fmt.Print(`Usage: goproxify <commande> [options]

Commandes de service :
  admin    Démarre l'Administration (Control Plane + Web UI)
  core     Démarre le Core (Data Plane — Reverse Proxy)
  agent    Démarre l'Agent (Discovery & Télémétrie)
  landing  Démarre la page de présentation

Commandes d'administration (API Admin — -admin-url / -token) :
  token     Tokens d'appairage Core/Agent (create/list/revoke)
  backup    Snapshots Admin + export routage (create/list/restore)
  import    Import nginx/Traefik/Caddy/HAProxy (parse local, apply remote)
  update    Mise à jour des images Docker (via Agent)
  alert     Test des canaux de notification
  status    État du cluster
  access    GoProxify Access (config, catalogue, users, templates, audit)
  nodes     Nœuds Infrastructure (list / accept / reject pending)
  declared  Nœuds déclarés wizard architecture (list / create / delete)
  bootstrap Tickets QR / curl|bash d'intégration d'hôtes

  version  Affiche la version du binaire
  help     Affiche cette aide

Options communes :
  -config <chemin>    Chemin vers le fichier de configuration JSON
                      (défaut : ./config/<commande>.json)
  -admin-url <url>    URL de l'Administration (API Admin)
                      (défaut : GPX_CONTROLPLANE_ADMIN_ENDPOINT)
  -token <token>      JWT session ou PAT Admin (défaut : GPX_CONTROLPLANE_AUTH_TOKEN)

Variables d'environnement :
  GPX_<SECTION>_<KEY>   Surcharge n'importe quelle clé du fichier de config.
  Exemples courants :
    GPX_APP_ENVIRONMENT=production
    GPX_CONTROLPLANE_AUTH_TOKEN=gpx_core_abc123
    GPX_SECURITY_JWT_SECRET=mon_secret_prod

  Plan de contrôle WebSocket :
    GPX_CONTROL_PLANE_ADMIN_HMAC_SECRET   Clé HMAC-SHA256 partagée Admin↔Core (auth tunnel WS)
    GPX_CONTROL_PLANE_JOIN_TOKEN          Token d'appairage Agent→Core (premier démarrage, gpx_join_*)
    GPX_CONTROL_PLANE_CORE_ENDPOINT       URL du Core local (Agent WS, ex: http://goproxify-core:8000)

Pour l'aide d'une sous-commande :
  goproxify agent help
  goproxify token help
  goproxify backup help
  goproxify import help
  goproxify alert help
  goproxify access help
`)
}

// -----------------------------------------------------------------------------
// Services
// -----------------------------------------------------------------------------

func runAdmin() {
	args := parseFlags(os.Args[2:])

	cfg, err := config.LoadAdmin(configPath("admin", args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur config admin : %v\n", err)
		os.Exit(1)
	}

	// Mode maintenance : reset du mot de passe admin sans démarrer le serveur
	if _, ok := args["-reset-password"]; ok {
		email := flagValue(args, "-email", "")
		password := flagValue(args, "-password", "")
		if email == "" || password == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify admin -reset-password -email <email> -password <nouveau-mdp>")
			os.Exit(1)
		}
		if err := admin.ResetPassword(cfg, email, password); err != nil {
			fmt.Fprintf(os.Stderr, "reset-password : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Mot de passe réinitialisé pour %s\n", email)
		return
	}

	srv, err := admin.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialisation admin : %v\n", err)
		os.Exit(1)
	}
	buildinfo.LogBanner(slog.Default(), "admin", VersionAdmin)
	tz.LogStartup(slog.Default())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "démarrage admin : %v\n", err)
		os.Exit(1)
	}
	<-ctx.Done()
	srv.Stop(context.Background())
}

func runCore() {
	sub := subcommand(os.Args, 2)

	// Sous-commandes de gestion du cache local
	if sub == "cache" {
		runCoreCache()
		return
	}

	// Sous-commandes de gestion des tokens locaux
	if sub == "token" {
		runCoreToken()
		return
	}

	args := parseFlags(os.Args[2:])
	cfg, err := config.LoadCore(configPath("core", args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur config core : %v\n", err)
		os.Exit(1)
	}

	errorpages.CoreVersion = VersionCore
	srv, err := core.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialisation core : %v\n", err)
		os.Exit(1)
	}
	buildinfo.LogBanner(slog.Default(), "core", VersionCore)
	tz.LogStartup(slog.Default())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "démarrage core : %v\n", err)
		os.Exit(1)
	}
	<-ctx.Done()
	srv.Stop(context.Background())
}

func runCoreCache() {
	sub := subcommand(os.Args, 3)

	cachePath := "/etc/goproxify/core-cache.gpx"
	if p := os.Getenv("GPX_CORE_CACHE_PATH"); p != "" {
		cachePath = p
	}
	secret := corecache.ResolveSecret(os.Getenv("GPX_CONTROL_PLANE_AUTH_TOKEN"))
	store := corecache.New(cachePath, secret)

	switch sub {
	case "show":
		info, err := store.Info()
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur lecture cache : %v\n", err)
			os.Exit(1)
		}
		if info == nil {
			fmt.Printf("Aucun cache disponible à %s\n", cachePath)
			return
		}
		fmt.Printf("Cache Core\n")
		fmt.Printf("  Chemin    : %s\n", info.Path)
		fmt.Printf("  Sauvegardé: %s\n", info.SavedAt.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("  Routes    : %d\n", info.RouteCount)
		fmt.Printf("  Certificats: %d\n", info.CertCount)

	case "refresh":
		fmt.Println("La commande refresh nécessite que le Core soit en cours d'exécution.")
		fmt.Println("Envoyez SIGHUP au processus Core pour forcer une resync.")

	case "export":
		args := parseFlags(os.Args[4:])
		output := flagValue(args, "-output", "core-cache-export.json")
		if err := store.ExportJSON(output); err != nil {
			fmt.Fprintf(os.Stderr, "export échoué : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Cache exporté → %s\n", output)

	case "clear":
		if err := store.Clear(); err != nil {
			fmt.Fprintf(os.Stderr, "suppression cache échouée : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Cache supprimé : %s\n", cachePath)

	case "help", "":
		fmt.Print(`Usage: goproxify core cache <sous-commande>

Sous-commandes apparentées :
  goproxify core token   Gestion des tokens d'authentification

Gestion du cache local du Core (table de routage + certificats sauvegardés).
Le Core charge ce cache au démarrage si l'Administration est injoignable.

Sous-commandes :
  show      Affiche l'état du cache (date, nombre de routes, certificats)
  refresh   Force une resynchronisation depuis l'Administration et sauvegarde
  export    Exporte le cache en JSON lisible
  clear     Efface le cache local

goproxify core cache show
goproxify core cache refresh
goproxify core cache export [-output <fichier>]
  -output   Fichier de destination (défaut: core-cache-export.json)
goproxify core cache clear
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande core cache inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify core cache help")
		os.Exit(1)
	}
}

func runCoreToken() {
	sub := subcommand(os.Args, 3)

	tokensPath := "/etc/goproxify/core-tokens.db"
	if p := os.Getenv("GPX_CORE_TOKENS_PATH"); p != "" {
		tokensPath = p
	}

	store, err := coretokens.Open(tokensPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	switch sub {
	case "create", "":
		args := parseFlags(os.Args[4:])
		name := flagValue(args, "-name", "")
		roleStr := flagValue(args, "-role", "agent")
		ttlStr := flagValue(args, "-ttl", "0")
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify core token create -name <nom> [-role admin|agent] [-ttl 24h]")
			os.Exit(1)
		}
		var role coretokens.Role
		switch roleStr {
		case "admin":
			role = coretokens.RoleAdmin
		case "agent":
			role = coretokens.RoleAgent
		default:
			fmt.Fprintf(os.Stderr, "-role doit être 'admin' ou 'agent' (reçu: %q)\n", roleStr)
			os.Exit(1)
		}
		var ttl time.Duration
		if ttlStr != "0" && ttlStr != "" {
			ttl, err = time.ParseDuration(ttlStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "-ttl invalide: %v\n", err)
				os.Exit(1)
			}
		}
		raw, id, err := store.Create(name, role, ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "création échouée: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token créé\n")
		fmt.Printf("  ID   : %s\n", id)
		fmt.Printf("  Nom  : %s\n", name)
		fmt.Printf("  Rôle : %s\n", roleStr)
		if ttl > 0 {
			fmt.Printf("  TTL  : %s\n", ttl)
		} else {
			fmt.Printf("  TTL  : permanent\n")
		}
		fmt.Printf("\nToken (copiez-le maintenant, il ne sera plus affiché) :\n\n  %s\n\n", raw)

	case "list":
		list, err := store.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture échouée: %v\n", err)
			os.Exit(1)
		}
		if len(list) == 0 {
			fmt.Println("Aucun token.")
			return
		}
		fmt.Printf("%-12s  %-20s  %-7s  %-10s  %s\n", "ID", "NOM", "RÔLE", "STATUT", "CRÉÉ")
		fmt.Println(strings.Repeat("-", 72))
		for _, t := range list {
			status := "actif"
			if t.Revoked {
				status = "révoqué"
			} else if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
				status = "expiré"
			}
			fmt.Printf("%-12s  %-20s  %-7s  %-10s  %s\n",
				t.ID, t.Name, t.Role, status, t.CreatedAt.Format("2006-01-02"))
		}

	case "revoke":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "usage: goproxify core token revoke <id>")
			os.Exit(1)
		}
		id := os.Args[4]
		if err := store.Revoke(id); err != nil {
			fmt.Fprintf(os.Stderr, "révocation échouée: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token %s révoqué.\n", id)

	case "help":
		fmt.Print(`Usage: goproxify core token <sous-commande> [options]

Gestion des tokens d'authentification locaux du Core.
Ces tokens contrôlent qui peut appeler l'API interne du Core (port 8000).

Sous-commandes :
  create   Génère un nouveau token (défaut si omis)
  list     Liste tous les tokens
  revoke   Révoque un token

goproxify core token create -name <nom> [-role admin|agent] [-ttl <durée>]
  -name   Nom descriptif (ex: "admin-prod", "agent-docker-1")
  -role   Rôle : admin (push routes/certs) | agent (heartbeat/containers) — défaut: agent
  -ttl    Durée de validité (ex: 24h, 7d) — défaut: permanent

goproxify core token list

goproxify core token revoke <id>
  id   Identifiant du token (affiché par 'list')

Variables d'environnement :
  GPX_CORE_TOKENS_PATH  Chemin vers la base SQLite (défaut: /etc/goproxify/core-tokens.db)
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande core token inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify core token help")
		os.Exit(1)
	}
}

func runAgent() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "pair":
		runAgentPair()
	case "approve":
		runAgentApprove()
	case "help":
		fmt.Print(`Usage: goproxify agent [sous-commande] [options]

Sans sous-commande : démarre le service Agent.

Sous-commandes :
  pair     Configure l'appairage WS Agent→Core (JOIN_TOKEN)
  approve  Approuve un Agent en attente depuis la CLI

goproxify agent [-config <chemin>]
  -config   Chemin vers agent.json (défaut: ./internal/agent/config.json)

goproxify agent pair -core <url> -join-token <token>
  -core        URL du Core (ex: http://goproxify-core:8000)
  -join-token  Token d'appairage généré par l'Admin (gpx_join_*)

goproxify agent approve <agent-id> [-admin-url <url>] [-token <token>]
  agent-id   Identifiant de l'Agent à approuver (affiché dans l'UI Admin)
  -admin-url URL de l'Administration (ou GPX_CONTROLPLANE_ADMIN_ENDPOINT)
  -token     Token Admin (ou GPX_CONTROLPLANE_AUTH_TOKEN)

Workflow d'appairage WS :
  1. L'Admin génère un JOIN_TOKEN (UI → Agents → Nouveau token)
  2. goproxify agent pair -core http://core:8000 -join-token gpx_join_xxx
  3. goproxify agent  →  l'Agent se connecte en WS, statut "pending"
  4. goproxify agent approve <agent-id>  (ou approuver dans l'UI)
  5. L'Agent reçoit un secret HMAC et passe en statut "approved"
`)
	default:
		runAgentService()
	}
}

func runAgentService() {
	args := parseFlags(os.Args[2:])
	cfg, err := config.LoadAgent(configPath("agent", args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur config agent : %v\n", err)
		os.Exit(1)
	}

	ag, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialisation agent : %v\n", err)
		os.Exit(1)
	}
	buildinfo.LogBanner(slog.Default(), "agent", VersionAgent)
	tz.LogStartup(slog.Default())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := ag.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "démarrage agent : %v\n", err)
		os.Exit(1)
	}
	<-ctx.Done()
	ag.Stop(context.Background())
}

// runAgentPair affiche la configuration WS à injecter dans agent.json ou en variables d'env.
func runAgentPair() {
	args := parseFlags(os.Args[3:])
	coreURL := flagValue(args, "-core", "")
	joinToken := flagValue(args, "-join-token", "")
	if coreURL == "" || joinToken == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify agent pair -core <url> -join-token <token>")
		fmt.Fprintln(os.Stderr, "       -core        URL du Core (ex: http://goproxify-core:8000)")
		fmt.Fprintln(os.Stderr, "       -join-token  Token d'appairage généré par l'Admin (gpx_join_*)")
		os.Exit(1)
	}
	if !strings.HasPrefix(joinToken, "gpx_join_") {
		fmt.Fprintln(os.Stderr, "avertissement : le token ne commence pas par 'gpx_join_' — vérifiez qu'il s'agit d'un JOIN_TOKEN Agent")
	}
	fmt.Printf("Configuration de l'appairage WS Agent→Core\n\n")
	fmt.Printf("Option A — fichier agent.json (section control_plane) :\n")
	fmt.Printf("  {\n")
	fmt.Printf("    \"control_plane\": {\n")
	fmt.Printf("      \"core_endpoint\": %q,\n", coreURL)
	fmt.Printf("      \"join_token\":    %q\n", joinToken)
	fmt.Printf("    }\n")
	fmt.Printf("  }\n\n")
	fmt.Printf("Option B — variables d'environnement :\n")
	fmt.Printf("  GPX_CONTROL_PLANE_CORE_ENDPOINT=%s\n", coreURL)
	fmt.Printf("  GPX_CONTROL_PLANE_JOIN_TOKEN=%s\n\n", joinToken)
	fmt.Printf("Démarrez ensuite l'Agent : goproxify agent\n")
	fmt.Printf("L'Agent apparaîtra en statut 'pending' dans l'UI Admin.\n")
	fmt.Printf("Approuvez-le via l'UI ou : goproxify agent approve <agent-id>\n")
}

// runAgentApprove approuve un Agent en attente via l'API Admin.
func runAgentApprove() {
	if len(os.Args) < 4 || strings.HasPrefix(os.Args[3], "-") {
		fmt.Fprintln(os.Stderr, "usage: goproxify agent approve <agent-id> [-admin-url <url>] [-token <token>]")
		os.Exit(1)
	}
	agentID := os.Args[3]
	args := parseFlags(os.Args[4:])
	adminURL := flagValue(args, "-admin-url", os.Getenv("GPX_CONTROLPLANE_ADMIN_ENDPOINT"))
	tok := flagValue(args, "-token", os.Getenv("GPX_CONTROLPLANE_AUTH_TOKEN"))
	if adminURL == "" {
		fmt.Fprintln(os.Stderr, "erreur : -admin-url ou GPX_CONTROLPLANE_ADMIN_ENDPOINT requis")
		os.Exit(1)
	}
	if tok == "" {
		fmt.Fprintln(os.Stderr, "erreur : -token ou GPX_CONTROLPLANE_AUTH_TOKEN requis")
		os.Exit(1)
	}

	url := strings.TrimRight(adminURL, "/") + "/api/v1/agents/" + agentID + "/approve"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur requête : %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur appel Admin : %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		fmt.Fprintf(os.Stderr, "erreur Admin (%d) : %s\n", resp.StatusCode, body)
		os.Exit(1)
	}
	fmt.Printf("Agent %q approuvé. Il recevra son secret HMAC à la prochaine connexion WS.\n", agentID)
}

// -----------------------------------------------------------------------------
// landing — page de présentation
// -----------------------------------------------------------------------------

func runLanding() {
	args := parseFlags(os.Args[2:])
	cfg, err := config.LoadLanding(configPath("landing", args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur config landing : %v\n", err)
		os.Exit(1)
	}

	logger := slog.Default()
	buildinfo.LogBanner(logger, "landing", VersionLanding)
	srv := landing.New(cfg, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "démarrage landing : %v\n", err)
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// update — mise à jour des images Docker via l'Agent
// -----------------------------------------------------------------------------

func runUpdate() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "check":
		// goproxify update check [-container <nom>]
		args := parseFlags(os.Args[3:])
		container := flagValue(args, "-container", "")
		_ = container
		// TODO: appel Agent → comparaison digest local vs registre
		fmt.Println("[update] check — non encore implémenté")

	case "apply", "":
		// goproxify update apply [-container <nom>] [-all] [-prune] [-dry-run]
		args := parseFlags(os.Args[3:])
		container := flagValue(args, "-container", "")
		_, all := args["-all"]
		_, prune := args["-prune"]
		_, dryRun := args["-dry-run"]
		if container == "" && !all {
			fmt.Fprintln(os.Stderr, "usage: goproxify update apply -container <nom> | -all [-prune] [-dry-run]")
			os.Exit(1)
		}
		// TODO: pull + recréation du conteneur, rollback si non healthy
		fmt.Printf("[update] apply — container: %q, all: %v, prune: %v, dry-run: %v — non encore implémenté\n",
			container, all, prune, dryRun)

	case "rollback":
		// goproxify update rollback -container <nom>
		args := parseFlags(os.Args[3:])
		container := flagValue(args, "-container", "")
		if container == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify update rollback -container <nom>")
			os.Exit(1)
		}
		// TODO: retour à l'image précédente
		fmt.Printf("[update] rollback %s — non encore implémenté\n", container)

	case "help":
		fmt.Print(`Usage: goproxify update <sous-commande> [options]

Sous-commandes :
  check     Vérifie si des mises à jour d'images sont disponibles
  apply     Applique les mises à jour (défaut si omis)
  rollback  Revient à l'image précédente d'un conteneur

goproxify update check [-container <nom>]
  -container  Nom du conteneur à vérifier (défaut: tous les conteneurs goproxify)

goproxify update apply -container <nom> | -all [-prune] [-dry-run]
  -container  Nom du conteneur à mettre à jour
  -all        Met à jour tous les conteneurs goproxify
  -prune      Supprime les images orphelines après mise à jour réussie
  -dry-run    Affiche ce qui serait fait sans l'appliquer

goproxify update rollback -container <nom>
  -container  Nom du conteneur à restaurer (image précédente)

Note : les mises à jour automatiques se configurent via les labels Docker :
  goproxify.update.auto: "true"
  goproxify.update.schedule: "0 3 * * *"
  goproxify.update.prune: "true"
  goproxify.update.rollback_timeout: "60s"
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande update inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify update help")
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// status — état du cluster
// -----------------------------------------------------------------------------

func runStatus() {
	args := parseFlags(os.Args[2:])
	adminURL := flagValue(args, "-admin-url", os.Getenv("GPX_CONTROLPLANE_ADMIN_ENDPOINT"))
	tok := flagValue(args, "-token", os.Getenv("GPX_CONTROLPLANE_AUTH_TOKEN"))
	_, short := args["-short"]

	if adminURL == "" || tok == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify status [-admin-url <url>] [-token <token>] [-short]")
		fmt.Fprintln(os.Stderr, "       -admin-url  URL de l'Admin (ou GPX_CONTROLPLANE_ADMIN_ENDPOINT)")
		fmt.Fprintln(os.Stderr, "       -token      Token d'accès (ou GPX_CONTROLPLANE_AUTH_TOKEN)")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(path string, out any) error {
		req, err := http.NewRequest(http.MethodGet, strings.TrimRight(adminURL, "/")+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("HTTP %d : %s", resp.StatusCode, b)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}

	// Nœuds (Cores + Agents HTTP)
	type Node struct {
		NodeName   string  `json:"node_name"`
		Role       string  `json:"role"`
		Version    string  `json:"version"`
		Endpoint   string  `json:"endpoint"`
		Status     string  `json:"status"`
		CPUPct     float64 `json:"cpu_pct"`
		MemPct     float64 `json:"mem_pct"`
		LastSeenAt string  `json:"last_seen_at"`
	}
	var nodes []Node
	if err := get("/api/v1/nodes", &nodes); err != nil {
		fmt.Fprintf(os.Stderr, "erreur lecture nœuds : %v\n", err)
		os.Exit(1)
	}

	// Agents WS (pending / approved)
	type AgentInfo struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		SeenAt string `json:"seen_at"`
	}
	var wsAgents []AgentInfo
	_ = get("/api/v1/agents", &wsAgents) // non fatal si endpoint absent

	if short {
		fmt.Printf("nœuds: %d  agents-ws: %d\n", len(nodes), len(wsAgents))
		return
	}

	// Affichage nœuds
	fmt.Printf("Nœuds (%d)\n", len(nodes))
	fmt.Printf("  %-24s  %-8s  %-10s  %-8s  %5s  %5s  %s\n", "NOM", "RÔLE", "STATUT", "VERSION", "CPU%", "MEM%", "ENDPOINT")
	fmt.Printf("  %s\n", strings.Repeat("─", 85))
	for _, n := range nodes {
		fmt.Printf("  %-24s  %-8s  %-10s  %-8s  %4.1f%%  %4.1f%%  %s\n",
			n.NodeName, n.Role, n.Status, n.Version, n.CPUPct, n.MemPct, n.Endpoint)
	}

	// Affichage agents WS
	pending := 0
	for _, a := range wsAgents {
		if a.Status == "pending" {
			pending++
		}
	}
	fmt.Printf("\nAgents WS (%d", len(wsAgents))
	if pending > 0 {
		fmt.Printf(" — %d en attente d'approbation", pending)
	}
	fmt.Printf(")\n")
	if len(wsAgents) == 0 {
		fmt.Printf("  Aucun Agent connecté via WebSocket.\n")
	} else {
		fmt.Printf("  %-32s  %-10s  %s\n", "NOM / ID", "STATUT", "VU LE")
		fmt.Printf("  %s\n", strings.Repeat("─", 65))
		for _, a := range wsAgents {
			name := a.Name
			if name == "" {
				name = a.ID
			}
			status := a.Status
			if status == "pending" {
				status = "⚠ pending"
			}
			fmt.Printf("  %-32s  %-10s  %s\n", name, status, a.SeenAt)
		}
		if pending > 0 {
			fmt.Printf("\n  Pour approuver : goproxify agent approve <agent-id> -admin-url %s -token <token>\n", adminURL)
		}
	}
}

// -----------------------------------------------------------------------------
// Utilitaires de parsing
// -----------------------------------------------------------------------------

// subcommand retourne os.Args[idx] s'il existe et ne commence pas par '-'.
func subcommand(args []string, idx int) string {
	if idx < len(args) && len(args[idx]) > 0 && args[idx][0] != '-' {
		return args[idx]
	}
	return ""
}

// parseFlags construit une map clé→valeur depuis une liste d'args style "-key value" ou "-flag".
func parseFlags(args []string) map[string]string {
	m := make(map[string]string)
	for i := 0; i < len(args); i++ {
		if len(args[i]) > 0 && args[i][0] == '-' {
			if i+1 < len(args) && (len(args[i+1]) == 0 || args[i+1][0] != '-') {
				m[args[i]] = args[i+1]
				i++
			} else {
				m[args[i]] = ""
			}
		}
	}
	return m
}

// flagValue retourne la valeur d'un flag ou le défaut.
func flagValue(args map[string]string, key, def string) string {
	if v, ok := args[key]; ok && v != "" {
		return v
	}
	return def
}

// configPath retourne le chemin vers le fichier de config selon -config ou le défaut.
func configPath(component string, args map[string]string) string {
	if v := flagValue(args, "-config", ""); v != "" {
		return v
	}
	return fmt.Sprintf("./internal/%s/config.json", component)
}
