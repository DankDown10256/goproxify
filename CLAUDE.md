# GoProxify — instructions Claude

## Branche de travail

Travailler **directement sur `main`** — ne pas créer de branche de feature, ne pas ouvrir de PR sauf si le user le demande explicitement.

```
git checkout main && git pull origin main
# ... modifications ...
git push origin main
```

## Stack

- Go 1.22+, module `github.com/vincamok/goproxify`
- Stockage proxies : YAML (`internal/core/proxystore/`) — lire/écrire via `proxystore.Store`
- UI admin : Vanilla JS sans framework (`internal/admin/ui/src/js/`)
- Images Docker depuis Harness artifact registry, services dans `services/`

## Conventions

- Pas de commentaires sauf si le WHY est non-obvious
- Pas de gestion d'erreur pour des cas impossibles
- Tests dans le même package (`_test.go`)

## Règle de documentation obligatoire (après chaque changement)

Après **tout** changement (feature, bugfix, refacto), vérifier et mettre à jour si nécessaire :

> **`versions.json` — PATCH géré par le CI Harness** (`bump_version` stage).
> Ne pas bumper le PATCH manuellement : le pipeline le fait automatiquement à chaque push selon les chemins modifiés.
> Bumper le **MINOR manuellement** uniquement pour une nouvelle feature (le CI ne bumpe que le PATCH).

1. **`suivi/changelog.md`** — entrée dans `[Unreleased]` (MAJOR.MINOR.PATCH)
2. **`versions.json`** — MINOR uniquement si nouvelle feature (PATCH = CI) ; services concernés uniquement
3. **`suivi/roadmap-public.md`** — marquer livré ou ajouter si prévu
4. **`docs/fonctionnalites.md`** — ajouter la fonctionnalité si nouvelle
5. **`docs/api_specs.md`** — documenter tout nouvel endpoint ou modification d'API
6. **`docs/mcp.md`** — mettre à jour si un outil MCP est ajouté ou modifié
7. **`docs/cli.md`** — mettre à jour si une commande CLI est ajoutée ou modifiée
8. **`README.md`** — mettre à jour si la feature est visible utilisateur
9. **`internal/landing/ui/index.html`** — mettre à jour si la feature mérite d'être mise en avant
10. **Moteur CLI** (`cmd/goproxify/`) — ajouter subcommandes si nouvelle ressource API exposée
11. **Moteur MCP** (`internal/admin/mcp/server.go`) — ajouter outils si nouvelle ressource interrogeable par IA

Cette règle est **non-négociable** : ne pas clore une tâche sans avoir fait ce audit.
