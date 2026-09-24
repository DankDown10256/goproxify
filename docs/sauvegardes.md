# Sauvegardes — comment et quoi

Ce document décrit le menu **Sauvegardes** de l'Administration : le fonctionnement des snapshots, leur contenu exact, ce qui est volontairement exclu, et le comportement à la restauration.

## 1. Fonctionnement

| Élément | Détail |
|---|---|
| Format | JSON (`.gpx-admin-backup`), champ `version: "1"` |
| Déclenchement | Manuel (bouton, CLI) ou planifié (jusqu'à **5 planifications** : quotidienne, hebdomadaire, mensuelle, annuelle, ou cron libre) |
| Stockage | Table `backup_snapshots` de la base Admin **et** copie `<storage.base_path>/backups/<id>.snap` sur disque (fallback si la base est illisible) |
| Rétention | Par planification (`retention` = nombre max de snapshots, 0 = illimité). Les snapshots manuels ne sont jamais purgés automatiquement |
| Chiffrement | AES-256-GCM si la variable `GPX_BACKUP_KEY` est définie (préfixe `GPXBK1:`). Sans clé, le snapshot est en clair (mais sans secrets, voir §4). Un snapshot chiffré ne peut être relu que si la même clé est définie |
| Import d'un fichier | Menu Sauvegardes → *Restaurer* : analyse (`/api/v1/import/backup/preview`), sélection des entités, application (`/api/v1/import/backup/apply`) |
| CLI | `goproxify backup create / list / restore` (voir [cli.md](cli.md)) |

## 2. Ce qui EST sauvegardé

### 2.1 Entités principales

| Entité | Contenu | Remarques |
|---|---|---|
| Proxies | Configuration complète de chaque proxy (route, TLS, WAF, headers…) + état activé | Restauration : republication vers les Cores |
| Utilisateurs | `id`, e-mail, rôle | **Sans mot de passe** (voir §3) |
| Tokens de nœuds | `id`, rôle, rôle RBAC, nom et endpoint du nœud, expiration | Secret **jamais** exporté ; tokens révoqués ignorés |
| Scopes de tokens | `token_scopes` | |
| PAT (tokens API utilisateur) | Hash, préfixe, libellé, scopes, expiration | Hash non réversible ; PAT révoqués ignorés |
| Snippets | Nom, type, config | |
| Canaux d'alerte | Nom, type, config, activé | Secrets vidés (§4) |
| Règles d'alerte | Scope, déclencheurs, canaux, cooldown, priorité, activé | |
| Nœuds déclarés | Topologie de l'assistant infrastructure | Les nœuds synthétiques `cfg:*` sont ignorés |

### 2.2 Tables de configuration (section `tables`)

Sauvegardées telles quelles (toutes colonnes), avec redaction des secrets.

| Domaine | Table | Contenu |
|---|---|---|
| Paramètres | `settings` | Paramètres clé/valeur (dont l'allowlist d'IP du MCP `mcp.allowed_ips`) |
| Sauvegardes | `backup_schedule` | Planifications |
| Sécurité | `fail2ban_config`, `crowdsec_config` | Configuration des moteurs IPS |
| Automatisation | `rules_engine_rules` | Règles automatiques (condition, action, cooldown, compteurs) |
| Domaines & certificats | `domains`, `cert_deploy_targets` | Domaines, délégation DNS, cibles de déploiement de certificats |
| Authentification | `auth_providers` | Fournisseurs OIDC / SAML / LDAP… |
| Réseau | `ip_profiles`, `node_tunnel_configs` | Profils IP (listes, feeds), tunnels de nœuds |
| Équipes & RBAC | `teams`, `team_members`, `team_scopes`, `team_scopes_v2`, `token_scopes_v2` | |
| Workspaces | `workspaces`, `workspace_members`, `workspace_resources` | |
| Pages | `error_page_templates`, `error_page_assets`, `portal_page_templates` | Les assets binaires sont encodés en base64 |
| Portail Access | `portal_destinations`, `portal_users` | Utilisateurs sans hash d'invitation |

## 3. Ce qui N'EST PAS sauvegardé (volontairement)

| Donnée | Raison |
|---|---|
| Mots de passe utilisateurs (hash) | À ne pas diffuser ; les comptes restaurés reçoivent un mot de passe aléatoire → réinitialisation nécessaire |
| MFA (`user_mfa`, codes de secours, appareils de confiance) | Secrets d'authentification ; à ré-enrôler |
| Secrets en clair (voir §4) | Snapshot potentiellement téléchargeable |
| Clés RGPD (`gdpr_keys`) | Clés de chiffrement : à sauvegarder séparément, hors snapshot |
| Logs, journal d'audit, historique de bans, menaces, CVE, alertes émises, événements de nœuds | Données d'état volumineuses, reconstituables |
| Historique d'exécution des règles automatiques, historique de déploiement de certificats | Historique |
| Certificats TLS et clés privées | Non inclus dans le snapshot Admin (voir cache chiffré du Core : `core-cache.gpx`) |
| Autres snapshots (`backup_snapshots`) et historique des proxies (`proxy_history`) | Éviter la récursivité ; l'historique a son propre mécanisme de restauration |
| Nœuds actifs / agents enregistrés (`nodes`, `pending_nodes`) | État dynamique ; les nœuds se ré-enregistrent |

> Les fichiers de configuration (`admin`, `core`, `agent:<nom>`) ne sont inclus que si la sauvegarde est générée avec `ExportConfigs` (section `configs`).

## 4. Gestion des secrets

À l'export, sont **vidés** (`""`) :
- le secret des tokens de nœuds ;
- dans les canaux d'alerte : `password`, `token`, `secret`, `api_key`, `app_token`, `user_token`, `webhook_url`, `authorization`, `private_key` ;
- dans les tables de configuration : toute clé JSON dont le nom contient `secret`, `password`, `passwd`, `token`, `api_key`, `apikey`, `private_key`, `credential`, `webhook_url` ou `authorization` (ex. `client_secret` OIDC, identifiants DNS) ;
- dans `settings`, `fail2ban_config`, `crowdsec_config` : la valeur de toute clé dont le nom correspond à ces motifs ;
- `portal_users.invite_token_hash`.

**Conséquence** : après une restauration sur une instance vierge, il faut ressaisir ces secrets (tokens de nœuds à ré-émettre, secrets OIDC, identifiants DNS, webhooks…). À la restauration, un secret vidé **n'écrase jamais** une valeur déjà présente.

## 5. Restauration

| Point | Comportement |
|---|---|
| Restauration d'un snapshot (bouton *Restaurer*) | Applique tout : utilisateurs, tokens, PAT, snippets, canaux, règles d'alerte, nœuds déclarés, tables de configuration ; en mode **overwrite** (les lignes existantes de même identifiant sont remplacées) ; proxies republiés vers les Cores ; planifications de sauvegarde rechargées |
| Snapshot de sécurité | Avant tout écrasement (restauration de snapshot ou import en `overwrite`), un snapshot `avant-restauration-<date>` / `avant-import-<date>` est pris automatiquement ; s'il échoue, l'opération est annulée. Il permet de revenir en arrière |
| Version | Une sauvegarde dont la `version` n'est pas `1` est refusée |
| Résultat | Compteurs par entité : proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, lignes de configuration, nœuds déclarés, ignorés, erreurs |
| Import d'un fichier (sélection) | Cases par entité : proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, **configuration** (identique dans *Sauvegardes → Restaurer*, *Import* et l'assistant de premier démarrage) ; conflit `skip` (conserver l'existant) ou `overwrite` |
| Utilisateurs | Créés avec un mot de passe aléatoire ; en overwrite, seul le rôle est mis à jour |
| Ordre | Les tables de configuration sont restaurées dans un ordre fixe (settings → règles → domaines → équipes → workspaces → pages → portail) |
| Tokens de nœuds | Le secret n'étant jamais sauvegardé, les tokens de nœuds sont **ignorés** (comptés « ignorés ») à la restauration : les nœuds doivent être ré-appairés |
| Anciennes sauvegardes | Sans section `tables` : restauration inchangée, la case *Configuration* n'apparaît pas |
| Colonnes inconnues | Ignorées (compatibilité entre versions) |

## 6. Recommandations

1. Définir `GPX_BACKUP_KEY` et la conserver **hors** du serveur.
2. Planifier au moins une sauvegarde quotidienne avec rétention ≥ 7.
3. Copier régulièrement `<storage.base_path>/backups/` hors de l'hôte.
4. Sauvegarder à part : clés RGPD, certificats/clés privées, et fichiers de configuration.
5. Tester une restauration sur une instance de test après tout changement majeur.
