# Portail Access — guide opérateur

Le portail Access offre aux utilisateurs finaux un accès SSH / shell aux backends, avec authentification 2FA et sessions à durée limitée (TTL). Ce guide couvre l'installation, la configuration SMTP et le cycle de vie des comptes.

## Prérequis

- GoProxify Admin + au moins une passerelle en fonctionnement
- Serveur SMTP accessible depuis l'Admin (requis pour les invitations par email)
- Optionnel : domaine dédié (ex. `access.example.com`) pointant vers la passerelle concernée

## Configuration SMTP

L'envoi d'invitations repose sur la configuration SMTP globale.

Dans l'Admin → **Paramètres → SMTP** :

| Champ | Exemple |
|---|---|
| Hôte | `smtp.example.com` |
| Port | `587` |
| Utilisateur | `noreply@example.com` |
| Mot de passe | (secret) |
| TLS | STARTTLS recommandé |
| Expéditeur | `"GoProxify Access" <noreply@example.com>` |

Tester la configuration avec le bouton **Envoyer un email test** avant d'inviter des utilisateurs.

## Inviter un utilisateur

1. Admin → **Access → Users** → bouton **Inviter**
2. Saisir l'email, les tags optionnels, et choisir la passerelle d'hébergement
3. L'utilisateur reçoit un lien d'activation valable 24 h
4. À l'activation, il choisit son mot de passe et configure le 2FA (TOTP ou clé passkey)

Pour renvoyer une invitation expirée : icône ✉ dans la table, colonne Actions.

## Cycle de vie des comptes

| Statut | Description |
|---|---|
| `invited` | Invitation envoyée, compte non activé |
| `active` | Compte opérationnel, accès autorisé |
| `disabled` | Accès révoqué sans suppression (conservation des logs) |

Changer le statut : bouton édition (crayon) → sélecteur **Status**.

Supprimer définitivement : bouton corbeille. Les sessions actives sont terminées immédiatement.

## Sessions et TTL

Chaque session Access a une durée maximale configurable par passerelle :

- Admin → **Nodes** → passerelle cible → **Access → Session TTL**
- Par défaut : 8 h
- Minimum : 15 min, maximum : 7 jours

L'utilisateur peut fermer sa session avant expiration via le bouton **Déconnexion** du portail.

## Tags et filtres

Les tags permettent de segmenter les utilisateurs (ex. `prod`, `ops`, `readonly`).  
Ils sont visibles dans les logs d'accès et utilisables dans les règles RBAC.

Filtrer par tag dans la vue Users : champ de recherche libre.

## Supervision

- Logs d'accès : Admin → **Logs** → filtre `source=access`
- Sessions actives : Admin → **Access → Sessions** (durée restante, IP client, hôte cible)
- Métriques Prometheus : `gpx_access_sessions_active`, `gpx_access_logins_total`

## Sécurité

- Le 2FA est obligatoire pour tous les comptes Access (non contournable depuis l'UI)
- Les tokens de session sont signés HS256, rotation automatique à chaque reconnexion
- L'accès SSH est limité aux hôtes déclarés dans le catalogue de la passerelle (`Access → Catalogue`)
- Les IP bannies par Sentinel bloquent également l'accès au portail
