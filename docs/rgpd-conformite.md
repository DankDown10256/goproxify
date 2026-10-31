# GoProxify — dossier de conformité RGPD (modèles pour l'opérateur)

> GoProxify est auto-hébergé : **l'opérateur est le responsable de traitement**. Ce dossier donne des modèles pré-remplis avec ce que le logiciel fait réellement (durées, données, destinataires) ; il ne remplace pas l'avis d'un juriste ou du DPO. Les cases `[à compléter]` dépendent de votre organisation. Le guide technique (réglages, API) est dans [rgpd.md](rgpd.md).

---

## 1. Registre des traitements (Art. 30) — modèle

Un enregistrement par finalité. Les durées sont les **défauts** d'une installation neuve ; elles se règlent (page **Logs** → réglages, `PUT /api/v1/logs/settings`).

### 1.1 Journalisation des accès au service

| Rubrique | Contenu |
|---|---|
| Responsable | `[à compléter : organisation, contact, DPO]` |
| Finalités | Sécurité du service (détection d'attaques, bans), exploitation (diagnostic, performance), preuve en cas d'incident |
| Base légale | Intérêt légitime (Art. 6-1-f) : sécurité du système d'information. Mise en balance à documenter `[à compléter]` |
| Personnes | Visiteurs des services publiés derrière la passerelle |
| Données | Adresse IP, date, méthode, domaine, chemin, code de réponse, taille, durée, User-Agent, Referer, empreintes TLS (JA3/JA4), catégories WAF déclenchées, identifiant de requête. **Jamais** : corps de requête ou de réponse, cookies, en-têtes d'autorisation |
| Destinataires | Comptes de l'Admin disposant du scope `logs:read`, dans la limite de leurs équipes. Aucun tiers |
| Durée | Sur l'Admin : 90 jours dans sa base (`retention_access_days`) pour les lignes signalées par le WAF ou Ephor, et 365 jours (90 pour les logs système, durées fixes pour l'instant) dans son volume de logs, qui range tous les accès de chaque passerelle (Admin `0.213.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)). Sur la passerelle : tant que l'Admin ne range pas ses lignes, 365 jours dans sa base de logs; dès qu'il les range et les acquitte, sa base n'est qu'un tampon (une période acquittée est supprimée 7 jours après sa fin, une période non acquittée après 30 jours : `engine.log_buffer_days` et `engine.log_buffer_max_days`, Edge `0.128.0`) (réglable depuis la page Logs › réglages, valeur commune ou par passerelle, Admin `0.183.0` ; à défaut `engine.log_retention_days` d'`edge.json`). Maximum recommandé par la CNIL : 13 mois |
| Protection des IP | Entières (défaut), anonymisées ou pseudonymisées (AES-GCM) : voir [rgpd.md](rgpd.md) |
| Transferts hors UE | Aucun par défaut |
| Mesures de sécurité | Voir §5 |

### 1.2 Bans d'adresses IP (Fail2Ban, Ephor, WAF, CrowdSec)

| Rubrique | Contenu |
|---|---|
| Finalité | Bloquer les sources d'attaques avérées |
| Base légale | Intérêt légitime (sécurité) |
| Données | Adresse IP, motif, source du ban, date, expiration ; historique des bans et débans |
| Destinataires | Administrateurs ; **CrowdSec** (si le *bouncer* est activé par l'opérateur : l'IP est interrogée auprès de leur API) |
| Durée | Ban actif : jusqu'à son expiration. Historique et bans expirés : 365 jours (`retention_ban_days`) |
| Transferts | Uniquement si CrowdSec est activé : consulter leur documentation |

### 1.3 Géolocalisation des IP (carte Prism, filtre par pays)

| Rubrique | Contenu |
|---|---|
| Finalité | Lecture des attaques par pays et par ville ; règles par pays |
| Base légale | Intérêt légitime |
| Données | IP → pays, ville, région, coordonnées approximatives (cache `geoip_cache`) |
| Durée | Celle des logs d'accès (90 jours) |
| Transferts | **Aucun par défaut** : base MaxMind GeoLite2 locale, aucune IP n'en sort. Le repli sur le service tiers `ip-api.com` (HTTP, hors UE) est **désactivé par défaut** ; `geoip.allow_external_lookup: true` dans `admin.json` l'active (à éviter, voir [rgpd.md](rgpd.md)) |

### 1.4 Comptes d'administration

| Rubrique | Contenu |
|---|---|
| Finalité | Authentifier et tracer les administrateurs |
| Base légale | Intérêt légitime / exécution du contrat avec l'opérateur `[à adapter]` |
| Données | E-mail, rôle, équipes, empreinte bcrypt du mot de passe, secrets MFA, sessions (JWT), adresse IP de connexion dans le journal d'audit |
| Durée | Compte : jusqu'à suppression. Journal d'audit : 90 jours |
| Destinataires | Super-administrateurs. Les actions d'un compte restent attribuées à son identifiant |

### 1.5 Portail d'accès (SSH, web, Docker) — si utilisé

| Rubrique | Contenu |
|---|---|
| Finalité | Accès privilégiés tracés aux systèmes internes |
| Base légale | Intérêt légitime (sécurité) ; information préalable des utilisateurs obligatoire `[à compléter]` |
| Données | Identité du compte (OIDC/local), cible, durée, journal des connexions. **Enregistrement des sessions** (sortie du terminal, jamais la saisie) : désactivé par défaut |
| Durée | Enregistrements : 90 jours par défaut (`record_retention_days`) ; `-1` pour une conservation illimitée, à justifier |
| Secrets | Identifiants et clés du coffre : chiffrés AES-GCM sur la passerelle, jamais envoyés à l'Admin |

### 1.6 Intégrations choisies par l'opérateur

Canaux d'alerte (e-mail, Slack, ntfy…), ACME (nom de domaine seulement), fournisseurs DNS, SSO (OIDC/SAML/LDAP) : voir [rgpd.md §4](rgpd.md). Chacun est un sous-traitant ou un destinataire à inscrire au registre avec son contrat (Art. 28) `[à compléter]`.

---

## 2. Analyse d'impact (AIPD) — pré-analyse

Une AIPD est exigée quand le traitement est « susceptible d'engendrer un risque élevé » (Art. 35). Pour la journalisation d'un proxy inverse, la CNIL ne la rend pas systématique ; elle devient probable si vous croisez les logs avec des identités (portail, SSO), si vous conservez longtemps ou si vous suivez des personnes à grande échelle.

| Question | Réponse pour une installation par défaut |
|---|---|
| Données sensibles (Art. 9) ? | Non collectées par le logiciel. Les chemins d'URL peuvent en contenir : c'est un risque résiduel `[évaluer]` |
| Surveillance systématique à grande échelle ? | Non par défaut. Oui possible si le service est très fréquenté : à apprécier `[à compléter]` |
| Croisement de données ? | Logs ↔ identité d'utilisateur (`user_id`) seulement avec une authentification de proxy ou le portail |
| Décision automatisée ayant un effet notable ? | Bans automatiques d'IP : effet limité (blocage d'accès à un service), réversible (déban, liste blanche) |
| Personnes vulnérables ? | `[selon vos services]` |

**Risques et mesures prévues** :

| Risque | Mesure fournie |
|---|---|
| Accès illégitime aux logs | Rôles, équipes et scopes ; lecture limitée aux administrateurs ; révélation d'IP réservée au super-administrateur et au rôle `dpo`, avec motif obligatoire et audit |
| Conservation excessive | Purge nocturne ; durées courtes par défaut ; bases de logs des passerelles purgées par fichier de période (365 jours, réglable) |
| Ré-identification | Anonymisation (irréversible) ou pseudonymisation (clé AES-GCM, empreinte HMAC pour l'effacement) |
| Perte de maîtrise des droits | Export d'accès (`logs subject-export`), effacement par IP ou par compte (`logs delete`), y compris sur les passerelles |
| Fuite via les sauvegardes | Chiffrement des sauvegardes (`GPX_BACKUP_KEY`), obligatoire si elles contiennent des données personnelles |

---

## 3. Notice d'information (Art. 13) — modèle à publier

> **Ce site est protégé par un reverse proxy GoProxify.** Pour assurer la sécurité du service, nous enregistrons, à chaque visite : votre adresse IP, la date et l'heure, la page demandée, le code de réponse, votre navigateur (User-Agent), la page d'origine (Referer) et une empreinte technique de la connexion TLS. Nous ne conservons ni le contenu de vos échanges ni vos cookies.
>
> **Pourquoi** : détecter et bloquer les attaques, diagnostiquer les incidents (intérêt légitime, Art. 6-1-f du RGPD).
> **Combien de temps** : `[90]` jours pour les journaux ; `[365]` jours pour l'historique des blocages d'adresses.
> **Qui y accède** : les administrateurs techniques de `[organisation]`. `[Mentionner tout sous-traitant ou service tiers activé.]`
> **Vos droits** : accès, rectification, effacement, opposition, limitation, dans les limites de l'intérêt légitime de sécurité. Écrivez à `[contact / DPO]`. En cas de désaccord, vous pouvez saisir la CNIL (cnil.fr).

---

## 4. Exercer les droits des personnes

| Droit | Comment, avec GoProxify |
|---|---|
| Accès (Art. 15) et portabilité (Art. 20) | `goproxify logs subject-export --by-ip <ip> --reason "…" --output export.json` ou `--by-user <id>` (`POST /api/v1/logs/subject-export`). L'export rassemble les logs, bans, historique des bans, position GeoIP, entrées d'audit et, pour un compte, son profil et ses équipes (jamais le mot de passe). Il est audité sans l'IP en clair |
| Effacement (Art. 17) | `goproxify logs delete --by-ip <ip> --reason "…"` : supprime les logs (pseudonymisés compris), les bans, l'historique des bans, l'entrée GeoIP, vide l'IP des entrées d'audit et efface les lignes de l'access log et l'historique de bans des **passerelles**, y compris celles hors ligne à ce moment (rejouée à leur reconnexion). Chaque passerelle joignable répond avec les lignes qu'elle a supprimées (accès, logs système, lignes pseudonymisées) : la réponse de l'Admin est la preuve passerelle par passerelle, et les passerelles qui n'ont pas répondu y figurent en attente |
| Effacement d'un compte | Supprimer le compte (page **Utilisateurs**) puis `goproxify logs delete --by-user <id>` pour ses logs. Le journal d'audit conserve les actions sous leur identifiant (obligation de traçabilité) |
| Rectification (Art. 16) | Sans objet pour des logs techniques ; un compte se modifie dans **Utilisateurs** |
| Opposition (Art. 21) | Appréciée au cas par cas : l'intérêt légitime de sécurité peut prévaloir. Si elle est acceptée : effacement, et liste blanche si l'IP ne doit plus être bannie |

**Ce que l'effacement ne couvre pas** (à traiter si la demande l'exige) : les sauvegardes déjà faites (elles expirent selon leur propre rotation), l'état en mémoire de Fail2Ban et d'Ephor sur les passerelles (il disparaît au redémarrage ou à l'expiration), les ordres de déban de la passerelle (table `unbans`, nécessaire pour ne pas reposer un ban levé), et les journaux d'un service tiers (CrowdSec, canaux d'alerte).

Réponse sous **un mois** (Art. 12-3), prolongeable de deux mois si la demande est complexe.

---

## 5. Violation de données (Art. 33 et 34) — procédure type

1. **Détecter** : journal d'audit (`GET /api/v1/audit`), alertes de sécurité, connexions inhabituelles au portail.
2. **Contenir** : désactiver ou supprimer le compte en cause, révoquer ses tokens API, changer les secrets exposés, couper l'accès concerné.
3. **Évaluer** : quelles données (IP, e-mails d'administrateurs, enregistrements du portail), combien de personnes, quel risque pour elles.
4. **Notifier la CNIL sous 72 h** après en avoir pris connaissance si la violation présente un risque pour les personnes (téléservice de notification de la CNIL) ; **informer les personnes** si le risque est élevé.
5. **Consigner** dans un registre des violations (même sans notification) `[à compléter]`.

Mesures de sécurité techniques (Art. 32) fournies : TLS partout, certificats en mémoire sur la passerelle, secrets du coffre chiffrés (AES-GCM), mots de passe bcrypt, MFA (TOTP, WebAuthn), JWT ECDSA, rôles et équipes, journal d'audit, sauvegardes chiffrées.

---

## 6. Liste de contrôle avant production

- [ ] Registre des traitements complété (§1) et à jour
- [ ] AIPD réalisée ou non-nécessité motivée (§2)
- [ ] Notice d'information publiée sur les services concernés (§3)
- [ ] Durées de conservation validées (page **Logs**) ; `geoip.allow_external_lookup` laissé à `false`
- [ ] Mode de protection des IP choisi (entières / anonymisées / pseudonymisées) et motivé
- [ ] Procédure de réponse aux demandes de droits connue de l'équipe (§4)
- [ ] Procédure de violation connue de l'équipe (§5)
- [ ] Contrats de sous-traitance (Art. 28) pour chaque service tiers activé
- [ ] Utilisateurs du portail informés de la journalisation et de l'enregistrement des sessions
