# Changelog Goproxify

Toutes les modifications notables sont documentées ici.
Format : [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [Unreleased]

### Corrigé

- **Admin 0.41.1 — carte Leaflet par-dessus les modales** : les panneaux et contrôles de la carte (z-index jusqu'à 800) passaient devant la modale « Moteurs de sécurité » ; le conteneur de la carte forme désormais son propre contexte d'empilement.

- **Admin 0.36.1 — page Bans : nom affiché de la passerelle** : la colonne Passerelle, le filtre et la répartition affichaient le nom de nœud (`goproxify-core`) au lieu du nom affiché de la passerelle ; ils lisent maintenant `display_name` (`GET /nodes`), avec le nom de nœud en repli.

- **Admin 0.35.0 — indicateurs de bans : récidivistes et périmètre passerelle** : `GET /security/bans/intel/kpis` comptait toujours 1 (ou 0) IP récidiviste, car la requête `COUNT(DISTINCT ip) … GROUP BY ip HAVING` ne renvoyait que la première ligne ; elle compte maintenant les IP avec au moins 3 bans. La répartition « par passerelle » de l'Admin affichait « (global) » pour tous les bans (aucune passerelle n'était enregistrée).

- **Admin 0.34.0 — API CA interne : clés JSON en minuscules** : `GET /api/v1/internal-ca` et `.../{id}/certs` renvoyaient les champs Go bruts (`ID`, `Name`, `NotAfter`…) alors que la CLI (`goproxify internal-ca list-ca`) et l'UI lisaient `id`, `name`, `not_after` : les colonnes s'affichaient vides. Les structures portent maintenant leurs tags JSON (`id`, `name`, `subject`, `cert_pem`, `not_after`, `created_at`, `ca_id`, `common_name`, `usage`, `sans`, `serial`, `revoked`). Les sorties de l'outil MCP `list_internal_cas` changent de casse pour la même raison.

- **Admin 0.31.1 — page Sentinel : liste des détections refaite** : le tableau « Scénarios déclenchés » affichait des scénarios **CrowdSec** (`security_threats`), pas des détections Sentinel. Il est remplacé, avec les trois tuiles « Listes de détection », par un catalogue unique de toutes les détections du moteur (`ip`, `ua`, `path`, leurs variantes `custom_*`, `rate`, `error4xx`, comportement WAF, limite globale) : état, configuration, poids dans le score, effet (ban ou rejet 503) et nombre de bans actifs par détection, lus depuis le motif des bans Sentinel. Interface uniquement. Restent à reprendre : les tuiles « Menaces enregistrées », « IPs détectées, non bannies », « Décisions récentes » et « Top IPs », qui lisent encore les décisions CrowdSec.

- **Admin 0.29.2 — logs d'accès/système d'une passerelle vides** : le filtre par `node_id` excluait les logs sans `node_id` (ingestion HTTP, historique) ; ils sont désormais rattachés via `node_name`.

### Ajouté

- **Admin 0.48.0 — menu Automatisation refondu (4 entrées, onglets, éditeur de flux)** : le sous-menu passe à *Vue d'ensemble / Automatisations / Alertes / Journal*, le reste devient des onglets (Règles · Éditeur de flux · Modèles ; Canaux · Routage des alertes). Nouvelle vue d'ensemble (KPI, activité 24 h, dernières exécutions, bandeau d'échecs, raccourcis), nouvel **éditeur de flux** (règle lue comme Déclencheur → Garde-fou → Action → Notification, édition sur place, simulation par dry-run réel) et **Journal** filtrable (exécutées / échecs / condition vraie sans action / non remplie). Aucun changement d'API : tout repose sur `/rules-engine/*` et `/alert-channels`. Textes EN/FR/ES/DE.

- **Admin 0.47.0 — Logs système et Journal d'audit : périodes rapides, histogramme, tiroir de détail** : les mêmes ajouts que les logs d'accès. **Logs système** : puces de période et de niveau (warn, error), histogramme par niveau (nouvel endpoint `GET /logs/histogram`, mêmes filtres que la liste : niveau, composant, passerelle, domaine, recherche) et tiroir de détail (message complet, contexte, filtrer sur le composant ou le domaine, corréler, copier le message ou l'entrée en JSON). **Journal d'audit** : puces de période (1 h à 30 jours) et de gravité, histogramme par gravité (`GET /audit/histogram`), tiroir de détail (acteur, IP, ressource, détail JSON mis en forme ; filtrer sur l'acteur ou l'action, voir l'IP dans les logs d'accès, copier en JSON), et l'export CSV/JSON applique maintenant les filtres et la période de la page (jusqu'ici il exportait tout). L'histogramme est un composant partagé (`shared/hist.js`) utilisé aussi par les logs d'accès. Traductions EN, FR, ES, DE. Limites : l'histogramme des logs ne tient pas compte de la recherche libre côté logs d'accès ; le tiroir d'audit n'affiche pas de comparaison avant/après (le détail est celui enregistré). (Admin `0.47.0`)

- **Admin 0.46.0 — Logs d'accès : périodes rapides, histogramme, tiroir de détail** : au-dessus du tableau, des puces de période (15 min à 7 jours, ou tout) et de classe de statut (2xx à 5xx) posent les filtres de date et de statut existants ; un histogramme requêtes / erreurs (données de `GET /prism/timeline`, mêmes filtres domaine, IP, chemin et passerelle) permet de zoomer sur une tranche d'un clic. Un clic sur une ligne (tableau ou liste mobile) ouvre un tiroir : détail de la requête (heure, passerelle, composant, IP, latence, taille, identifiant de requête, message), réputation de l'IP (`GET /prism/ip-scan`) et actions : analyser dans Prism, corréler avec les logs système, filtrer sur l'IP ou le chemin, copier en cURL, bannir l'IP. Depuis l'Admin sans passerelle sélectionnée, le bouton Prism ouvre maintenant Prism pour toutes les passerelles au lieu de demander d'en choisir une. Traductions EN, FR, ES, DE. Limites : l'histogramme ne tient pas compte du filtre de statut ni de la recherche libre ; les logs système n'ont pas ces ajouts. (Admin `0.46.0`)

- **Admin 0.39.0 — Observabilité : Synthèse, Prism recentré, carte Leaflet et attaques en direct** : le menu Observabilité (Admin et passerelle) atterrit maintenant sur une **Synthèse** (`obs-synthese` / `edge-obs-synthese`, un seul composant dont seul le périmètre change : toutes les passerelles côté Admin avec sélecteur, passerelle verrouillée côté passerelle). Elle affiche les trois premières anomalies, six indicateurs avec tendance, la courbe requêtes/erreurs, les codes HTTP (avec le détail des codes, qui ouvre les logs filtrés), le tableau des passerelles (Admin : état, requêtes, erreurs, latence, un clic ouvre sa synthèse), les proxies à surveiller (classés par taux d'erreur), le top 5 des pays et les certificats à renouveler sous 30 jours. **Prism** : les cartes « Top p95 » et « Top taux d'erreur » sont retirées (remplacées par « Proxies à surveiller »), les onglets Composants / Bots et Référents sont fusionnés en **Sources**, l'onglet Bans est remplacé par un lien vers Sécurité › Bans, l'onglet Backends est retiré (le taux d'erreur par proxy est dans « Proxies à surveiller » de la Synthèse et les p95 par backend dans Métriques ; l'anomalie « Backend en difficulté » filtre Prism sur le proxy). La carte SVG est remplacée par une carte **Leaflet** (zoom, déplacement, modes Requêtes / Tx erreurs / IPs bannies, styles **Zones**, **Villes** et **Régions** (départements, provinces, États… de tous les pays), pulsation à la position de la ville pour chaque connexion en Live) ; le fond est fait des contours de pays embarqués, sans tuiles ni requête vers un tiers. Les blocs communs (indicateurs, courbe, codes HTTP, anomalies) vivent dans `shared/obs-widgets.js` et la carte dans `shared/geomap.js`. **Sécurité › Synthèse** : nouvelle carte « Attaques en direct » (erreurs et IPs bannies des 24 dernières heures, puis flux des événements `error` et `banned` toutes les 4 s avec pulsation sur la ville source). Backend : `geoip_cache` reçoit `lat`, `lon`, `city`, `region` (le résolveur les demande à ip-api.com et complète 100 IPs par minute pour les entrées déjà en cache) ; `GET /prism/geo/points` (trafic par ville) ; `GET /prism/anomalies` (les anomalies sont maintenant calculées côté serveur : pic d'erreurs, IP dominante, pays en erreur, backend en difficulté, part de bots) ; `GET /prism/live-ips` renvoie aussi `city`, `lat`, `lon` ; la requête de `GET /prism/backend-errors` passe dans le paquet `analytics` (réponse inchangée). Outils MCP `get_prism_anomalies` et `get_prism_geo` (scope `logs:read`) et commande `goproxify prism anomalies|geo`. Leaflet 1.9.4 (BSD-2), les contours de pays Natural Earth 50m (environ 540 Ko) et les régions Natural Earth 10m admin-1 (environ 2 Mo, servis compressés), domaine public, sont embarqués dans `internal/admin/ui/src/lib/` ; `scripts/gen_world_geojson.go` régénère les contours. Géolocalisation : l'Admin télécharge en arrière-plan la base **GeoLite2-City** (`geoip.auto_download`, `geoip.city_db_path`, `geoip.city_db_url`, environ 65 Mo) et résout alors les IPs hors ligne, sans rien envoyer à un tiers ; tant qu'elle est absente, ip-api.com reste le repli (les IPs lui sont envoyées, en HTTP). Limites : la position d'une IP est approximative (précision de l'ordre de la ville) ; le style « Villes » reste vide tant que les IPs déjà connues n'ont pas été complétées ; la vue « Régions » place chaque ville dans sa région d'après sa position (point dans polygone, sans dépendre des noms) : elle repose sur les 1 000 villes les plus actives et charge environ 2 Mo (500 Ko compressés) à la première utilisation ; les alertes et SLO, l'explorateur de logs et les autres idées de la maquette ne sont pas inclus ; les seuils d'anomalie sont fixes ; les libellés de Prism, des blocs partagés et de la carte sont traduits (EN, FR, ES, DE) ; depuis la Synthèse, un clic sur un point de la courbe ou sur « Zoomer » ouvre Prism sur la période de la tranche. **SLO** : la Synthèse affiche un SLO de disponibilité (5xx) sur 30 jours avec objectif au choix (99 à 99,99 %, enregistré côté serveur), budget d'erreur restant et vitesse de consommation sur 1 h et 6 h ; `GET /prism/slo` et outil MCP `get_prism_slo`. Nouveau déclencheur d'alerte **`slo_burn`** (« Budget d'erreur SLO consommé trop vite ») : toutes les 5 minutes, le moniteur évalue l'SLO à 99,9 % de la flotte puis de chaque passerelle ayant du trafic récent, et émet un événement `warning` (consommation ≥ 3× sur 6 h) ou `critical` (≥ 14,4× sur 1 h et ≥ 6× sur 6 h, ou budget épuisé) avec disponibilité, budget restant et consommation ; les règles existantes (canaux, périmètre par passerelle, délai de rappel) s'appliquent. L'objectif est un réglage serveur unique (`slo.target`, 99,9 % par défaut, modifiable par un administrateur depuis le sélecteur de la Synthèse ou par `PUT /prism/slo/config`) partagé par l'écran, l'API, le MCP et l'alerte ; `monitor.Config.SLOTarget` à 0 désactive l'alerte. (Admin `0.39.0`)

- **Admin 0.38.0 — Sécurité › Synthèse unique et fenêtre « Moteurs de sécurité »** : la Synthèse est un seul composant (`security-synthese.js`) pour l'Admin et les passerelles, qui remplace les deux anciennes pages. Elle affiche un score de sécurité en anneau, quatre indicateurs (bans actifs, menaces actives, CVE critiques, certificats), les pastilles d'état des moteurs, l'activité sur 24 h, les bans actifs par source, les menaces récentes, un classement d'exposition (passerelles côté Admin, backends côté passerelle), la posture (en-têtes, certificats) et la timeline de sécurité filtrable par type. L'icône réglages ouvre la fenêtre **Moteurs de sécurité** : un onglet par moteur avec un interrupteur général et un interrupteur par capacité, appliqué immédiatement. Sentinel (propre à la passerelle côté passerelle) : bannir les IP détectées (mode `block`/`detect`), listes d'IP, User-Agent, chemins, débit par IP, erreurs 4xx, limite globale, tarpit. Fail2Ban : activation, confiance en `X-Forwarded-For`, ban permanent, réglages avancés. CrowdSec : activation et réglages avancés. Règles automatiques (Admin) : activation de chaque règle. Scanner CVE : réseaux privés. Côté passerelle, Fail2Ban et CrowdSec étant globaux, l'onglet « Moteur IPS » choisit le fournisseur de la passerelle (natif, Fail2Ban, CrowdSec). Sur mobile (≤ 720 px), les indicateurs passent sur deux colonnes, la timeline et le classement s'empilent, et la fenêtre devient plein écran avec des onglets défilants et un bouton Fermer collé en bas. Interface uniquement, aucun changement d'API. Limites : le score de sécurité est calculé dans le navigateur (CVE ouvertes 50 %, en-têtes 30 %, certificats 20 %) ; réactiver une limite chiffrée de Sentinel jamais réglée applique une valeur par défaut (débit 10 req/s, erreurs 4xx 20, limite globale 1000 req/s). (Admin `0.38.0`)

- **Admin 0.37.0 — menu Sécurité en onglets, page Vulnérabilités en vue Parc / Liste** : l'entrée « Sécurité » de la sidebar (Admin et passerelle) n'a plus de sous-menu ; ses pages s'affichent en onglets sous la barre de titre : Synthèse, Vulnérabilités, Bans, Menaces (Admin seulement), Sentinel, En-têtes & certificats (l'ancienne « Posture », désormais aussi disponible côté Admin). Les onglets sont décrits dans `pageTabs` (`app.config.js`) et l'entrée de sidebar reste surlignée quel que soit l'onglet. La page Vulnérabilités est un seul composant pour l'Admin et une passerelle, avec deux affichages au choix (mémorisé) : **Parc**, une carte par passerelle côté Admin et par backend côté passerelle (score de risque sur 100, barre de gravité, compteurs par gravité ; un clic déplie les CVE), et **Liste**, tableau filtrable (recherche, gravité, statut, passerelle côté Admin). Un tiroir de détail affiche la description, le backend, les dates et les actions (corrigée, ignorer, rouvrir, fiche NVD) sans recharger la page. Sur mobile (≤ 900 px), le tiroir devient une feuille en bas d'écran, les indicateurs passent sur deux colonnes, les filtres de gravité défilent horizontalement et chaque ligne de la liste s'empile (CVE, score et statut, puis backend et passerelle) ; les grilles des pages Synthèse et Menaces s'adaptent aussi. Interface uniquement, aucun changement d'API. Limites : le score de risque est calculé côté navigateur (gravité CVSS des CVE ouvertes) ; exploitation connue (KEV), EPSS, version corrigée, SLA et affectation ne sont pas inclus car le scanner ne les fournit pas. (Admin `0.37.0`)

- **Admin 0.35.0 — page Bans unique pour l'Admin et les passerelles, rattachement des bans à leur passerelle** : les menus Bans de l'Admin (`security-bans`) et d'une passerelle (`edge-security-bans`) affichent le même composant (`bans.js`), qui remplace `renderAdminSecurityBans` et `renderSecurityBans`. Disposition : indicateurs (bans actifs, expirent sous 1 h, permanents, récidivistes, ratio déban/ban), frise des bans par heure sur 48 h, origine géographique, répartition par source, par passerelle (par domaine côté passerelle) et raisons fréquentes, puis la liste en trois onglets (Actifs, Historique, CrowdSec). La liste se filtre par recherche, source, durée (expire sous 1 h, temporaires, permanents, récidivistes) et, côté Admin, par passerelle ; un clic sur une barre de répartition applique le filtre. Actions par ligne en icônes (Prism, historique de l'IP, prolonger de 24 h, rendre permanent, lever le ban), et actions groupées sur une sélection (prolonger, rendre permanent, lever). Le bouton « Lever » devient une icône (cadenas ouvert). Côté passerelle, la passerelle est verrouillée : ses bans et les bans globaux sont demandés au serveur, et la colonne Passerelle laisse la place au domaine. Sur mobile (≤ 700 px), la liste passe en cartes, les grilles s'empilent et les icônes d'action font 38 px. Backend : `security_bans` et `security_ban_history` reçoivent une colonne `edge_name` (passerelle d'origine, vide = ban global), renseignée pour les bans remontés par une passerelle (Sentinel, Fail2Ban, CrowdSec, moteur de règles) ; `GET /security/bans` renvoie `edge_name` et accepte `edge` ; `active=false` renvoie les bans expirés ; `bans/countries`, `bans/export` et `bans/intel/*` acceptent `edge`. CLI `goproxify security bans list` : `-edge`, `-source`, `-active`. Outil MCP `list_security_bans` : paramètre `edge` et champ `edge_name`. Limites : les bans créés avant cette version n'ont pas de passerelle (affichés « Global ») ; un ban créé depuis l'Admin ou depuis le menu d'une passerelle reste global ; les bans par CIDR/ASN, la liste blanche et l'import de liste ne sont pas inclus. (Admin `0.35.0`)

- **Admin 0.34.0 — « Domaines & certificats » en vue unique, actions en bout de ligne, certificats locaux** : la page réunit dans une seule liste les certificats **publics** (ACME, importés) et **locaux** (émis par une CA interne), avec compteurs (total, valides, à renouveler, critiques, expirés), filtre Tous / Publics / Locaux et recherche. Chaque ligne porte ses actions à droite, aux mêmes positions : renouveler (réémettre pour un local, remplacer pour un import), déployer (télécharger la CA racine pour un local), détails, modifier, copier, télécharger, supprimer (révoquer pour un local). Le bouton **Ajouter** ouvre un assistant à trois choix — Public (formulaire de domaine existant), Local (émission par une CA interne avec rappel d'installer la CA racine), Importer. Les réglages ACME (e-mail, URL du répertoire), les fournisseurs DNS et les CA internes passent dans un **tiroir « Paramètres »**. Nouvel endpoint `GET /api/v1/certs/{domain}/pem` (certificat public uniquement, jamais la clé). Limites : pas d'historique par ligne, et « Déployer » n'existe pas pour les certificats locaux (ils ne sont pas dans la table `certs`). Sur mobile (≤ 700 px), chaque ligne s’empile : nom et statut en haut, les sept actions en pleine largeur dessous (cibles de 40 px), filtres et recherche sur toute la largeur, cartes de l’assistant sur une colonne, tiroir plein écran. CLI et MCP non modifiés (pas d’outil dédié au téléchargement du PEM pour l’instant). (Admin `0.34.0`)

- **Admin 0.33.0 — page Sentinel refondue en onglets avec tiroir de réglages, simulation avant enregistrement** : la page s'organise en trois onglets — **Vue d'ensemble** (bans actifs, bans sur 24 h, IP récidivistes, détection principale, puces de configuration cliquables dont l'état du tarpit, décisions récentes, IP récidivistes), **Détections** (catalogue complet avec, par détection, un bouton « Régler » et la part des bans actifs) et **Listes et exceptions** (listes de référence et leur rafraîchissement, listes personnalisées, liste blanche, lien vers les profils WAF). La modale de paramètres est remplacée par un **tiroir latéral** organisé en sections (Général, Détection, Anti-DDoS, Riposte, Listes, Exceptions) : la page reste visible et interactive pendant l'édition, et sur une passerelle membre d'un groupe HA le tiroir et l'en-tête rappellent que les réglages sont ceux du groupe. Les tuiles « Menaces enregistrées », « IPs détectées non bannies », « Décisions récentes » et « Top IPs », qui lisaient encore les décisions CrowdSec, sont reprises à partir des bans Sentinel (historique et actifs). Le tiroir embarque un bouton **Simuler** (1, 6 ou 24 h) qui rejoue les access logs contre la config en cours d'édition sans rien enregistrer : requêtes bloquées, faux positifs probables, IP et bans, avant/après. Nouvel endpoint `POST /api/v1/security/threat-config/simulate` (même moteur que l'outil MCP `simulate_sentinel_config`, désormais factorisé dans `api.SimulateSentinel`) et commande `goproxify security threat simulate`. Limite : l'état du tarpit affiché est sa configuration, pas le nombre de requêtes retenues en direct (compteur côté passerelle, pas remonté à l'Admin). (Admin `0.33.0`)

- **Prism — bans détaillés par source et technique, scan d'IP** : le panneau Bans ventile désormais les bans actifs par source (Fail2Ban, CrowdSec, Sentinel, manuel) puis par technique de détection (Sentinel : liste d'IP, User-Agent, chemin sensible, débit ; Fail2Ban : erreurs HTTP ; CrowdSec : scénario), avec un badge « Sentinel » explicite. Dans le tableau des IP, un bouton à icône re-scanne une IP (bans actifs, historique, décisions de menace, activité et chemins visés) dans un panneau latéral. Nouveaux endpoints `GET /prism/bans/breakdown` et `GET /prism/ip-scan`. (Admin `0.32.0`)

- **Prism — Analyse repensé en « centre de commande »** : barre de filtres collante (plage rapide 15 min ajoutée), KPI avec sparklines, grande carte du monde avec zoom moulinet, déplacement, recentrage, légende de dégradé et style Zones ou Bulles proportionnelles, panneau latéral « Anomalies détectées » (pic d’erreurs, IP dominante, pays ou backend en erreur, part de bots élevée, avec actions directes) et « Top pays » cliquable qui ouvre un détail du pays. Les tableaux (chemins, IP, bots, référents, pays, backends, bans) passent en onglets. Interface uniquement, aucune modification d’API. (Admin `0.31.0`)

- **Modale « Modifier le proxy » — navigation latérale et section WAF à part** : les onglets horizontaux laissent place à un menu à gauche regroupé par intention (Trafic, Sécurité, Fiabilité, Expert). Le WAF, auparavant enfoui dans Protection puis dans son sous-menu, devient une section de premier niveau : carte d'état avec interrupteur, choix du mode en deux cartes (Bloquer / Détecter), bandeau d'héritage du Edge, puis les **plateformes applicatives** en cartes cochables avec recherche, compteur, « Tout effacer » et détection automatique ; les réglages avancés (seuil, règles, analyse comportementale) sont repliés. Le menu affiche le nombre de plateformes sélectionnées. Changement d'interface uniquement : mêmes champs, même format de configuration, aucun changement d'API. (Admin `0.30.0`)

- **HA — le portail d'accès est partagé par le groupe, ses données sont répliquées entre passerelles, les bans circulent sans l'Admin (phases 2 et 3)** :
  - *Config par groupe (Admin)* : dans un groupe HA, la config du portail (options, destinations, utilisateurs invités) est **celle du groupe** — éditée une fois depuis n'importe quel membre, poussée à tous. L'activation reste une propriété du nœud (`config.portal` du wizard) : un membre sans portail reçoit la config **en attente** (`ha_standby`), charge le magasin sans écouter et réplique, prêt à prendre le relais. Migration au démarrage des données propres aux membres (config du premier membre, destinations en double retirées, désaccords signalés dans le log). Correctif de la phase 1 : l'UI désigne une passerelle par l'id de son token, qui peut différer de l'id de son nœud dans `architecture.json` — le groupe est maintenant retrouvé aussi par ce lien (avant, la config Sentinel d'un Core principal dont le token n'avait pas l'id du fichier était écrite sur la passerelle et non sur le groupe).
  - *Réplication du magasin du portail (Edge)* : comptes (partie Admin et partie mot de passe/2FA séparées pour qu'une resynchronisation Admin n'écrase jamais un mot de passe), coffres, cibles perso, favoris, et sessions web en option, échangés entre passerelles du groupe, **chiffrés (AES-256-GCM) par une clé de groupe** générée et scellée par l'Admin (chaque passerelle garde sa propre clé maître au repos). Fusion « dernier écrit gagne » par clé, estampilles uniques par magasin (convergence même à horloge identique), suppressions propagées, comptes SSO créés séparément sur chaque membre fusionnés. Envoi immédiat (250 ms) à chaque modification locale, tirage toutes les 15 s. L'audit reste local (l'Admin consolide).
  - *Sessions en option* : `ha_session_mode` = `sticky` (défaut, la session web reste sur la passerelle qui l'a émise, affinité à assurer sur le répartiteur) ou `shared` (sessions répliquées ; à choisir avec un DNS round-robin). Réglage dans la page Portail (UI), `goproxify access config set -ha-session-mode`, outil MCP `update_portal_config`. Limites : les tickets UUID one-shot (60 s) restent valables sur la passerelle qui les a émis ; les coffres des comptes SSO ne sont déchiffrables sur un autre membre que si `GPX_PORTAL_MASTER_KEY` est identique sur tous (avertissement journalisé sinon).
  - *Bans sans l'Admin (Edge)* : un ban décidé localement (Sentinel, Fail2Ban) est transmis aux passerelles pairs tout de suite, et chaque passerelle récupère les bans actifs de ses pairs à chaque cycle ; bans expirés, sans IP ou déjà connus ignorés, un ban reçu n'est jamais réémis. L'Admin reste le circuit principal.
  - Vérifié par tests (magasin : convergence dans les deux sens, resync Admin sans perte de mot de passe, suppressions, sessions sticky/shared, fusion SSO, chiffrement et clé de groupe ; HTTP entre deux passerelles : envoi immédiat, tirage, clé différente, pair hors groupe ; bans : diffusion, idempotence, non-réémission ; Admin : config/destinations/utilisateurs/migration par groupe). (Admin `0.29.0`, Edge `0.12.0`, Webapp `0.14.0`)

- **HA — la configuration de sécurité suit le groupe, et les listes de référence Sentinel sont synchronisées (phase 1)** : dans un groupe HA (`config.cluster` + `config.cluster_group` dans `architecture.json`), activer Sentinel sur une passerelle ne l'activait que sur elle. Désormais Sentinel (`threat-config`), le fournisseur IPS (`ips-provider`) et les timeouts HTTP/QUIC (`server-config`) sont **ceux du groupe** : édités une fois (clé `…:group:<nom>`), poussés à tous les membres, et rejoués à la connexion d'un membre qui les avait manqués (la config globale sert aussi de repli, elle n'était jamais renvoyée à la connexion). Lecture : groupe, puis valeur propre à la passerelle, puis globale. Au démarrage, un groupe sans valeur reprend celle du premier membre qui en avait une ; un désaccord entre membres est signalé dans le log et jamais écrasé. Le push de `server-config` visait auparavant toutes les passerelles quel que soit `?edge=` : il vise maintenant la portée demandée. Les listes de référence Sentinel (`ua.txt`, `paths.txt`, `ips.txt`) sont échangées entre passerelles pairs (endpoints `/internal/v1/threat-lists/export`, existants mais jamais appelés) : la plus récente l'emporte, les membres d'un groupe convergent. L'UI indique « réglages partagés par le groupe HA ha-1 : … » dans les pages Sécurité d'une passerelle membre (nouvel endpoint `GET /api/v1/architecture/groups`). Limites : les fichiers de ban restent diffusés par l'Admin (pas de circulation passerelle ↔ passerelle si l'Admin est indisponible) ; le portail (config, utilisateurs, sessions) reste par passerelle, phases suivantes. Vérifié sur un cluster docker de 3 passerelles déclarées dans `ha-1` : activation via `core-b` → les 3 la reçoivent, lecture identique sur chaque membre ; `core-c` arrêté pendant un changement puis redémarré reçoit la config du groupe à la reconnexion. (Admin `0.28.0`, Edge `0.11.0`, Webapp `0.13.1`)

- **Wizard — hôtes composés de plusieurs éléments, agents à plusieurs plateformes** : « Composer votre topologie » ne proposait pas d'ajouter un hôte (il se créait implicitement avec un nœud). Le wizard gagne un **bandeau d'hôtes** : une carte par hôte (couleur, nom, zone Internet / privé, région, rôles posés dessus, plateformes de ses agents), « + Ajouter un hôte » et un menu « + Ajouter un élément » (passerelle, agent, Admin) ; sélectionner un hôte ouvre ses réglages (nom, région, zone, éléments, suppression) et la carte de chaque nœud reprend la couleur de son hôte. Un sélecteur **Par rôle / Par hôte** (mémorisé, aussi dans la vue Infrastructure) bascule entre le schéma par niveaux et des cadres d'hôte qui contiennent leurs rôles. Un hôte peut porter plusieurs passerelles, plusieurs agents et l'Admin ; un agent porte une ou plusieurs plateformes (Portainer et K8s cumulables avec un runtime, Docker et Podman exclusifs sur un même agent car l'agent n'ouvre qu'un socket), ou l'on place un agent par plateforme sur le même hôte. La génération de Compose / `.env` / ligne de commande / ticket, qui ne prenait que la première passerelle et le premier agent de chaque hôte, couvre maintenant **tous les rôles de l'hôte** ; avec plusieurs passerelles ou agents sur l'hôte, les variables sont en ligne dans le Compose (pas de `.env` commun), et la pré-approbation à la demande vise chaque agent. Les « + Ajouter » des niveaux ajoutent un nœud à l'hôte sélectionné. (Admin `0.27.0`)

- **Infrastructure et wizard refondus autour d'un schéma d'architecture unique, lu depuis `architecture.json`** : la page Infrastructure (grilles de cartes + graphe SVG) et le wizard (toile d'hôtes + étape « Continuer / Déployer ») sont remplacés par un même schéma, de haut en bas : Internet, passerelles (cadre pointillé « Groupe HA » avec leader et quorum), Admin relié aux passerelles par un trait « gère » et accessible par l'administrateur, agents reliés en WebSocket, puis une synthèse (requêtes, nœuds en ligne, quorum HA, alerte). Chaque nœud est une carte (icône par rôle, statut, hôte, capacités, débit) avec une frise de disponibilité de la session. Le schéma est en HTML/CSS avec container queries : même page en colonne sur mobile ; le glisser-déposer HTML5 (inutilisable au toucher) disparaît au profit des boutons « + Ajouter ». Le modèle hôte → rôle → capacité n'est plus reconstruit par heuristique depuis la base : il vient du fichier d'architecture (`GET /api/v1/architecture`), qui porte désormais l'hôte de chaque nœud (`config.host`) ; l'état live (`/nodes`, `/nodes/live`) n'en est que la surcouche. Le wizard n'a plus qu'un bouton **Enregistrer** (écrit `architecture.json`) : la création des tickets d'installation et la pré-approbation des agents ne se font plus à l'enregistrement mais à la demande, dans l'onglet « Ticket d'installation ». Nouvelle modale **Configuration** (par hôte) : *Formats* (Compose, `.env`, ligne de commande, flux réseau, déclaré, ticket ; copier / télécharger), *Écarts* (déclaré contre ce que le nœud remonte) et *Versions* (les 50 versions de `architecture.json` : consulter, différences avec l'état courant, restaurer). Clic sur un nœud de la vue : détail et actions d'exploitation (trafic, réglages, mise à jour, retour arrière, rescan, conteneurs, événements, suppression). Limite : l'Admin ne conserve pas d'historique de statut par nœud, la disponibilité affichée est celle de la session en cours (échantillon toutes les 5 s), pas un pourcentage sur 30 jours. Nouveaux points d'accès : `GET /api/v1/architecture`, `GET /api/v1/architecture/versions/{name}`, `goproxify architecture show [-version]`, outil MCP `get_architecture` (scope `nodes:read`). Tests : lecture du fichier et d'une version sans restauration (nom hors format refusé), outil MCP. (Admin `0.27.0`)

- **HA / multi-Core — l'Admin connaît les Cores du groupe sans variable supplémentaire** : jusqu'ici un Core distant n'apparaissait dans l'Admin (et ne recevait proxies, certificats, Sentinel…) que si `GPX_CORE_EXTRA_ENDPOINTS` le listait, en doublon de `GPX_CLUSTER_PEERS` déjà renseigné sur les Cores (graphe : `backup` grisé, `cores_connectés: 1`). Deux mécanismes, sans nouvelle variable : (1) le heartbeat Core → Admin annonce désormais les pairs Raft du Core (`cluster_peers`) ; l'Admin en déduit l'endpoint de contrôle (même hôte, port `8000`), crée le token, enregistre le Core et l'écrit dans le fichier d'architecture ; un pair déjà connu (par nom, ou ayant déjà émis un heartbeat) n'est jamais dédoublé. (2) Au démarrage, l'Admin relit le fichier d'architecture **avant** toute resynchronisation depuis la base (`SyncFromDB` le réécrivait depuis SQLite) et reconnecte les Cores qui portent un `endpoint`, en réutilisant l'ID du nœud du fichier (les périmètres RBAC y sont liés). Vérifié sur un cluster docker de 3 Cores : l'Admin ne connaît que `core-a` au départ, `core-b` et `core-c` sont découverts au premier heartbeat (`cores_connectés: 3`) ; base SQLite et `node_tokens.json` supprimés, les 3 Cores sont reconnectés depuis le fichier seul, mêmes identifiants. La découverte demande un Core à jour (le heartbeat annonce les pairs) ; la relecture du fichier fonctionne avec l'Admin seul. (Admin `0.24.0`, Core `0.9.0`)

- **Métriques par proxy avec historique (`GET /api/v1/metrics/proxies`, outil MCP `get_proxy_metrics`, `goproxify proxy metrics`)** : l'Admin relève toutes les passerelles toutes les 10 s, calcule débit (req/s), taux d'erreurs 5xx et p95 sur l'intervalle (différence entre deux relevés, remise à zéro des compteurs détectée, passerelles additionnées) et garde 1 h de série par host en mémoire. Les vues « état » et « détail » de la page Trafic en tirent leurs indicateurs et leur courbe, qui ne sont donc plus vides à l'ouverture (elles le restent quelques secondes après un démarrage de l'Admin ; l'historique ne survit pas à un redémarrage). Scope PAT `metrics:read`. Tests : calcul des différences, remise à zéro, addition des passerelles, capacité et purge, relevé de bout en bout contre une passerelle simulée avec token chiffré. (Admin `0.27.0`, Passerelle `0.10.1`)

### Modifié

- **Admin 0.45.0 / Edge 0.17.0 — observation en direct et notification des demandes d'accès** : le bouton **Observer** de l'onglet Sessions ouvre un terminal en lecture seule qui suit la sortie de la connexion (`GET /api/v1/portal/sessions/{id}/watch`, flux SSE ; `goproxify access sessions watch`), avec la fin de sortie déjà émise à l'ouverture ; l'observation est journalisée côté Admin et côté portail. Une nouvelle demande d'accès temporaire envoie un email aux comptes admin et superadmin quand le SMTP est configuré. **Sécurité** : lire un enregistrement (`/portal/recordings/{id}`) ou observer une session exige désormais la portée `portal:write` pour un jeton d'accès personnel, car ces routes donnent le contenu d'un terminal (elles n'exigeaient que `portal:read`).

- **Admin 0.44.0 / Edge 0.16.0 — enregistrement et rejeu des sessions Access** : avec `record_sessions` dans la politique, la passerelle enregistre la sortie du terminal de chaque nouvelle session (asciicast v2, jamais la saisie), chiffrée au repos, limitée à 8 Mio par session, avec conservation réglable. Nouvel onglet **Enregistrements** : liste, lecteur intégré (pause, vitesse, barre de progression, pauses longues raccourcies) et suppression ; chaque lecture ou suppression est journalisée. `GET`/`DELETE /api/v1/portal/recordings`, API interne passerelle `/internal/v1/portal/recordings`, commandes `goproxify access recordings list|get|delete`, outils MCP `list_portal_recordings` et `delete_portal_recording`.

- **Admin 0.43.0 / Edge 0.15.0 — politiques d'accès Access** : nouvel onglet Politiques du portail avec plages horaires (jours, heures, fuseau), liste d'adresses IP autorisées (IP ou CIDR) et fermeture des sessions inactives (basée sur la saisie de l'utilisateur, pas sur la sortie du terminal). La passerelle refuse, avec audit, la connexion au portail, l'ouverture d'une session et la connexion SSH hors politique. `GET`/`PUT /api/v1/portal/policy`, commandes `goproxify access policy get|set`, outils MCP `get_portal_policy` et `set_portal_policy`. Le formulaire Réglages ne modifie plus la politique.

- **Admin 0.42.0 / Edge 0.14.0 — accès temporaires Access avec approbation** : depuis le portail, un utilisateur demande l'accès à une destination qu'il ne voit pas (motif et durée) ; l'Admin reçoit la demande par WebSocket (`portal_access_request`), la liste dans le nouvel onglet **Approbations** (approuver avec durée ajustable, refuser, révoquer, historique) et pousse les accès accordés à la passerelle, qui les applique jusqu'à leur échéance sans nouveau push. `GET /api/v1/portal/access-requests`, `POST …/{id}/approve|deny|revoke`, commandes `goproxify access requests …`, outils MCP `list_portal_access_requests` et `decide_portal_access_request`. La Synthèse affiche le nombre de demandes en attente.

- **Admin 0.41.0 / Edge 0.13.0 — sessions Access en direct** : nouvel onglet Sessions du portail (connexions SSH et web en cours, bouton Terminer, rafraîchissement automatique) ; `GET /api/v1/portal/sessions` et `DELETE /api/v1/portal/sessions/{id}`, commandes `goproxify access sessions list|terminate`, outils MCP `list_portal_sessions` et `terminate_portal_session`. La passerelle remonte l'instantané par WebSocket (`portal_live`) et exécute la fermeture (`kill_portal_session`). La Synthèse affiche le nombre de sessions en direct.

- **Admin 0.40.0 — menu Portail Access en onglets** : les 4 sous-menus (Catalogue, Users, Templates, Audit) deviennent des onglets d'une entrée unique : Synthèse (état, sessions actives, destinations, utilisateurs, échecs, derniers événements), Destinations, Utilisateurs, Modèles, Audit, Réglages (l'ancien formulaire d'options, route `portal-settings`).

- **Admin 0.38.1 — onglet Sécurité › Menaces retiré** : la page « Menaces » de l'Admin (`security-threats`) faisait doublon : la liste des menaces CrowdSec, avec ses filtres et ses tris, reste dans Bans › CrowdSec (même composant), et la timeline des événements est dans la Synthèse. L'Admin et les passerelles ont ainsi les mêmes onglets. Interface uniquement. (Admin `0.38.1`)

- **Admin 0.36.0 — menu unifié Admin / passerelles et « Trafic » renommé « Routage »** : la liste « Passerelles » de la barre latérale est remplacée par un rail d’espaces (icône Admin puis une pastille par passerelle avec son état, recherche au-delà de `navEdges.overflowAt`). Le menu n’existe plus en double : Routage, Observabilité et Sécurité sont communs, puis la section Plateforme (Infrastructure, Automatisation, Accès, Paramètres) en vue Admin, ou Passerelle (Portail Access, Tunnel L4, Paramètres) sur une passerelle. Changer d’espace reste sur la même rubrique quand elle existe des deux côtés. Le menu et la page « Trafic » s’appellent maintenant « Routage » (FR, EN, ES, DE). Interface uniquement.

- **Tableau de bord en trois vues — Santé, Cockpit, Carte** : la page d'accueil s'organise en trois onglets qui lisent le même jeu de données (un seul chargement, pas de requête par onglet) ; l'onglet choisi est mémorisé, Santé s'ouvre par défaut. **Santé** : un verdict (« Tout fonctionne » / « Quelques points demandent votre attention » / « Une action est nécessaire »), la liste « Attention requise » avec un bouton d'action par ligne, l'état des services (passerelles, agents, backends, certificats), le trafic de la dernière heure et l'activité récente. **Cockpit** : quatre indicateurs (débit, erreurs 5xx, p95 moyen, débit sortant), courbe de trafic sur 1 h à échelle lisible avec son pic, alertes, passerelles avec charge CPU/RAM, hôtes les plus sollicités et prochaines échéances de certificats. **Carte** : origine du trafic par pays (requêtes, taux d'erreurs ou IPs bannies, infobulle par pays), pays principaux, blocages par couche (WAF, limitation de débit, Fail2Ban, CrowdSec) et latence p95 par passerelle. Les données viennent de `/metrics/summary`, `/metrics/proxies?points=360` et `/prism/geo` ; aucun nouveau point d'accès. Le doublon d'alerte quand un même certificat remontait à la fois de Prometheus et de la liste des domaines est supprimé. Limites : la courbe est le débit total (l'historique par proxy ne porte que le débit, pas les erreurs) et repart de zéro au redémarrage de l'Admin ; la carte reste vide tant que Prism n'a pas analysé de trafic. Adapté au mobile : onglets pleine largeur, indicateurs en grille 2 × 2, graphique redessiné à la largeur de l’écran, actions à la ligne, carte défilable horizontalement (centrée sur l’Europe) avec le détail du pays touché affiché sous la carte. Traductions EN/FR/ES/DE. (Admin `0.28.0`)

- **Workflows GitHub Actions supprimés** : `.github/workflows/` (`build-push`, `ci`, `release`, `sbom-sign`) est retiré ; la CI et la publication passent par les pipelines Harness (`.harness/`, branche `harness/overlay`). Aucun changement de comportement du produit.

- **Page Trafic — tuile proxy et vue tableau plus lisibles** : l'hôte devient le titre de la tuile ; les neuf boutons d'action alignés sont remplacés par un bouton Modifier, l'alerte sécurité (visible seulement si nécessaire) et un menu ⋯ (Sécurité, Logs d'accès, Prism, Historique, Chemin du trafic, Labels Docker, Supprimer). Les fonctions actives passent en icônes colorées avec infobulle ; le premier backend s'affiche avec une pastille « +N » qui déplie les autres ; débit, erreurs et p95 tiennent sur une ligne, et un proxy désactivé est estompé. La vue tableau reprend le même modèle et gagne une colonne « Trafic ». Aucune fonctionnalité retirée. Le rendu tuile/tableau partage désormais un modèle et des actions communs (`proxyModel`, `proxyControls`), préparant de nouvelles vues. (Admin `0.27.0`)

- **Modale proxy unifiée — configuration et sécurité dans une seule fenêtre** : la modale « Modifier le proxy » et la modale « Sécurité » (deux fenêtres, deux boutons d'enregistrement) sont fusionnées. Onglets horizontaux **Général · En-têtes · Auth / SSO · Protection · Résilience · Avancé · YAML** ; l'onglet **Protection** reprend intégralement l'ancienne modale Sécurité (Récap, Paramètres, Snippets, Headers, WAF, Bans, Timeline). Un bandeau « Actif » liste les fonctions en place (cliquables, elles ouvrent l'onglet concerné) avec le score des en-têtes de sécurité, et des compteurs signalent le nombre de fonctions actives par onglet. Un seul bouton **Enregistrer** écrit tout ; les actions « Appliquer les headers recommandés » et « Réinitialiser le WAF » enregistrent d'abord les autres onglets, puis rouvrent la modale sur l'onglet courant. Les points d'entrée existants (menu ⋯ de la page Trafic, page Sécurité) ouvrent l'onglet Protection. HSTS, X-Frame-Options et « Masquer Server » ne sont plus en double dans l'onglet En-têtes : ils se règlent uniquement dans Protection. Correctif au passage : enregistrer depuis l'ancienne modale de configuration seule pouvait effacer limite de débit, filtre IP, GeoIP et snippets ; ils sont désormais toujours conservés. Le bandeau et les compteurs reflètent la config enregistrée (pas les modifications en cours). (Admin `0.27.0`)

- **Page Trafic — deux nouvelles vues : « état » et « maître / détail »** : le sélecteur de vue passe de deux à quatre modes (tuiles, tableau, état, détail), le choix étant conservé pendant la navigation. **Vue état** : cartes avec bandeau de santé (sain / dégradé si un backend est tombé ou plus de 5 % d'erreurs / hors service / désactivé), trois indicateurs (req/s, erreurs, p95), mini-courbe du débit et liste des couches actives ; le sélecteur de colonnes s'y applique. **Vue détail** : liste compacte à gauche (santé, hôte, premier backend, alerte sécurité, type) et panneau complet à droite pour le proxy sélectionné — santé, indicateurs et courbe, accès rapides (Logs, Prism, chemin du trafic), tous les domaines et backends avec leur état, couches actives (un clic ouvre l'onglet correspondant de la modale d'édition), et le menu ⋯ ; sélection multiple et regroupements restent disponibles, les flux TCP/UDP ont leur propre panneau. L'API n'expose pas d'historique par proxy : la courbe se construit à partir d'un relevé de `/internal/v1/metrics/summary` toutes les 5 s tant qu'une de ces deux vues est affichée (60 points, conservés le temps de la session), elle est donc vide à la première ouverture. Traductions EN/FR/ES/DE. (Admin `0.27.0`)

- **Création d'un proxy — mode Simple** : « Nouveau proxy » s'ouvre par défaut en mode **Simple** (bascule Simple / Avancé dans l'en-tête, choix mémorisé dans le navigateur) : domaine, backend, accès (HTTPS avec certificat automatique ou HTTP seul), puis une grille de cartes à activer — WAF, en-têtes de sécurité, limite de débit, anti-bots, filtre IP, coupe-circuit, WebSocket ; activer une carte déploie ses réglages (mode, débit, CIDR…). Le panneau Simple lit et écrit les champs du formulaire complet, donc passer en Avancé (ou l'inverse) ne perd rien et l'enregistrement reste le même ; un lien mène au mode Avancé pour l'authentification, le cache, les en-têtes, la résilience détaillée et le YAML. L'édition d'un proxy existant garde la modale complète. (Admin `0.27.0`)

- **Modale des flux TCP/UDP harmonisée avec celle des proxies** : le toggle « Activé » passe dans l'en-tête, comme pour un proxy, et un résumé du chemin (`Client → :6379 TCP → backends`) se met à jour pendant la saisie. Correctif : enregistrer un flux existant reconstruisait sa configuration à zéro et perdait les réglages non affichés dans la modale (par exemple `proxy_protocol`) ; ils sont désormais conservés. (Admin `0.27.0`)

- **Page Trafic — lignes dépliables et HTTPS par défaut à la création** : dans la vue tableau, un chevron déplie sous chaque ligne les domaines, tous les backends avec leur état, les couches actives et des accès rapides (Logs, Prism, chemin du trafic) ; l'état d'ouverture survit aux rafraîchissements. Un nouveau proxy est créé en **HTTPS (certificat automatique)** par défaut, en mode Simple comme en mode Avancé. Vérifié contre un vrai Admin et une vraie passerelle (création en mode Simple, édition avec les onglets En-têtes / Protection / Résilience, application des en-têtes recommandés, flux TCP, clic sur les couches, Logs, Prism, chemin du trafic, mode sombre). (Admin `0.27.0`)

- **⚠ « Core » devient « passerelle » (français) / « Edge » (anglais), y compris les identifiants techniques** : le composant Data Plane (reverse proxy) s'appelait « Core » ; il s'appelle désormais **passerelle** dans l'interface, les docs et les traductions FR, **Edge** en EN/ES/DE, et `edge` partout dans le code. Changements visibles :
  - **Binaire et conteneur** : commande `goproxify edge` (remplace `goproxify core`), image `…/edge`, service et conteneur `goproxify-edge`, volume `goproxify_edge_data`, `services/edge/`, clé `edge` dans `versions.json`, variable de build `VersionEdge`.
  - **Variables d'environnement** : `GPX_CORE_*` → `GPX_EDGE_*`, `GPX_IDENTITY_CORE_NODE_NAME` → `GPX_IDENTITY_EDGE_NODE_NAME`, `GPX_CONTROL_PLANE_CORE_ENDPOINT` → `GPX_CONTROL_PLANE_EDGE_ENDPOINT`, `CORE_*`/`GOPROXIFY_CORE_TAG` → `EDGE_*`/`GOPROXIFY_EDGE_TAG`.
  - **Fichiers** : `core.json` → `edge.json`, `core-cache.gpx` → `edge-cache.gpx`, `core-tokens.db` → `edge-tokens.db`, export de routage `.gpx-core-backup` → `.gpx-edge-backup`.
  - **API, MCP, CLI** : paramètre `?core=` → `?edge=`, `GET /api/v1/backups/core` → `/backups/edge`, champs JSON `core_*` → `edge_*` (`core_name`, `core_id`, `core_endpoint`, `delegated_to_core_id`, `home_core`…), rôle/`scope_type`/`resource_type` `core` → `edge`, outils MCP et options CLI `-core` → `-edge`. Métriques Prometheus `gpx_core_*` → `gpx_edge_*` (**dashboards et alertes à mettre à jour**). Préfixe des nouveaux tokens `gpx_core_` → `gpx_edge_` (les tokens existants restent valides).
  - **Aucune couche de compatibilité** : les anciens noms ne sont plus lus. Un déploiement existant doit être migré à la main : renommer `core.json`, `core-cache.gpx` et `core-tokens.db` du volume de la passerelle en `edge.json`, `edge-cache.gpx` et `edge-tokens.db` ; renommer dans `agent.json`/`edge.json` les clés `core_*` en `edge_*` ; utiliser les variables `GPX_EDGE_*` ; adapter service/image/commande (`goproxify edge`), scripts d'API (`?edge=`, champs `edge_*`), dashboards Prometheus (`gpx_edge_*`) et clients MCP. La base SQLite de l'Admin (colonnes `core_*`, valeurs de rôle et de périmètre `core`) n'est pas migrée : repartir d'une base neuve ou renommer colonnes et valeurs à la main. Mettre à jour ensemble l'Admin et toutes les passerelles.
  - Les entrées de ce changelog antérieures à ce changement gardent le mot « Core » : elles décrivent l'état de l'époque. (Admin `0.26.0`, Passerelle `0.10.0`, Agent `0.6.0`, Webapp `0.13.0`, Landing `0.3.0`)

- **Landing — schéma d'architecture refait en deux exemples verticaux, et « Démarrer en 5 minutes » aligné** : le schéma horizontal unique laisse place à un sélecteur **Home lab** (1 Admin · 1 Core · 1 Agent) / **Entreprise redondé** (1 Admin · 2 Cores · 4 hôtes avec Agents). Les deux se lisent de haut en bas : Internet, une ou plusieurs passerelles (Cores), puis les Agents (proxies HTTP(S) par labels) ou directement les hôtes (proxies TCP/UDP) ; l'Admin est représenté comme le lien de gestion des Cores. En entreprise, DNS round-robin ou IP virtuelle devant les deux passerelles et réseau interne vers les hôtes. Traductions EN/FR/ES/DE ; anciennes clés `arch.*` retirées. « Démarrer en 5 minutes » suit le même choix : l'onglet Home lab garde les méthodes existantes (Script, Docker Compose, Portainer, Helm, binaire) ; l'onglet Entreprise décrit les trois étapes multi-hôtes (Admin + passerelle 1, second Core enregistré via le Wizard, un Agent par hôte avec ports et variables à renseigner). Documentation alignée : exemples d'architecture dans `README.md`, `docs/architecture.md` et `docs/deployment.md`. (Landing `0.2.0`)

- **`architecture.json` devient la référence de l'architecture (fichier → base) et est versionné** : jusqu'ici la base SQLite primait et le fichier n'en était qu'une copie (relue seulement si la base était vide). Désormais, au démarrage, l'Admin reconnecte les Cores du fichier puis **aligne la base dessus** (`declared_nodes`, `token_scopes`, `domains`) : un nœud absent du fichier est retiré de la base, une modification manuelle du fichier est prise en compte au redémarrage. Garde-fous : un fichier qui ne liste aucun nœud n'est jamais une déclaration (rien n'est supprimé) ; le fichier n'est créé depuis la base qu'une seule fois (`SeedFromDB`) et jamais réécrit depuis elle ; les périmètres et les domaines ne sont réalignés que si le fichier en liste au moins un. Les écritures du wizard, des tokens et des périmètres échouent maintenant en 500 si le fichier ne peut pas être écrit (elles ignoraient l'erreur : la modification disparaissait au redémarrage). Un Core décrit par le wizard n'a plus besoin d'un `endpoint` en plus : l'Admin utilise `reachable_host` de sa config (une adresse n'est jamais dupliquée dans le fichier ; `endpoint` reste possible pour la surcharger, ex. réseau Docker interne). Chaque écriture qui change le fichier conserve la version précédente dans `architecture.versions/` (50 versions) ; restauration réversible : API `GET /api/v1/architecture/versions` et `POST /api/v1/architecture/restore` (admin), CLI `goproxify architecture versions|restore`. `Upsert` ne perd plus les périmètres, la config du wizard, la région ni l'environnement d'un nœud existant. Limite : les domaines restent pilotés par la base (leurs handlers n'écrivent pas encore le fichier d'abord) et sont recopiés dans le fichier. Vérifié sur un cluster docker : fichier écrit à la main avec un nœud wizard sans `endpoint`, Core connecté au démarrage, version conservée, restauration OK, chemin invalide refusé. (Admin `0.25.0`)

- **⚠ Fichier d'architecture de l'Admin : `architecture.yaml` → `architecture.json`, sans migration automatique** : le référentiel d'architecture (nœuds déclarés/Cores avec `endpoint`, périmètres RBAC, domaines) est désormais lu et écrit en JSON, dans `<storage>/state/architecture.json` (format plus adapté, fichier de vérité du wizard). L'ancien `architecture.yaml` n'est plus lu : il n'y a ni double lecture ni conversion en douce. **Action sur un déploiement existant** : convertir une fois votre `architecture.yaml` en `architecture.json` (mêmes clés : `schema_version`, `nodes[]` avec `id`, `role`, `name`, `endpoint`, `rbac_role`, `region`, `environment`, `config`, `scopes[]`, et `domains[]`) ; sans cela l'Admin repart du contenu de la base SQLite et réécrit un `architecture.json` neuf au démarrage. La `config` du wizard y est un objet JSON (et non plus une chaîne). `users.yaml` et `config.yaml` ne changent pas. (Admin `0.24.0`)

### Corrigé

- **Admin 0.29.1 — vues Tuiles et État : les domaines ne sont cliquables que sous le curseur, un clic sur une zone libre de la tuile ouvre les paramètres** : le lien de domaine occupait toute la largeur de la ligne (`display:block`), il se limite maintenant à la largeur du texte ; cliquer ailleurs sur la tuile (hors lien, bouton, case, menu) ouvre la modale d'édition du proxy ou du flux (rôles en écriture, hors proxys automatiques).
- **HA — la découverte des pairs Raft recréait un nœud « fantôme » quand la passerelle est connue sous un nom d'affichage** : `discoverClusterPeers` ne comparait le nom du pair (`GPX_CLUSTER_PEERS=frontal=…`) qu'au `node_name` des heartbeats. Une passerelle enregistrée sous `goproxify-core` mais affichée `frontal` (`display_name`) était donc prise pour inconnue : un token `frontal` était créé sur `hôte:8000`, en 403/404 en boucle (WebSocket refusé, `sync proxies` et `backends-health` en erreur pour les autres passerelles). La comparaison couvre maintenant aussi `display_name`. Un token fantôme déjà créé reste à supprimer (page Tokens). (Admin `0.27.1`)

- **Trafic — les métriques par proxy n'arrivaient jamais dans l'interface, et le « p95 » était une moyenne** : la page Trafic (et le dashboard) interrogeait `/api/v1/internal/v1/metrics/summary`, route qui n'existe pas côté Admin (la requête échouait en silence) ; les indicateurs affichés sur les tuiles n'apparaissaient donc pas en production. La page Trafic lit maintenant `GET /api/v1/metrics/proxies`. De plus, la passerelle publiait comme `p95_ms` par host la latence **moyenne** cumulée ; elle calcule désormais un vrai p95 à partir de l'histogramme et expose les données brutes (`duration_sum_s`, `duration_count`, `latency_buckets`) qui permettent à l'Admin de calculer un p95 sur une fenêtre. Le **dashboard** (bandeau débit / erreurs 5xx / octets, débit et p95 par passerelle, certificats proches de l'expiration) et **Prism** (top p95 et taux d'erreur par proxy) lisent la même route, enrichie de `global`, `edges` et `tls.certs` ; les backends en panne viennent de `/backends/health`. Les libellés du bandeau du dashboard (`dash.rps`, `dash.error_rate`, `dash.bytes_in`, `dash.bytes_out`, `dash.backends_down`) n'existaient dans aucune langue : le bandeau, jamais affiché jusqu'ici, montrait les clés brutes ; ils sont ajoutés en EN/FR/ES/DE. Domaines/TLS, Infrastructure, Portail et Sécurité (vue d'ensemble, passerelles, moteur de règles) lisent la nouvelle synthèse `GET /api/v1/metrics/summary` : connexions WebSocket, synchronisation entre pairs, sessions du portail, profils WAF, blocages du pipeline, Fail2Ban, CrowdSec, moteur de règles (cycles/min, durée moyenne, règles actives) et handshake TLS par domaine, alimentés par de nouvelles sections de la synthèse des passerelles et par les métriques du processus Admin. Les sections sans source (par exemple CrowdSec tant qu'aucune décision n'est passée) affichent « — ». (Admin `0.27.0`, Passerelle `0.10.1`)

- **Landing — affichage mobile** : le tableau « Tech stack » était tronqué (plus de défilement horizontal, dernière colonne coupée) ; il défile maintenant. Les schémas d'architecture ont une version mobile dédiée (≤ 600 px) : mise en page compacte qui tient dans la largeur de l'écran (Admin à côté des passerelles, hôtes en grille 2×2) au lieu d'un schéma coupé à défiler. (Landing `0.2.2`)

- **Landing — l'onglet Portainer « Sans stack.env » n'affichait rien** : une apostrophe parasite dans le script (`"portainer-inline';"`) faisait chercher un panneau inexistant. Même défaut corrigé dans le choix de langue (`"en';"`) et dans la génération des secrets du stack.env (chaîne cassée). (Landing `0.2.1`)

- **Admin UI — la navigation entre pages n'était pas reflétée dans l'URL** : retour arrière, rafraîchissement (F5) et liens directs ramenaient toujours au tableau de bord. `navigate()` écrit maintenant `#<page>` dans l'URL (historique du navigateur), l'événement `hashchange` rouvre la page correspondante et la connexion restaure la page du hash (les pages Core exigent un Core sélectionné, sinon tableau de bord). (Webapp `0.12.4`)

- **Sentinel — le toggle « Moteurs de sécurité » affichait « activé » puis revenait à « désactivé » au rafraîchissement, et n'était jamais réappliqué au redémarrage du Core** : en mode Core, la page Sécurité lit la config Sentinel de ce Core (`GET /security/threat-config?core=<id>`), mais `toggleEngineSentinel` écrivait sans `?core=`, donc dans la config **globale** (`threat_engine_config`) que la page ne relit pas — le toast de succès était exact, l'état affiché après rechargement non. De plus, à la (re)connexion d'un Core l'Admin ne lui renvoie que sa clé propre (`threat_engine_config:<id>`) : une activation faite via le toggle était donc perdue au premier redémarrage. Le toggle cible désormais le Core courant (`window._secCoreQ`, renseigné par la page Sécurité, le dashboard Sentinel et la page Moteurs IPS). Côté Admin, une config Sentinel propre à un Core n'est plus poussée qu'à ce Core (elle partait jusqu'ici vers tous les Cores connectés, `Manager.PushThreatConfig` prend maintenant un `coreRef`, vide = tous). Vérifié sur un cluster docker de 3 Cores : activation sur core-b seul → seul core-b reçoit la mise à jour, relecture `enabled:true`, config globale et core-a inchangées. (Admin `0.23.7`, Webapp `0.12.3`)

- **Multi-Core / HA — un Core resté hors ligne pendant une publication ne rattrapait jamais les proxies manquants** : les proxies vivent en YAML sur chaque Core (l'Admin n'en garde pas de copie) et `publishAll` tolère l'échec d'un Core. Le `full_sync` envoyé à la reconnexion ne contenait volontairement pas les routes (`routes: 0`), donc un Core absent pendant la création d'un proxy restait durablement en retard sur ses pairs. À chaque `full_sync`, l'Admin compare désormais les proxies de production du Core qui se (re)connecte à ceux de ses pairs et publie les manquants (`create → dry-run → promote`, `coreproxy.SyncMissing`), avec 4 tentatives espacées de 5 s car les Cores répondent 401 juste après un redémarrage de l'Admin. Seuls les proxies **absents** sont ajoutés : un proxy déjà présent n'est jamais écrasé, et une suppression faite pendant l'absence n'est pas propagée (le Core revenu garde le proxy supprimé). Vérifié sur un cluster docker de 3 Cores. (Admin `0.23.6`)

- **CRITIQUE — Admin ouvrait une base SQLite neuve et vide au lieu de la base existante (domaines, certs, config ACME, utilisateurs disparus de l'UI)** : régression introduite par le correctif du chemin de `config.json` (`d25555a`). Le template jusqu'ici embarqué dans l'image (`services/admin/config.json`, jamais réellement utilisé sur le volume avant ce correctif) pointait `storage.sqlite_dsn` vers `/etc/goproxify/database/goproxify.db` — c'est cet emplacement précis que portent toutes les bases SQLite existantes des déploiements réels. Une fois `admin.json` réellement bootstrappé sous `/etc/goproxify` (comme prévu), `BootstrapAdmin()` générait un chemin différent, `/etc/goproxify/admin.db` : Admin démarrait alors avec une base **neuve et vide** à cet autre emplacement, sans toucher ni supprimer la base réelle qui restait intacte sur le volume — d'où l'apparence de perte totale (domaines, certificats, config ACME, comptes) alors que rien n'était réellement effacé. `BootstrapAdmin()` utilise désormais exactement le même chemin que l'ancien template. Même correctif de parité pour les chemins de logs générés par `BootstrapCore()` (`core_access.log`/`core_system.log`, et non `access.log`), moins critique (aucune perte de configuration, juste des logs futurs écrits dans un fichier différent de l'historique) mais de même nature. **Action pour les déploiements affectés** : si vous avez redémarré Admin entre `d25555a` et ce correctif, `/etc/goproxify/admin.db` (base neuve, quasi vide) a pu être créée à côté de votre vraie base `/etc/goproxify/database/goproxify.db` (intacte) — supprimez ce fichier `admin.db` parasite si présent, puis redémarrez : Admin rouvrira automatiquement la bonne base. (Core `0.8.3`, Admin `0.23.5`)

- **401 permanent Admin→Core sur healthcheck, métriques et push routes/certs quand le chiffrement des tokens est actif** : `tokens.token` peut être chiffré au repos (AES-GCM, `auth.SealNodeToken`, actif dès que `GPX_NODE_TOKEN_KEY` ou le secret JWT est configuré). `pushAdminToken` (WS) déchiffre bien le token avant de l'envoyer à Core, qui ne connaît donc que le hash du token **en clair** — mais trois appels HTTP internes Admin→Core lisaient la colonne `tokens.token` et l'utilisaient telle quelle comme Bearer, sans déchiffrement symétrique : `backends-health` (agrégation santé des backends, log `backends-health: Core a refusé … status=401`), `metrics/summary` (dashboard par nœud), et surtout **`corepush` — le push des routes et certificats vers Core**, qui échouait silencieusement en 401 dans les mêmes conditions. Les trois déchiffrent désormais le token avant de l'envoyer, comme le fait déjà `pushAdminToken` et les autres endpoints agrégés (`nodes.go`, `discovered_containers.go`, qui étaient déjà corrects). (Admin `0.23.4`)

- **Logs Core introuvables après un renommage/re-pairing de nœud** : les logs (page Logs de l'Admin) n'étaient filtrables que par `node_name`, un texte libre écrit en dur sur chaque ligne au moment de l'ingestion. Après un renommage du nœud (le cas déclencheur : un re-pairing suite à la régénération de `core.json`, voir le correctif `config.json`/volume ci-dessous), l'historique complet des logs de ce nœud devenait invisible dans l'UI — pas supprimé, juste filtré hors de la vue puisque le sélecteur envoie le nouveau nom. Chaque ligne de log Core porte désormais aussi `node_id`, l'identifiant stable de la connexion WS (le token du nœud), toujours réécrit côté Admin quel que soit ce que Core envoie (jamais déclaré par le client). Le filtre "logs de ce Core" utilise maintenant `node_id` en priorité — stable même après un renommage. En complément, la recherche libre de la page Logs matche désormais aussi `node_name`, pour retrouver manuellement l'historique d'un nœud renommé ou disparu. (Admin `0.23.3`)

- **`config.json`/`admin.json`/`agent.json` chargés depuis un template embarqué dans l'image, jamais depuis le volume — toutes les variables `GPX_*` de premier démarrage silencieusement ignorées** : `configPath()` (utilisé au démarrage pour charger/générer la config) défaut vers `./internal/<composant>/config.json`, qui résout vers un fichier **copié dans l'image Docker au build** (`services/<composant>/config.json`, hors du volume `/etc/goproxify`). Ce fichier existant dès le tout premier démarrage, `Bootstrap{Admin,Core,Agent}()` (qui ne génère la config qu'en son absence) ne s'exécutait donc **jamais**, sur aucun déploiement — les variables `GPX_CLUSTER_*`, `GPX_IDENTITY_*`, etc. n'avaient aucun effet, quel que soit le nombre de redémarrages. `goproxify backup` cherchait de son côté ce fichier sous `/etc/goproxify` (`defaultConfigPath()` dans `cmd/goproxify/backup.go`, correct) et ne le trouvait donc jamais non plus pour l'inclure dans les sauvegardes : deux fonctions internes désaccordées sur l'emplacement du même fichier. `configPath()` pointe désormais vers `/etc/goproxify/<composant>.json` (même défaut que `backup`), et les templates statiques ne sont plus copiés dans les images Admin/Core/Agent — le fichier est intégralement généré au premier démarrage à partir des variables `GPX_*`, puis persiste sur le volume comme prévu. **Action requise sur un déploiement existant** : si un conteneur a démarré au moins une fois avec l'ancienne image, aucun fichier de config n'a jamais été écrit sur son volume — au prochain démarrage avec la nouvelle image, il sera généré normalement à partir des variables d'environnement actuelles (comportement de premier démarrage). (Core `0.8.2`, Admin `0.23.2`, Agent `0.5.1`)

- **Config cluster Core — `GPX_CLUSTER_GROUP_NAME` ignoré et `GPX_CLUSTER_PEERS` cassé par des guillemets** : deux bugs de chargement de config empêchaient le cluster Raft du Core de démarrer correctement dans un déploiement docker-compose réel (repéré sur un déploiement à 2 nœuds où aucun log `cluster`/`raft` n'apparaissait au démarrage malgré `GPX_CLUSTER_ENABLED=true`). D'une part, seul l'alias court `GPX_CLUSTER_GROUP` était lu ; `GPX_CLUSTER_GROUP_NAME` — le nom utilisé dans les exemples de déploiement — n'avait aucun effet, `GroupName` restait vide. D'autre part, en syntaxe docker-compose `environment:`, des guillemets écrits autour d'une valeur (`GPX_CLUSTER_PEERS="id=http://host:8002"`) sont transmis tels quels au process (pas de shell pour les retirer) : le parseur ne les retirait pas, produisant un ID de pair et une URL corrompus (guillemet en tête/en queue), donc un pair injoignable. `GPX_CLUSTER_GROUP_NAME` est désormais lu (en plus de l'alias), et les guillemets superflus (simples ou doubles) sont retirés avant parsing, sur la valeur globale comme sur chaque `id`/`url`. (Core `0.8.2`)

- **HA — élections Raft en boucle, aucun leader ne survivait assez longtemps pour committer une écriture** : trois bugs cumulés rendaient le HA (Admin comme Core) inutilisable dès qu'un cluster comptait 2+ nœuds réels, pas seulement en test :
  1. Le résultat d'une élection est connu de façon asynchrone (dépouillement des votes dans des goroutines séparées). L'instance de boucle qui attendait ce résultat retournait aussitôt après avoir lancé l'élection, et la boucle principale la relançait immédiatement en attendant — cette nouvelle instance ignorait totalement qu'un des votes en cours allait bientôt faire gagner le nœud : à l'expiration de son propre timer, elle relançait une élection sans vérifier l'état courant, redégradant le leader tout juste élu. Résultat observé : le terme grimpait en boucle (jusqu'à +20 en 500ms) et le leadership changeait de nœud à peu près à chaque fenêtre de timeout — jamais assez stable pour qu'une entrée du journal soit committée. Un canal de notification (`becomeLeader` → `leaderCh`) permet désormais à l'instance en attente de céder immédiatement la main dès que l'élection aboutit.
  2. Le timer d'élection (`electionTimer`) était remis à zéro (`Reset`/`Stop`) depuis les goroutines de traitement des RPC entrants (heartbeats, votes), pendant qu'une autre goroutine lisait son canal — un usage documenté comme non sûr par `time.Timer`, qui provoquait la perte de resets malgré des heartbeats reçus à temps. Le timer est désormais possédé et manipulé par une seule goroutine ; les autres ne font que signaler un reset via un canal dédié.
  3. Un nœud sans pair joignable (dernier survivant après panne des autres, ou cluster à un seul nœud) restait bloqué en `Candidate` indéfiniment : `becomeLeader()` n'était déclenché que par les réponses des pairs sollicités, jamais par la boucle elle-même quand elle était vide — alors que le quorum (1 voix, soi-même) était déjà atteint.

  Conséquence globale avant correctif : `/ha/status` répondait `leader_id: ""` de façon quasi permanente et toute écriture forwardée par un follower échouait en `503 {"error":"no leader available"}`. Testé par un nouveau banc de tests multi-nœuds en mémoire (élection, réplication, failover, stabilité sur 1,5s avec les timeouts de production), absent jusqu'ici (le paquet `raft` n'avait aucun test). (Core `0.8.1`, Admin `0.23.1`)

- **Découverte Kubernetes — annotations de sécurité ignorées** : l'Agent K8s ne lisait que `host`/`domain`, `port`, `backend` et `tls`. Toutes les autres annotations `goproxify.*` (`waf`, `rate_limit`, `ip_filter`, `jwt`, `mtls`, `limit_conn`, `headers.*`, `cache`, `lb`, `retry`…) étaient ignorées sans erreur, alors que la doc annonçait la même sémantique que les labels Docker : un Ingress annoté `goproxify.waf: block` n'avait aucun WAF. L'Agent K8s réutilise désormais le parseur des labels Docker (parité complète, préfixe d'annotation configurable, `host` en CSV = alias). **Attention** : des annotations jusqu'ici sans effet le deviennent au prochain redéploiement de l'Agent. Les valeurs déduites de la ressource (hôte, backend, TLS) l'emportent sur les annotations. La ressource doit toujours porter le **label** `goproxify.enabled: "true"` (un sélecteur de labels K8s ne peut pas viser une annotation) : c'est maintenant documenté, la doc parlait à tort de `goproxify.enable`. (Agent `0.5.0`)

- **Label Docker `goproxify.headers.remove` retirait des en-têtes de la requête, pas de la réponse** : la doc et l'exemple (`X-Powered-By,Server`) désignent des en-têtes de réponse, mais le Core les retirait de la requête envoyée au backend, où ils n'existent pas : le label n'avait aucun effet utile. Il retire désormais les en-têtes de la réponse du backend (`transform.remove_response_headers`). **Attention** : si vous l'utilisiez pour retirer des en-têtes de requête (`Cookie`, `Authorization`), passez par la config `request_hide_header` de la route. (Core `0.8.0`)

- **Sécurité — labels Docker `goproxify.jwt` et `goproxify.mtls` sans effet (route non protégée)** : l'Agent envoyait `{"secret": …}` / `{"cert_name": …}`, des champs que le Core ne connaît pas ; la configuration arrivait avec `enabled: false` et la validation JWT / mTLS n'était jamais appliquée, sans aucune erreur : une route étiquetée pour être protégée restait ouverte. Détecté par un audit qui suit chacun des labels de configuration jusqu'à la route (test `TestDockerLabelsAudit`, les 29 autres labels sont conformes). Désormais : `goproxify.jwt` = URL JWKS (+ `goproxify.jwt.issuer` / `goproxify.jwt.audience` optionnels), `goproxify.mtls` = chemin du fichier CA (PEM) côté Core, certificat client exigé. Les anciennes valeurs (`"true"`, secret inline, nom de certificat) n'ont jamais fonctionné et ne sont pas supportées : elles sont ignorées avec un avertissement dans les logs de l'Agent. **Action requise** : les routes qui utilisaient ces labels sont à vérifier, elles n'étaient pas protégées. (Core `0.8.0`, Agent `0.5.0`)

- **mTLS — CA illisible = route ouverte** : quand le fichier CA d'une route mTLS avec `require_client_cert` était introuvable ou invalide, le middleware laissait passer toutes les requêtes. La route répond désormais `503` (et le journalise). Sans certificat client obligatoire, le comportement est inchangé. (Core `0.8.0`)

- **WebSocket en 502 derrière le WAF ou des en-têtes de réponse personnalisés** : les wrappers de réponse du WAF (suivi comportemental) et des transformations d'en-têtes ne relayaient pas `Hijack`, donc `ReverseProxy` ne pouvait pas détourner la connexion et tout upgrade WebSocket (Socket.IO…) finissait en 502 alors que le backend répondait 101. Les deux wrappers exposent désormais `Unwrap`, et le WAF ne bufférise plus la réponse d'un upgrade WebSocket (règles de réponse actives). (Core `0.8.0`)

- **Label Docker `goproxify.limit_conn` sans effet** : l'Agent envoyait `{"max": N}` alors que le Core attend `max_per_ip` ; la limite restait à 0 (désactivée) pour toute route découverte par label. Le générateur de labels de l'UI relisait aussi la mauvaise clé. Corrigé des deux côtés, avec un test qui suit le label jusqu'à la route. (Core `0.8.0`, Agent `0.5.0`, Admin `0.20.0`)

- **`limit_conn` — quota partagé entre les routes** : le compteur de connexions par IP était global : une IP très active sur une route consommait le quota des autres routes (503 injustifiés). Le compteur est désormais propre à chaque route. (Core `0.8.0`)

- **OpenTelemetry — traces non chaînées, en-tête `X-Trace-Id` jamais reçu, endpoint poussé ignoré** : aucun propagateur n'était installé, donc un `traceparent` entrant était ignoré (chaque requête ouvrait une nouvelle trace racine) et rien n'était transmis au backend ; `X-Trace-Id` était posé après l'écriture de la réponse (donc jamais envoyé) ; l'endpoint OTLP poussé par Admin (`tracing_endpoint`) était mémorisé mais jamais appliqué. Tous trois corrigés (voir « Ajouté »). Attribut de span `http.response.status_code` ajouté à côté de `http.status_code`. (Core `0.8.0`)

- **WAF — corps de requête tronqué au-delà de `max_body_mb`** : le WAF lisait au plus `max_body_mb` (10 Mo par défaut) puis remplaçait le corps par ces seuls octets, sans transmettre le reste. Une requête plus grosse (upload) repartait tronquée vers le backend (erreur 502 ou données corrompues). Seuls les premiers `max_body_mb` restent inspectés, mais le corps complet est désormais renvoyé intact. Détecté par le labo de tests (`tests/lab`). (Core `0.7.0`)

- **Journal d'audit — dates affichées `01/01/1`** : `created_at` était relu avec un seul format SQLite ; le driver renvoyant du RFC3339, le parse échouait en silence et la date restait à zéro. Le parse accepte désormais les deux formats, et l'UI affiche `—` pour une date nulle. (Admin `0.18.1`)

- **Sentinel — épuisement mémoire et contournement IPv6** : les compteurs par IP (rate, erreurs 4xx, déclenchements) n'étaient pas bornés et protégés par un mutex global avec GC O(n) dans le chemin de requête. Ils sont désormais répartis en 64 shards, plafonnés (~262 k clés par type, éviction fail-open) et les IPv6 sont agrégées par /64 pour ne plus contourner le rate limit avec un préfixe entier. Nouvelle métrique `gpx_threat_counter_evictions_total`. Les bans restent posés sur l'IP exacte. (Core `0.6.2`)
- **Sentinel — `rate_window` sans effet** : le paramètre était ignoré (burst = `rate_limit`). Il fixe désormais la capacité de burst : `rate_limit` req/s en moyenne, pics tolérés jusqu'à `rate_limit × rate_window` requêtes (défaut `1s` : comportement inchangé). (Core `0.6.2`)

- **Sécurité — IP client falsifiable via `X-Forwarded-For`** : `RealIP` croyait `CF-Connecting-IP` / `X-Forwarded-For` / `X-Real-IP` de n'importe quel client, ce qui permettait de contourner Fail2Ban/Sentinel/rate-limit (IP changée à chaque requête), de faire bannir un tiers et de falsifier les logs. Les en-têtes ne sont désormais lus que si la connexion directe provient d'un proxy de confiance : loopback + réseaux privés par défaut, extensible via `GPX_TRUSTED_PROXIES` (CSV IP/CIDR, `*` = ancien comportement). **Attention** : derrière Cloudflare ou un load balancer à IP publique, renseigner `GPX_TRUSTED_PROXIES` sinon l'IP vue est celle du proxy. `X-Forwarded-For` est lu de droite à gauche (première IP hors proxy de confiance) : une IP forgée en tête de chaîne derrière un proxy qui ajoute à l'en-tête n'est plus prise en compte ; les valeurs non-IP sont ignorées. (Core `0.6.1`, Admin `0.17.1`)

### Ajouté

- **CA interne (autorité de certification interne)** : génération d'une autorité racine auto-signée (clé ECDSA P-256) et émission de certificats serveur/client internes, hors ACME — pour les services internes sans exposition publique. Clés privées persistées sur disque (`certs/internal-ca/<ca_id>/`), métadonnées en DB (`internal_ca`, `internal_ca_certs`). Nouveaux endpoints `GET/POST /api/v1/internal-ca`, `GET/POST /api/v1/internal-ca/{id}/certs`, `DELETE /api/v1/internal-ca/{id}/certs/{certID}` ; commande `goproxify internal-ca` (`create-ca`, `list-ca`, `issue`, `list-certs`, `revoke`) ; outils MCP `create_internal_ca`, `list_internal_cas`, `issue_internal_cert`, `list_internal_certs`, `revoke_internal_cert`. Interface Admin : section « CA interne » intégrée à la page Domaines & certificats (`/acme-monitor`) — création de CA, liste, panneau latéral d'émission/révocation des certificats. (Admin `0.23.0`)

- **Labels Docker `goproxify.backpressure` et `goproxify.slow_start`** : `backpressure` = `max[:file[:attente]]` (ex. `200:100:2s`), `slow_start` = secondes ou durée (`30`, `30s`, `2m`). Découverte Agent → route du Core, générateur de labels de l'UI (création et pré-remplissage depuis une route) et badges de la liste des conteneurs. Un test suit les labels jusqu'à la route. (Core `0.8.0`, Agent `0.5.0`, Admin `0.20.0`)

- **Topologie temps réel** : la carte Infrastructure → Topologie se rafraîchit toutes les 5 s sans recharger la page et affiche, sur chaque nœud, le débit (req/s sur 60 s + sparkline de 2 min) et un **score de risque 0-100** (bordure orange/rouge selon `medium`/`high`). Le score est le plus élevé de quatre facteurs indépendants, dont la cause dominante est indiquée : hors ligne, taux de refus 403/429 (×2), taux d'erreurs 5xx (×4), pression CPU/RAM (70 → 100 %) ; sous 20 requêtes dans la fenêtre les taux sont ignorés. Nouveau `GET /api/v1/nodes/live` (débit calculé depuis les access logs par nœud, hors logs Admin), commande `goproxify nodes live` et outil MCP `get_topology_live` (scope `nodes:read`). Un nœud qui apparaît ou disparaît recharge la carte. Les bans actifs sont affichés globalement (non rattachés à un Core). (Admin `0.20.0`)

- **OpenTelemetry — propagation W3C de bout en bout** : le Core reprend la trace d'un `traceparent` entrant, ouvre un span client par appel backend (attributs `server.address`, `gpx.backend.attempt`, statut, erreurs) et transmet `traceparent` au backend : la trace couvre appelant → Core → backend. Les décisions de sécurité sont des événements du span serveur (`sentinel.signal`, `ban.blocked`, `ip_profile.blocked` — sans IP) et la route est en attributs (`gpx.route.id`, `gpx.route.host`). Nouveau `engine.tracing_sample_ratio` (défaut `1`, la décision de l'appelant est respectée) et endpoint OTLP en URL complète (`https://…`) en plus de `host:port`. Sans endpoint, le Core reste transparent : le `traceparent` entrant est quand même transmis. `/metrics` n'est pas tracé. L'endpoint poussé par Admin s'applique à chaud. Non couvert : WebSocket, requêtes de shadow mirror, tunnels L4. (Core `0.8.0`)

- **Sentinel — tarpit** : nouvelle option `tarpit` (`enabled`, `delay_ms`, `max_concurrent`) de la config Sentinel. Une requête bloquée par Sentinel, ou venant d'une IP bannie par Sentinel (source `threat`, WAF compris), est retenue `delay_ms` (défaut 5 s, max 30 s) avant le `403`, ce qui ralentit les bots. Le nombre de requêtes retenues est plafonné (`max_concurrent`, défaut 200) : au-delà, refus immédiat comme avant, le tarpit ne peut pas épuiser les connexions du Core. Un client qui se déconnecte libère son slot. Fail2Ban, CrowdSec, bans manuels et profils IP ne sont pas concernés. Métriques `gpx_threat_tarpit_active` et `gpx_threat_tarpit_total{result}`. Champs dans Sécurité > Sentinel. Désactivé par défaut. (Core `0.8.0`, Admin `0.20.0`)

- **Load balancer — slow-start** : nouveau champ de route `slow_start_sec`. Un backend nouvellement ajouté (scale-out Docker) ou revenu en service après une panne / quarantaine reçoit une part de trafic croissante de ~5 % à 100 % de sa part nominale pendant cette durée, au lieu de la charge pleine d'un coup (cold-start). Les requêtes détournées vont vers un backend plus avancé ; sans alternative (backend unique, tous en montée) rien ne change ; une session collante garde son backend. S'applique à tous les algorithmes (round_robin, weighted, adaptive). Nouvelle métrique `gpx_backend_slowstart_shifted_total{host,backend}`. Champ dans le formulaire de route de l'UI ; pas encore de label Docker. Désactivé par défaut. Au démarrage du Core tous les backends sont « nouveaux » : la répartition reste alors inchangée. (Core `0.8.0`, Admin `0.20.0`)

- **MCP — dry-run Sentinel (`simulate_sentinel_config`)** : rejoue les access logs des dernières heures (1 à 24 h, 200 000 requêtes max) contre une config Sentinel candidate et la compare à la config actuelle, sans rien appliquer : requêtes bloquées, bans, IP les plus touchées, `legit_blocked` (bloquées alors qu'elles avaient abouti). Utilise le vrai moteur Sentinel sur l'horloge des logs (`threat.Simulate`, sans effet sur les métriques). Non simulé : listes par défaut, `global_rps`, règles User-Agent (UA absent des logs), WAF ; IP pseudonymisées ignorées. Scope `logs:read`. (Admin `0.20.0`)

- **Backpressure par route** : nouveau champ `backpressure` (`max_inflight`, `queue`, `queue_timeout_ms`) qui plafonne les requêtes simultanées vers les backends. Les excédentaires attendent dans une file bornée (défaut : aucune file, attente max 1 s) puis reçoivent `503` + `Retry-After: 1`, ce qui borne la mémoire du Core quand un backend ralentit. Les WebSocket sont exclus du plafond. Métriques `gpx_backpressure_inflight`, `gpx_backpressure_queued`, `gpx_backpressure_rejected_total{reason}`. Section dédiée dans le formulaire de route de l'UI. Désactivé par défaut. (Core `0.8.0`, Admin `0.19.0`)

- **Sécurité — `TRACE`/`TRACK` refusés et taille des en-têtes bornée** : le Core répond `405` à `TRACE` et `TRACK` (aucun usage légitime derrière un reverse proxy ; un backend naïf renvoyait la requête telle quelle). La taille cumulée des en-têtes de requête est limitée à **32 Ko par défaut** (`timeouts.max_header_kb`, `0` = défaut) au lieu de 1 Mo ; au-delà, `431 Request Header Fields Too Large`. Attention : des en-têtes légitimes supérieurs à 32 Ko (cookies/jetons très volumineux) devront relever cette valeur. HTTP/1.1, HTTPS et HTTP/3. Détecté par le labo de tests (`tests/lab`). (Core `0.7.0`)

- **Labo de tests** (`tests/lab/`) : environnement Docker isolé (routes `*.lab.test`) avec backend contrôlable, scénarios de charge k6 (smoke, baseline, spike, stress, soak, mixed), batterie d'attaques avec verdicts PASS/FAIL (WAF, usurpation XFF, smuggling, slowloris, API Admin), chaos réseau via Toxiproxy et scanners ZAP/Nuclei. Piloté par `tests/lab/lab.sh`. Aucun changement de service.

- **MCP — allowlist de destinations backend** : `create_proxy` et `update_proxy` refusent un backend hors allowlist (IP, CIDR, hôte exact ou `*.suffixe`), pour qu'un agent victime de prompt injection ne puisse pas rediriger le trafic vers un serveur externe. Défaut : RFC 1918, loopback, ULA, `*.internal|local|svc|cluster.local` et noms à label unique ; liste vide = pas de restriction. Éditable via `GET/PUT /api/v1/mcp-access/allowed-backends` (pas encore d'écran UI). Ne couvre pas l'API REST/UI. Attention : les backends MCP publics existants devront être ajoutés à la liste. (Admin `0.18.0`)

### Modifié

- **Alerting — déclencheur `ip_profile_refresh_failed`** : une alerte est émise quand le rafraîchissement d'un profil IP échoue N fois de suite (N = `3` par défaut, réglage `ipprofile.alert_after_failures`, `0` = désactivé), une seule fois par série d'échecs (elle se réarme après un succès). Le détail contient le profil, le nombre d'échecs, la dernière erreur et la date de dernière mise à jour réussie. Sévérité `warning`, à router via une règle d'alerte comme les autres déclencheurs (Alerting → Règles). Le seuil n'a pas encore de champ dans l'UI. (Admin `0.22.0`)

- **Profils IP — résilience du rafraîchissement, visibilité et garde-fou** : un feed en échec (réseau, HTTP ≠ 200, parsing) n'est plus retenté toutes les 15 min mais avec un backoff exponentiel (15 min doublées à chaque échec, plafonné à 6 h et à l'intervalle du profil), ce qui évite de marteler Spamhaus, abuse.ch & co. ; la dernière liste valide reste appliquée. L'état est exposé : `last_error`, `consecutive_failures` et `next_attempt_at` dans `GET /ip-profiles[/:id]`, l'outil MCP `list_ip_profiles`, la colonne `ETAT` de `goproxify ip-profile list` et un badge « Échec ×N » (cause en infobulle) dans la page Profils IP ; `last_updated_at` ne désigne plus que le dernier succès. Nouveau garde-fou : une mise à jour qui perd plus de la moitié d'une liste d'au moins 10 entrées (feed vide, tronqué, page d'erreur servie en 200) est rejetée, comptée comme un échec, et l'ancienne liste est conservée ; le bouton ↻ / `POST /ip-profiles/:id/refresh` force l'acceptation. Non fait : alerte au-delà de N échecs. (Admin `0.21.0`)

- **Profils IP — listes de blocage optimisées** : les CIDRs d'un feed sont désormais validés, dédupliqués et agrégés (préfixes contenus dans un autre supprimés, voisins fusionnés) avant stockage et push aux Cores — mesuré sur les feeds publics : AWS 17 425 → 4 075, GCP 1 103 → 476, Tor 1 380 → 800 entrées. Les plages privées/réservées (RFC 1918, loopback, link-local, CGNAT, documentation, multicast/réservées ; IPv6 équivalentes) sont retirées des profils `deny` : une liste de blocage ne peut plus couper le trafic interne. Les téléchargements sont conditionnels (`ETag` / `Last-Modified`) : un feed inchangé répond `304` et n'est ni retéléchargé ni retraité ; `POST /ip-profiles/:id/refresh` force un téléchargement complet. **Doublons** : FireHOL Level 1 inclut déjà Spamhaus DROP, DShield et Feodo ; ces trois profils par défaut sont désormais désactivés (nouvelles installations, et une seule fois sur les bases existantes tant que leur feed n'a pas été personnalisé). Réactivables depuis l'UI ; les blocages sont alors attribués au profil « FireHOL Level 1 ». Un profil sans feed (CIDRs saisis à la main) n'est plus jamais réécrit par le rafraîchissement automatique, et `refresh` répond une erreur pour un tel profil. (Admin `0.20.1`)

- **Sauvegardes — imports et restauration revus** : snapshot de sécurité automatique (`avant-restauration-*` / `avant-import-*`) avant tout écrasement, opération annulée s'il échoue ; `POST /backups/snapshots/:id/restore` accepte une `selection` optionnelle ; restauration des PAT et de la configuration dans les 3 écrans (Sauvegardes, Import, assistant de démarrage) avec cases dédiées ; résumé du preview détaillé par table (`config_tables`) ; compteurs `config` et `declared_nodes` dans le résultat ; version de sauvegarde inconnue refusée ; corps d'import limité à 32 Mo ; planifications rechargées après restauration ; endpoints documentés dans `api_specs.md`. (Admin `0.17.0`)

- **Documentation des sauvegardes** : nouveau `docs/sauvegardes.md` (fonctionnement, contenu exact, exclusions, secrets, restauration).

- **Sauvegardes — couverture étendue** : le snapshot n'exportait que proxies, utilisateurs, tokens, snippets, canaux/règles d'alerte et nœuds déclarés ; tout le reste était perdu à la restauration. Ajout de la section `tables` (règles automatiques, settings dont allowlist MCP, planification de sauvegarde, équipes/scopes, workspaces, domaines, cibles de déploiement de certificats, fournisseurs d'authentification, profils IP, tunnels, pages d'erreur/portail, config fail2ban/CrowdSec). Secrets rédigés à l'export et jamais écrasés à la restauration ; nouvelle case « Configuration » (`import_config`) dans la restauration, cochée par défaut, et incluse dans la restauration d'un snapshot. Les MFA, mots de passe, logs, bans, audit et clés RGPD restent volontairement exclus. (Admin `0.16.0`)

### Modifié

- **Accès MCP — IP sources autorisées : réseaux privés par défaut** : tant que la liste n'a jamais été enregistrée, `/mcp` n'accepte que RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), loopback et IPv6 ULA/loopback. Une liste explicitement vidée reste sans restriction. Attention : les installations existantes n'ayant jamais configuré la liste refusent désormais les IP publiques. (Admin `0.15.1`)

### Ajouté

- **Store de règles — 8 nouveaux templates (15 au total)** : sécurité (`cve-high-notify` CVSS ≥ 7, `ban-spike-notify` > 50 bans/1h, `ban-repeat-permanent` ban définitif après 5 bans/7j), fiabilité (`crowdsec-silent-alert`, `error-rate-notify` > 30 %/10 min, `node-offline-long-backup` nœud hors ligne > 30 min → sauvegarde), conformité (`cert-expiring-notify` 30 j, `cert-expiring-critical` 3 j). Réutilisent les conditions/actions existantes ; aucun changement d'API. (Admin `0.15.0`)

### Corrigé

- **"Règles automatiques" — le bouton Éditer ne fonctionnait pas** : `onclick="openRuleModal(${JSON.stringify(JSON.stringify(r))})"` injectait un JSON doublement échappé directement dans l'attribut HTML `onclick="..."` — les guillemets `"` du JSON, non ré-échappés pour le contexte HTML, terminaient prématurément l'attribut et cassaient le markup (bouton inopérant ou comportement erratique selon le contenu de la règle). Corrigé en passant l'`id` de la règle (comme le fait déjà `runRuleNow`) et en la retrouvant dans `window._reRules`, déjà en cache depuis `renderSecurityRules` — même pattern que `openAlertRuleModal`/`openChannelModal` (`alerts.js`). (Webapp `0.12.2`)

- **Traductions manquantes sur les pages du menu Automatisation et sur Accès MCP** : `automation.js`, `rules-store.js` et `mcp-access.js` appelaient `t('clé') || 'texte français'` pour des clés jamais ajoutées à `i18n.js` — tout utilisateur EN/ES/DE voyait le fallback français en dur. Ajout des 38 clés (`automation.*`, `rules_store.*`, `mcp_access.*`, plus `common.empty`/`common.total` déjà utilisées ailleurs sans être définies) dans les 4 locales (`en`, `fr`, `es`, `de`). (Webapp `0.12.1`)

### Ajouté

- **Moteur de règles automatiques — 2 nouvelles conditions et 2 nouvelles actions** : conditions `node_offline` (Core/Agent sans heartbeat depuis > N minutes, basé sur `nodes.last_seen_at`) et `cert_expiring` (certificat TLS expirant sous N jours, basé sur `certs.expires_at`) ; actions `webhook_call` (POST JSON générique vers une URL externe — payload `{rule, condition, action, detail, fired_at}`) et `run_backup` (déclenche un snapshot de sauvegarde immédiat via `backup.Scheduler.TakeSnapshot`, rétention optionnelle). Formulaire de règle (`security.js`, modale condition/action) et descripteurs API (`GET /api/v1/rules-engine/condition-types`, nouveau `GET /api/v1/rules-engine/action-types`) mis à jour en conséquence. 2 nouveaux templates dans le store de règles (`node-offline-notify`, `cert-expiring-backup`). (Admin `0.14.0`, Webapp `0.12.0`)

- **Menu "Automatisation" restructuré en 3 sous-menus + store de règles préconfigurées** : le menu Automatisation regroupe désormais "Règles automatiques" (`security-rules`, inchangé), "Canaux d'alerte" (`alert-channels`, déplacé depuis le menu Sécurité) et un nouveau "Store de règles" (`rules-store`) — un catalogue de 5 règles condition→action préconfigurées (CVE critique, pic de bans, IP récidiviste, moteur IPS silencieux, taux d'erreur anormal) installables en un clic depuis l'UI (`internal/admin/rulesengine/templates.go`, `GET/POST /api/v1/rules-engine/templates`). Une page de vue d'ensemble (`pages.automation`) résume l'état des trois. (Admin `0.12.0`, Webapp `0.10.0`)
- **Page admin "Accès MCP"** (menu Accès → `mcp-access`) — périmètre d'accès du serveur MCP : **allowlist d'IP/CIDR sources** autorisées à appeler `/mcp` (`GET`/`PUT /api/v1/mcp-access/allowed-ips`, nouveau paquet `internal/admin/mcpaccess`, appliquée dans `mcp.Handler.ServeHTTP` **avant** l'authentification PAT — 403 immédiat pour toute IP hors liste ; liste vide par défaut = pas de restriction), tableau des **utilisateurs porteurs d'un token MCP actif** avec leurs scopes (`GET /api/v1/mcp-access/tokens`, tous porteurs confondus), et catalogue de scopes PAT avec les outils MCP couverts par chacun pour référence (`rbac.ToolsForScope`, dérivé de `ToolRequiredScope`, `GET /api/v1/mcp-access/scopes`). Admin uniquement. La création/édition des scopes d'un PAT reste self-service sur "Mes tokens API" — un PAT est personnel à son porteur. (Admin `0.13.0`, Webapp `0.11.0`)

### Corrigé

- **Modale "Historique" du proxy — "Aucun historique pour ce proxy." alors qu'il y en a un** : la modale unifiée (`openProxyVersionsModal`, `trafic.js`, fusionnée récemment avec l'ancien "Diff config") ne lisait que `GET /backups/proxy-history/{id}`, une table SQLite côté Admin (`proxy_history`) qui n'enregistre une version qu'à chaque création/modification faite *via l'API Admin*. Un proxy jamais retouché depuis l'Admin (créé/synchronisé côté Core, ou modifié avant l'introduction de cette table) y a zéro ligne — alors que l'historique réel existe bien côté Core (`proxystore`, un fichier de révision à chaque création/dry-run/promote), déjà exposé par `GET /proxies/{id}/revisions/diff` (champ `revisions`, utilisé jusqu'ici seulement pour calculer un diff, jamais pour lister). La modale retombe désormais sur ces révisions Core quand `proxy_history` est vide, avec la config déjà incluse dans chaque révision (pas d'appel réseau supplémentaire). Le bouton "Restaurer" est masqué sur ces lignes (aucun endpoint Admin ne permet de restaurer une révision Core arbitraire) et une note indique la provenance Core-only. La comparaison de config, elle, fonctionne à l'identique dans les deux cas. (Webapp `0.9.8`)

### Retiré

- **Menu Core "Health checks" (`pages['core-health']`)** : la page dupliquait, par backend, une information déjà disponible dans "Trafic" (statut up/down par backend, via `GET /backends/health`) sans apporter de valeur propre. Entrée de nav, route (`app.config.js`, `router.js`) et implémentation (`core.js`) supprimées. L'endpoint `/api/v1/backends/health` reste utilisé par la page Trafic, inchangé. (Admin `0.11.4`, Webapp `0.9.7`)

### Changé

- **Historique de proxies + Diff config fusionnés en une seule modale** : les deux boutons distincts de la liste des proxies (`trafic.js`) ouvraient chacun leur propre modale, l'une listant les versions (restaurer), l'autre comparant deux révisions issues d'un système distinct (révisions Core via `revisions/diff`), sans lien entre les deux. Un seul bouton "Historique" ouvre désormais `openProxyVersionsModal` : la liste des versions (`proxy_history`) à gauche, un panneau de diff à droite. Cliquer sur une version affiche sa diff face à la configuration actuelle ; cliquer sur une deuxième version affiche la diff entre les deux versions sélectionnées (badges A/B sur les lignes) ; recliquer désélectionne, un 3ᵉ clic repart d'une sélection neuve. L'icône restaurer reste sur chaque ligne. Nouvel endpoint `GET /api/v1/backups/proxy-history/{id}/config` (config brute d'une version, pour calculer la diff côté client) ; le diff n'utilise plus l'historique des révisions Core (`revisions/diff`, toujours actif mais plus appelé depuis l'UI). (Admin `0.11.3`, Webapp `0.9.6`)

### Corrigé

- **Vue Admin "Menaces" — Core d'origine et raison absents, date jamais mise à jour, aucun tri/filtre** : la page (`renderAdminSecurityThreats`, `pages['security-threats']`) était une implémentation dupliquée et jamais raccordée aux vraies données — elle lisait `t.active`, `t.source`, `t.reason`, `t.core_name`/`t.core_id`, `e.ts`, `e.core_name`, `e.reason`/`e.detail`, aucun de ces champs n'existant sur `security.Threat` (`id, ip, scenario, origin, type, duration, created_at`) ni sur l'objet `event` de `/security/timeline` (`type, created_at, ip, domain, summary, severity, source`). Résultat : le bloc "Menaces actives" ne s'affichait jamais (`t.active` toujours `undefined`), la colonne Core toujours "—", la colonne Raison toujours "—", et la date de la timeline toujours "—". Par ailleurs `security_threats` a une contrainte unique `(ip, scenario)` et l'ingestion utilisait `INSERT OR IGNORE` : une même menace réémise plusieurs fois par CrowdSec ne créait jamais de nouvelle ligne et ne rafraîchissait jamais sa date — la date affichée restait celle de la toute première observation. Corrigé : nouvelles colonnes `security_threats.core_name` (résolu côté serveur depuis le token d'appairage de l'appelant, comme pour les CVE), `occurrences` et `last_seen_at` ; `handleInternalThreats` fait maintenant un upsert (`ON CONFLICT (ip, scenario) DO UPDATE`) qui incrémente `occurrences` et rafraîchit `last_seen_at`/`core_name` à chaque réception au lieu d'ignorer les doublons. La page Admin réutilise désormais le tableau Menaces mutualisé avec la vue Core (`threatsPanelHTML`/`threatsTableRows`/`filterSecThreatsList`), déjà doté de recherche, tri et filtre par type — avec une colonne Core en plus côté Admin (masquée côté Core, déjà scopé à un seul Core) et une colonne Occurrences. La timeline générique (bans/menaces/CVE tous types) affiche maintenant la vraie date (`e.created_at`) et le vrai résumé (`e.summary`) au lieu de champs inexistants. Les menaces enregistrées avant cette migration affichent Core "—" et 1 occurrence (valeurs jamais renseignées auparavant). (Admin `0.11.2`, Webapp `0.9.5`)

### Changé

- **Vue Admin "Vulnérabilités (CVE)" — carte "Scanner CVE" retirée, colonne Core ajoutée à la liste** : côté Admin, la carte affichait l'état d'un scan par backend (bouton "Scanner maintenant" déjà masqué, mais KPIs et détail par backend restaient visibles) alors que le scan est une action et un état propres à chaque Core — sans intérêt agrégé côté Admin, qui ne peut de toute façon rien y déclencher ni configurer. La carte "Scanner CVE" ne s'affiche plus que côté Core (`pages['core-security-vulns']`). En contrepartie, la liste des CVE (utile de façon transverse) affiche désormais une colonne "Core" en vue Admin, indiquant le Core d'origine de chaque CVE — résolu côté serveur (`handleInternalCVEs`, via le token d'appairage de l'appelant) et stocké dans une nouvelle colonne `security_cves.core_name`, exposée par `GET /security/cves`. Colonne masquée côté Core (déjà filtré sur ce Core, donc redondante). Les CVE existantes avant cette migration affichent "—" (Core inconnu, jamais renseigné). (Admin `0.11.1`, Webapp `0.9.4`)

### Corrigé

- **Volet "Domaines & certificats" (Deploy Targets / Pull Tokens) — fond transparent, contenu superposé à la page en dessous** : `openCertDeployPanel` (`cert-deploy.js`) fixait le fond du drawer avec `var(--bg1)`, une variable jamais définie dans les thèmes (`--bg`, `--bg2`, `--bg3` sont les seules qui existent). Sans valeur de repli, `background` restait transparent et laissait voir la page sous-jacente (horloge, liste des certificats) à travers tout le panneau, avec les boutons de la page ("+ Nouveau certificat", rafraîchir) qui se superposaient visuellement à ceux du drawer ("+ Nouveau target"). Remplacé par `var(--bg)`, cohérent avec le fond plein écran utilisé ailleurs pour ce type de panneau. (Webapp `0.9.3`)

- **Section "Scanner CVE" (bouton de scan manuel + coche réseau privé) inversée entre Admin et Core** : `renderSecurityVulns` conditionnait ces deux contrôles à `isAdmin` (`mode === 'admin'`), donc affichés côté Admin — qui ne doit montrer que l'agrégat des résultats de tous les Cores — et absents côté Core (`pages['core-security-vulns']`), qui est pourtant le seul endroit pertinent pour déclencher un scan et autoriser l'accès réseau privé de ce Core. Le bouton "Scanner maintenant" et la coche "Autoriser l'accès au réseau privé" ne s'affichent plus qu'en vue Core ; la vue Admin ne conserve que les KPIs, la liste des CVEs et le détail des résultats en lecture seule. (Webapp `0.9.1`)

- **Page Admin "Vulnérabilités" (`pages['security-vulns']`) — colonnes Package/Proxy/Core toujours à "—"** : cette page utilisait une implémentation historique distincte (`renderAdminSecurityVulns`), non touchée par le partage de code Admin/Core fait au-dessus, dont le tableau lisait `c.package`, `c.proxy_name`/`c.proxy_id` et `c.core_name` — des champs qui n'ont jamais existé dans la réponse de `GET /security/cves` (`security.CVE` n'expose que `id`, `backend_url`, `cve_id`, `cvss_score`, `description`, `status`, `detected_at`), d'où un tableau vide en pratique. `pages['security-vulns']` appelle maintenant la même `renderSecurityVulns({ mode: 'admin' })` que la vue Core (résultats agrégés tous Cores, sans le bouton de scan ni la coche réseau privé), qui affiche `backend_url` et `description` — les seules informations réellement renvoyées par l'API. L'ancienne fonction dupliquée est supprimée. (Webapp `0.9.2`)

### Changé

- **Politiques d'accès retiré de la 3ᵉ section de "Gestion d'équipe"** : maintenant qu'elle a sa propre landing (clic sur le groupe "Accès"), plus besoin de la dupliquer dans "Gestion d'équipe" — qui revient à 2 sections (Utilisateurs & équipes, Espaces de travail). (Webapp `0.9.0`)

- **Clic sur le groupe "Accès" → Politiques d'accès (au lieu de Gestion d'équipe)** : la vue matricielle croisée domaines × sujets offre une meilleure vue globale du périmètre d'accès et convient mieux comme landing du groupe nav. `pages.access` redirige désormais vers `access-policies`. (Webapp `0.9.0`)

### Corrigé

- **Health checks (Paramètres Core) — le rafraîchissement 30s écrasait la page courante après navigation** : `pages['core-health']` démarre un `setInterval(refresh, 30000)` qui écrit directement dans le `#content` capturé à l'ouverture de la page, et prévoyait bien un hook `content._cleanup` pour l'arrêter — mais le routeur ne l'appelait jamais. Le timer continuait de tourner indéfiniment après avoir quitté la page, et toutes les 30 s remplaçait le contenu affiché (n'importe quelle autre page) par "Health checks". Le routeur (`navigate()`) invoque désormais `content._cleanup()` sur la page sortante avant de charger la nouvelle — mécanisme générique réutilisable par toute page qui démarre un timer. (Webapp `0.9.0`)

- **`var(--card-bg)` — variable CSS jamais définie, fond transparent sur 15 usages dans 4 fichiers** : ni `--card-bg` ni `--input-bg` n'existent dans `themes/flat.css`/`industry-ds.css` (seuls `--bg`, `--bg2`, `--bg3` sont définis). Une variable CSS custom non définie et sans valeur de repli statique rend la propriété `background` transparente, laissant la page sous-jacente transparaître à travers le panneau/la carte censée avoir un fond opaque. Le plus visible : le volet détail d'un espace de travail (`workspaces.js`, `#ws-detail-panel`) laissait voir le contenu de la page en dessous (dates, boutons "+ Nouvel espace"/"+ Nouvelle équipe") à travers tout le panneau, pas seulement dans la marge assombrie du backdrop. Même bug dans le volet détail certificat ACME (`acme-monitor.js`), 7 cartes d'info dans `security.js`, et les `<select>` des modales Utilisateur/Équipe (`users.js`, repli sur `--input-bg` tout aussi indéfini). Remplacé par `var(--bg2)` — la variable réellement utilisée partout ailleurs (`.card`) pour les surfaces de carte. (Webapp `0.9.0`)

### Ajouté

- **"Politiques d'accès" intégré à Gestion d'équipe** : la matrice domaines × sujets (utilisateurs, équipes, tokens Core), purement en lecture seule (aucune action d'écriture, juste deux raccourcis de navigation), devient une 3ᵉ section de la page, après Utilisateurs & équipes et Espaces de travail. Son entrée sidebar dans Accès est retirée ; la tuile Paramètres (`settings.js`) et `pages['access-policies']` restent accessibles en direct (rendu identique, plein écran). La redirection de l'entrée parente "Accès" (clic sur le groupe lui-même) pointe désormais vers `workspaces` au lieu de `users`, cohérent avec le nouveau contenu. (Webapp `0.9.0`)

### Corrigé

- **`users.js` — erreur de syntaxe cassant tout le fichier (page Utilisateurs & équipes entièrement non fonctionnelle)** : le commit `a7d625a` (20/09, migration des backdrops de modale vers `document.body`) a changé `elt.innerHTML = \`...\`` (une affectation) en `document.body.insertAdjacentHTML('beforeend', \`...\`)` (un appel de fonction) pour les modales Utilisateur et Équipe, mais sans ajouter le `)` de fermeture correspondant à la fin du template literal. Un `SyntaxError` sur un fichier `<script>` classique empêche l'exécution de **tout son contenu** : `pages.users`, `refreshUsers`, `openUserModal`, `saveUser`, `openTeamModal`, `saveTeam`, etc. n'existaient tout simplement jamais. C'est la cause racine de "il n'y a rien dans l'onglet Utilisateurs" et, une fois les onglets retirés, de la page "Gestion d'équipe" entièrement vide (le premier appel `refreshUsers(...)` levait un `ReferenceError` avant même que la section Espaces de travail ne s'affiche). `node --check` sur ce fichier échouait déjà avant tout changement de cette session — non détecté plus tôt car jamais vérifié isolément. (Webapp `0.9.0`)

- **Gestion d'équipe — backdrop imbriqué en double sur le volet détail d'un espace de travail** : `_renderWorkspacePanel` récupérait le conteneur `#ws-detail-backdrop` (l'overlay plein écran lui-même) puis réinjectait dedans un **second** `<div id="ws-detail-backdrop" class="dialog-backdrop">` identique. Deux overlays semi-transparents superposés = fond anormalement sombre, IDs dupliqués dans le DOM. Le clic pour fermer en cliquant à l'extérieur n'était de plus jamais attaché sur le premier rendu (skeleton de chargement). Corrigé : l'overlay est créé une seule fois (avec son handler de fermeture), `_renderWorkspacePanel` ne remplace plus que le contenu du panneau interne (`#ws-detail-panel`). (Webapp `0.9.0`)

### Changé

- **Gestion d'équipe — onglets remplacés par des sections en scroll** : la bascule par onglets ("Utilisateurs & équipes" / "Espaces de travail") laisse place à une page unique : les deux blocs s'affichent l'un après l'autre, sans clic pour changer de vue. Simplifie aussi le rendu (plus d'état d'onglet actif à synchroniser). (Webapp `0.9.0`)

### Ajouté

- **Paramètres Core → Tokens d'appairage (récap lecture seule)** : nouvelle tuile dans la section Sécurité de Paramètres Core, affichant le(s) token(s) `role=core` appairés à ce nœud (statut actif/expiré/révoqué, rôle RBAC, scopes). La CRUD complète (création, édition des scopes, révocation) reste dans **Accès → Tokens d'appairage**, avec un bouton de raccourci — un token sert justement à appairer un Core qui n'existe pas encore, la gestion complète ne peut donc pas être scopée à un Core déjà appairé. (Webapp `0.9.0`)

### Corrigé

- **Menu Accès — libellé "Utilisateurs & équipes" jamais affiché** : `gpxPageLabel(page, fallback)` (i18n.js) donne toujours priorité à la clé `page.<page>` si elle existe, en ignorant totalement le `fallback` passé par `app.config.js`. La clé `page.users` valait encore `'Utilisateurs'` (FR) / `'Users'` (EN) / `'Usuarios'` (ES) / `'Benutzer'` (DE) dans les 4 langues — écrasant silencieusement le libellé `'Utilisateurs & équipes'` défini dans le sous-menu Accès depuis la fusion Users/Teams. Le libellé n'a donc jamais pu s'afficher, dans aucune langue, indépendamment du rôle ou du cache navigateur. Clés `page.users` mises à jour dans les 4 locales. (Webapp `0.9.0`)
- **Catalogue Access — modale d'édition mal empilée** : `portal-catalog.js` construisait son propre backdrop (`z-index:80`) injecté dans un conteneur `#pc-modal` à l'intérieur de `#content`, au lieu du composant partagé `.dialog-backdrop` (z-index 9999, `document.body`). Contrairement aux autres pages (Users, Workspaces, Cert Deploy, Trafic, Core) déjà corrigées en septembre, celle-ci n'avait jamais été migrée — cause probable de superpositions/z-index récurrentes sur cette modale. Migré vers le pattern standard. (Webapp `0.9.0`)
- **`docker-compose.yml` — tags d'images par défaut obsolètes** : `GOPROXIFY_ADMIN_TAG`, `GOPROXIFY_CORE_TAG` et `GOPROXIFY_AGENT_TAG` par défaut pointaient vers des versions périmées (`0.3.3`/`0.3.94`/`0.3.50`) désynchronisées de `versions.json`. Alignés sur `preview`, comme `docker-compose.quickstart.yml`, pour éviter que les défauts se re-périment à chaque release.
- **HA Admin — `/ha/status` renvoyait le mauvais `node_id`** : `ha.Manager.HandleStatus` retournait `LeaderID()` à la place de l'ID propre du nœud interrogé, faisant apparaître tous les nœuds (leader et followers) avec le même Node ID dans la page Statut HA. Ajout de `raft.Node.ID()` et correction du handler pour retourner l'identité réelle du nœud.
- **HA — Core backup ne recevait jamais le `full_sync` Admin** : `GPX_CORE_EXTRA_ENDPOINTS` était documenté mais non implémenté. `ConnectFromEnv` supporte désormais cette variable (format CSV `name=http://host:port`). L'Admin se connecte à chaque Core extra au démarrage et pousse le `full_sync`. (Admin `0.10.1`)

### Corrigé

- **Menu Accès — libellé "Tokens Core & Agent" jamais affiché** : même piège que `page.users`/`page.acme-monitor` — `app.config.js` déclarait `'Tokens Core & Agent'` pour l'entrée `tokens`, mais la clé i18n `page.tokens` (`'Tokens d'appairage'`, cohérente avec le titre de page et les 4 langues) l'écrasait silencieusement via `gpxPageLabel()`. Libellé du menu aligné sur ce qui s'affiche réellement. Audit des 4 entrées d'Accès (`tokens`, `access-policies`, `workspaces`, `acme-monitor`) : plus aucun écart config/i18n. (Webapp `0.9.0`)

### Ajouté

- **"Monitoring ACME" renommé "Domaines & certificats"** : reflète le périmètre élargi depuis la fusion avec Certificats/Déploiement (actions Déployer/Éditer ajoutées précédemment). Clé `page.acme-monitor` mise à jour en FR/EN (piège identique à celui corrigé pour `page.users` : `gpxPageLabel()` priorise toujours la traduction sur le libellé d'`app.config.js`). (Webapp `0.9.0`)
- **"Espaces de travail" renommé "Gestion d'équipe" et fusionné avec "Utilisateurs & équipes"** : l'entrée sidebar "Utilisateurs & équipes" est retirée d'Accès. Sa page (CRUD utilisateurs/équipes, grants, scopes) est intégrée comme onglet dans la page renommée **Accès → Gestion d'équipe**, aux côtés de l'onglet "Espaces de travail" (inchangé : conteneurs regroupant ressources + membres). `pages.users` reste accessible directement (liens internes depuis Politiques d'accès et Infrastructure) et continue de s'afficher en plein écran sans onglets. Aucun changement d'API. (Webapp `0.9.0`)
- **Fusion des pages certificats dans Monitoring ACME** : les menus "Certificats" (tuile Paramètres) et "Déploiement certificats" (sidebar Accès) sont retirés — tout se passe désormais depuis **Accès → Monitoring ACME**. Chaque ligne de certificat gagne deux actions : **Déployer** (ouvre le drawer de déploiement — webhook signé HMAC / SSH exec, tokens de pull HTTP existants, inchangés) et **Éditer** (ouvre la modale du domaine source — provider DNS, PEM manuel, Core d'entrée, délégation ; désactivé si le certificat n'a pas de domaine déclaré, ex. import manuel). Le lien mort "Aller au domaine" (`navigate('domains')`, page inexistante) est supprimé. Nouveau champ `domain_id` dans `GET /api/v1/certs/acme-monitor` pour relier certificat émis et domaine source. La page "Certificats TLS" du contexte Core (`Paramètres Core`) est inchangée, elle gère un périmètre différent (par Core). (Admin `0.11.0`, Webapp `0.9.0`)

- **Pseudonymisation IP RGPD + scope `gdpr:reveal`** : nouveau mode `ip_pseudonymize` dans les settings Logs. Le Core tronque l'IP dans son fichier local ; l'Admin reçoit l'IP réelle et la chiffre en AES-GCM 256 bits (clé générée à la table `gdpr_keys`). Nouveau scope RBAC `gdpr:reveal` (super-admin par défaut, délégable). Endpoint `POST /api/v1/logs/reveal-ip` : révèle l'IP d'une entrée avec motif obligatoire, crée une entrée d'audit `gdpr_reveal_ip`. Commande CLI `goproxify logs reveal-ip --entry-id xxx --reason "…"`. Documentation dans `docs/rgpd.md` §3 bis.

- **Anonymisation IP dans les access logs** : option `engine.ip_anonymize` dans `core.json` (et toggle Admin UI → Logs → Settings). IPv4 : dernier octet remplacé par 0 ; IPv6 : 80 derniers bits masqués. Fail2Ban et Sentinel reçoivent toujours l'IP réelle. Propagé en temps réel aux Cores via WS `push_settings`.
- **WAF — whitelist IP par route** : champ `waf_whitelist_ips` (tableau CIDRs) dans `WAFConfig`. Les IPs correspondantes bypassent complètement le WAF pour cette route (Fail2Ban/Sentinel restent actifs).
- **WAF — hot-reload depuis fichier externe** : champ `engine.waf_custom_rules_path` dans `core.json`. Le Core surveille le fichier toutes les 10 s et recharge les règles custom sans redémarrage.
- **Doc RGPD** : `docs/rgpd.md` — inventaire complet des données collectées, options de minimisation (anonymisation, rétention, droit à l'effacement), checklist opérateur, mesures de sécurité.
- **Benchmark** : `docs/benchmark.md` — méthodologie k6, résultats HTTP/1.1 passthrough et WAF vs Nginx/Caddy, instructions pour reproduire.

### Ajouté

- **Monitoring ACME — multi-fournisseurs** : la page "Monitoring ACME" peut désormais gérer plusieurs fournisseurs DNS nommés (ex: "cloudflare-prod", "ovh-zone2"). Nouvelle table `acme_providers` (id, name, type, params JSON). Nouveaux endpoints CRUD `/api/v1/acme/providers`. Section "DNS Providers" dans l'UI avec liste des providers configurés, badges colorés, formulaire d'ajout/édition (nom, type, credentials JSON) et suppression par provider.

- **Prism — carte live** : en mode Live, la carte monde affiche désormais des points pulsants animés par pays au fil des connexions entrantes (bleu = visite, rouge = ban, orange = erreur). Un flux "Connexions temps réel" scrollant apparaît sous la carte avec IP, pays, domaine, statut et horodatage. Nouveau endpoint backend `/api/v1/prism/live-ips` (polling toutes les 4 s) et fonction analytics `GetLiveIPs` qui joint `logs`, `geoip_cache` et `security_bans` pour classifier chaque événement.

### Amélioré

- **UI Monitoring ACME** : la page affiche désormais le fournisseur DNS associé à chaque certificat (via jointure avec la table `domains`), avec un badge coloré par provider (Cloudflare, OVH, Gandi, Hetzner, Route 53). Ajout d'un panneau "Configuration ACME" en haut permettant de visualiser et modifier la config globale (activé, email, provider, directory URL). Ajout du bouton "Supprimer" par certificat. Nouveau panel détail latéral (clic sur une ligne) avec lien vers la section Domaines. Toutes les modales utilisent `document.body` pour éviter les problèmes de stacking context.

### Ajouté

- **UI Modale sécurité proxy — section WAF** : indicateur d'héritage Core (bannière verte "Hérite de la config WAF du Core"), détection automatique de plateforme depuis l'URL upstream (WordPress, Drupal, Nextcloud, DokuWiki, cPanel), liste manuelle de plateformes avec cases à cocher, bouton "↩ Hériter du Core" pour réinitialiser. Champ `exclude_platforms` persisté dans la config WAF du proxy.
- **API / Modèle** : champ `exclude_platforms []string` ajouté à `WAFConfig` dans `route.go` — plateformes applicatives pour lesquelles les règles WAF générant des faux positifs seront exclues automatiquement (union avec `ExcludeIDs`).

### Corrigé

- **i18n ACME** : traductions ES et DE complètes pour toutes les clés `acme_monitor.*` (providers, new_cert) — la page s'affichait en anglais pour ces locales. Ajout de `common.optional` et `common.required` en ES et DE.
- **ACME — icônes actions** : les boutons texte "Edit"/"Delete" (providers DNS) et "Renew"/"Delete" (certificats) remplacés par des icônes SVG avec tooltip `title`.
- **Wizard — fournisseurs ACME dynamiques** : le wizard chargé depuis `/acme/providers` la liste des fournisseurs nommés configurés ; le sélecteur DNS affiche désormais ces providers réels ("cloudflare-prod (cloudflare)") au lieu d'une liste statique générique. Fallback sur la liste statique si aucun provider n'est configuré.

- **UI Sentinel (sécurité Core)** : clés i18n `page.core-security-sentinel` et `common.active`/`common.inactive` manquantes dans les 4 locales — les étiquettes affichaient le nom de clé brut. Icônes améliorées pour Fail2Ban (stylo/édition), CrowdSec (bouclier avec alerte) et Sentinel (œil de surveillance).
- **UI Tunnel L4 mTLS** : double préfixe `/api/v1` dans les appels `api()` — GET et PUT `tunnel-config` échouaient silencieusement
- **UI modales (transparence)** : tous les backdrops `position:fixed` rendus dans `#content` échappaient à la fenêtre si le conteneur parent créait un nouveau contexte d'empilement — modales déplacées directement dans `document.body` (`insertAdjacentHTML('beforeend')`) dans `workspaces.js`, `cert-deploy.js`, `users.js`, `trafic.js` et `core.js`
- **UI Workspaces** : padding et bordure manquants dans le footer du modal "Nouvel espace" — la classe CSS `dialog-footer` n'était pas définie (alias vers `dialog-actions` ajouté)
- **UI modales** : harmonisation du z-index sur toutes les modales/panels (cert-deploy, workspaces, trafic, core, users) — cert-deploy utilisait z-index:9990 au lieu de 9999 ; nettoyage des inline styles redondants avec la classe `dialog-backdrop`
- **i18n** : ajout de la clé `common.add` manquante (EN/FR/ES/DE) — les boutons "Ajouter" affichaient le nom de clé brut dans le panel Workspaces
- **UI Health checks** : groupement par proxy cassé — regex supposait un format d'URL inexistant ; cross-référence correcte via les backends déclarés dans chaque proxy ; rendu amélioré (chips colorés au lieu d'un tableau)


### Ajouté — MCP server étendu : outils Certificate Hub (`admin`)

- **`get_cert_status`** : statut d'expiration de tous les certs avec KPIs (ok/warning/critical/expired) + filtre domaine optionnel ; resource URI `goproxify://certs/monitor`
- **`list_cert_deploy_targets`** : liste les cibles de déploiement d'un cert (webhook, ssh_exec) avec dernier statut
- **`trigger_cert_deploy`** : déclenche immédiatement le déploiement d'un cert vers une cible spécifique
- **`import_cert`** : importe un certificat externe (PEM + clé) — extraction automatique du domaine (SAN/CN), upsert en DB

### Ajouté — Import de certificats externes (`webapp` · `admin`)

- **Endpoint `POST /api/v1/certs/import`** : accepte `{cert_pem, key_pem, issuer?}`, valide le bloc PEM, extrait domaine (SAN/CN) et `expires_at` depuis le certificat, upsert en DB — écrase un cert existant sur le même domaine
- Après import, le certificat est poussé en temps réel aux Cores via `CertImportPusher` (même chemin que les certs ACME)
- **Page Admin `acme-monitor`** : bouton "+ Importer un certificat" → modal PEM (cert + clé + émetteur optionnel) ; auto-refresh 60s avec nettoyage du timer à la navigation

### Ajouté — Monitoring ACME & alertes d'expiration (`webapp` · `admin`)

- **Endpoint `GET /api/v1/certs/acme-monitor`** — retourne par cert : `days_left`, `status` (`ok`/`warning`/`critical`/`expired`) + KPIs résumés (`total`, `ok`, `warning`, `critical`, `expired`)
- **Alertes automatiques** : callback `OnCertExpiring` dans `acme.Manager` — déclenché à chaque cycle 12h pour tous les certs expirant dans ≤ 30 jours → émission de `TriggerCertExpiringSoon` (warning ≤30j, critical ≤7j) vers le moteur d'alertes existant
- **Page Admin `acme-monitor`** : 5 tuiles KPI (total / valides / ≤30j / ≤7j / expirés), tableau avec badge statut coloré, date d'expiration, date de dernier renouvellement, bouton "Renouveler" inline — accessible via Accès → Monitoring ACME

### Ajouté — Certificate Deploy Hub (`webapp` · `admin`)

- **3 nouvelles tables SQLite** : `cert_deploy_targets` (webhook, pull_token, ssh_exec), `cert_pull_tokens` (tokens signés HMAC, TTL, max_uses), `cert_deploy_history` (audit de chaque déploiement)
- **Deploy targets** : CRUD `GET|POST /api/v1/certs/{id}/deploy-targets`, `DELETE /…/{targetID}`, `POST /…/{targetID}/trigger`, `GET /…/{targetID}/history` — déclenchement automatique à chaque renouvellement ACME ou manuel
- **Webhook push** : POST HMAC-SHA256 signé (`X-GoProxify-Signature: sha256=…`) vers n'importe quelle URL avec retry — payload JSON `{domain, cert_pem, key_pem, chain_pem, fingerprint, expires_at}`
- **Pull tokens** : génération de tokens sécurisés (hash HMAC-SHA256, TTL, max_uses) — `GET /api/v1/cert-bundle?token=xxx&format=pem|key|fullchain|json` — endpoint **public** sans auth, téléchargeable par simple `curl`
- **Hook OnCertObtained** dans `acme.Manager` — déclenche automatiquement `certdeploy.Deployer.TriggerForCert` après chaque renouvellement
- **SSH exec target** : déploiement via SSH vers n'importe quelle machine — GoProxify SSHe à la cible et exécute un script configurable avec les variables `GPX_CERT_PEM / GPX_KEY_PEM / GPX_DOMAIN / GPX_EXPIRES_AT` injectées
- **Package `certformat`** : conversion PEM→DER, DER clé (PKCS#8), PKCS#12/PFX (`software.sslmate.com/src/go-pkcs12`), fullchain, JSON — endpoint `cert-bundle` utilise désormais `certformat.Convert` avec validation du format à la création du token
- **Page Admin** `cert-deploy` : liste des certificats, drawer de gestion par cert, onglets "Deploy Targets" / "Pull Tokens", modal de création target (webhook + ssh_exec), modal de création token avec tous les formats (PEM/DER/PKCS#12/JSON) + champ mot de passe PKCS#12 conditionnel + exemple `curl` affiché one-time

### Ajouté — Workspaces : espaces de travail multi-tenant (`webapp` · `admin`)

- **3 nouvelles tables SQLite** : `workspaces` (nom, description, créateur), `workspace_members` (user/team), `workspace_resources` (proxy/domain/core)
- **API CRUD** `GET|POST /api/v1/workspaces`, `GET|PUT|DELETE /api/v1/workspaces/{id}`, gestion membres (`POST|DELETE /api/v1/workspaces/{id}/members/{type}/{id}`) et ressources (`POST|DELETE /api/v1/workspaces/{id}/resources/{type}/{id}`)
- **Page Admin** `workspaces` : grille de cards avec compteurs membres/ressources, panneau latéral de détail — ajout/suppression membres (équipes + utilisateurs) et ressources (proxies, cores, domaines par pattern)
- Accessible via le menu **Accès → Espaces de travail** (réservé admin/superadmin)

### Ajouté — Ban Intelligence : dashboard IP rejetées (`webapp` · `admin`)

- **5 endpoints** `GET /api/v1/security/bans/intel/{kpis,by-reason,by-source,timeline,top-ips}` — analyse historique sur `security_ban_history` + `security_bans`
- **Vue Admin** (`security-bans`) refonte complète : 4 KPIs, sparkline 48h, donut raisons (SVG), barres par source, top 20 IPs récidivistes avec débannissement en 1 clic
- **Vue Core** (`core-security-bans`) : bans actifs + intelligence fusionnés — onglets Actifs / Analyse / CrowdSec / Historique sur la même page

### Ajouté — UX opérateur avancée — B1/B2/B3 (`webapp` · `admin`)

- **B1 — Page Health checks par route** (`core-health`) : tableau des backends groupés par proxy avec statut up/down, paramètres HealthCheck (path, interval, seuils), rafraîchissement auto 30 s
- **B2 — Tunnel L4 mTLS complet** (`core-tunnel`) : UI + API Admin `GET/PUT /api/v1/nodes/{id}/tunnel-config` + table `node_tunnel_configs` + **WS push Admin→Core** (`push_tunnel_config`) — les peers configurés sont désormais poussés en temps réel au Core et appliqués via `tunnel.Manager.SetPeers`
- **B3 — Diff de config proxy** : endpoint `GET /api/v1/proxies/{id}/revisions/diff?from=&to=` + **bouton "Diff config" dans trafic.js** — modal interactif avec sélecteurs de révisions, tableau de diff champ par champ (avant/après mis en évidence)
- **UX Sécurité Core** : "Moteurs de sécurité" devient une section de configuration inline dans la page `core-security` (toggles Fail2Ban/CrowdSec/Sentinel avec leurs panels) — le sous-menu "Moteurs IPS" est supprimé
- Client `coreproxy` : ajout de `ListRevisions(ctx, target, id)` (proxy vers `GET /internal/v1/proxies/{id}/revisions`)

### Ajouté — Observabilité bans dans Prism (`webapp` · `admin`)

- **Section "Bans IP" dans Prism** : timeline bans/heure (SVG sparkline), répartition par source (barres), top 15 IPs les plus bannies
- **API Prism** : 3 nouveaux endpoints — `GET /api/v1/prism/bans/timeline`, `GET /api/v1/prism/bans/by-source`, `GET /api/v1/prism/bans/top-ips` — alimentés depuis `security_ban_history` et `security_bans`
- **Export CSV bans** : bouton "CSV" sur la page Bans + endpoint `GET /api/v1/security/bans/export?format=csv|json` (10 000 bans max, fichier `bans-export-<ts>.csv`)
- **Export CSV bans dans Prism** : lien "Export CSV" dans le panneau Bans de Prism

### Documentation

- **README translated to English**: `README.md` is now in English, with a user-centered introduction (value proposition, concrete use case, 7 differentiators). The French version is preserved as `README.fr.md`.
- **Docs translated to English**: `docs/faq.md`, `docs/architecture.md`, `docs/fonctionnalites.md` fully translated from French to English for an international audience.

---

## [0.4.0] — 2026-09-19

### Corrigé — Agrégation complète des bans Rules Engine dans l'Admin (`admin`)

- **`internal/core/ws/messages.go`** : ajout de `ActionType` dans `RuleFiredPayload` (propagé depuis `ExecLog`)
- **`internal/core/rulesengine/types.go`** : ajout de `ActionType string` dans `ExecLog`
- **`internal/core/rulesengine/engine.go`** : `evalRule` peuple `ActionType` dans le log d'exécution
- **`internal/core/rulesengine/actions.go`** : `execBanIP` enrichit `Detail` avec `ban_reason`, `ban_expires_at`, `ban_duration` — permet à l'Admin de reconstruire le ban
- **`internal/admin/corews/manager.go`** : `handleRuleFired` insère maintenant dans `security_bans` + `security_ban_history` quand `action_type == ban_ip` — complète l'agrégation des 4 sources (F2B, CrowdSec, Threat, Rules Engine)

### Ajouté — Base de données SQLite bans dans le Core (`core`)

- **`internal/core/bansdb/`** : nouveau package SQLite local (CGO-free, `modernc.org/sqlite`)
  - Table `bans` : bans actifs par source (admin, fail2ban, crowdsec, rules_engine, threat) avec expiration
  - Table `ban_history` : historique complet (remplace le ring buffer de 2000 entrées), indexé par IP + date
  - Table `proxy_errors` : journal HTTP par domaine (remplace le ring buffer de 5000 entrées), purgé toutes les 48h
  - Écriture atomique WAL + synchronisation NORMAL
  - `ActiveBans()`, `UpsertBan()`, `DeleteBan()`, `DeleteBansBySource()`, `RecordBanEvent()`, `RecentBanCount()`, `RepeatBanIP()`, `BanHistorySince()`, `RecordProxyEvent()`, `ProxyErrorRate()`, purge par source/date
- **`internal/core/server.go`** : champ `bansDB *bansdb.DB` ; suppression des ring buffers `banEvents`/`proxyErrLog` et de `lastBanList` ; initialisation au démarrage + fermeture à l'arrêt
- **`internal/core/persistence.go`** : `applyBans` persiste via DB (source "admin") ; `loadBansFromDisk` lit depuis DB ; `bansDBPurgeLoop` purge toutes les heures (expirés + historique > 30j + proxy_errors > 48h)
- **`internal/core/internalapi.go`** : helper `reloadBanStore()` reconstruit le BanStore en mémoire depuis DB + pendingThreatBans ; `onF2BBan`, `onCrowdSecBansChanged`, `addRuleBan` utilisent la DB ; `addBanEvent`, `recentBanCount`, `repeatBanIP`, `recordProxyEvent`, `proxyErrorRate` délèguent à la DB
- **API interne Core** : nouveaux endpoints `GET /internal/v1/bans`, `GET /internal/v1/bans/history`, `DELETE /internal/v1/bans/{id}`

### Ajouté — Moteur de règles automatiques autonome dans le Core (`core`)

- **`internal/core/rulesengine/`** : nouveau package — moteur de règles entièrement autonome dans le Core
  - `types.go` : `Rule`, `Condition`, `Action`, `ExecLog` (miroir du moteur Admin, sans champs DB)
  - `evaluators.go` : évaluation via callbacks Deps (`GetRecentBanCount`, `GetRepeatBanIP`, `GetF2BLastActivity`, `GetCrowdSecLastSync`, `GetProxyErrorRate`) ; `CondCVECritical` retourne toujours false (pas de données CVE dans le Core)
  - `actions.go` : actions via Deps (`DisableProxy`, `BanIP`, `EmitNotify`, `EnableStrictF2B`)
  - `engine.go` : tick toutes les 60 s, cooldown par règle, `ReplaceRules` dynamique, `OnRuleFired` callback
  - Fonctionne **sans l'Admin** — le Core évalue les règles en autonomie
- **`internal/core/server.go`** : ring buffer `banEvents` (2 000 entrées) alimenté depuis F2B, CrowdSec et le moteur de règles lui-même ; ring buffer `proxyErrLog` (5 000 entrées) alimenté via `accessLog.SetProxyTap` ; wiring complet des Deps ; `EnableStrictF2B` réduit `MaxErrors` à 5 pendant la durée configurée
- **`internal/core/logger/accesslog.go`** : ajout de `SetProxyTap(func(domain string, status int))` pour alimenter le taux d'erreur proxy
- **`internal/core/fail2ban/fail2ban.go`** : ajout de `LastBan() time.Time` pour la condition `EngineSilent`
- **`internal/core/router/table.go`** : ajout de `DisableByIDOrHost(idOrHost string)` pour l'action `disable_proxy`
- **`corews`** : nouveaux messages `TypePushAutoRules` (Admin→Core) et `TypeRuleFired` (Core→Admin) + `RuleFiredPayload`
- **`internal/core/wshandlers.go`** : handler `TypePushAutoRules` → `rulesEngine.ReplaceRules`
- **`internal/core/internalapi.go`** : méthodes `addBanEvent`, `recentBanCount`, `repeatBanIP`, `recordProxyEvent`, `proxyErrorRate`, `addRuleBan`, `onRuleFired`, `onRuleNotify`
- **Admin `corews/manager`** : handler `handleRuleFired` qui persiste dans `rules_engine_history` et met à jour `last_fired_at`/`fire_count` ; méthode `PushAutoRules` pour envoyer les règles à tous les Cores au connect

### Ajouté — Moteur CrowdSec autonome dans le Core (`core`)

- **`internal/core/crowdsec/`** : nouveau bouncer CrowdSec entièrement autonome dans le Core
  - État en mémoire (`[]Decision`) + snapshot JSON (`/etc/goproxify/crowdsec/threats.json`) chargé au démarrage
  - Synchronisation LAPI HTTP toutes les 60 s, `SyncNow` immédiat sur changement de config
  - `OnBansChanged` : reconstruit la liste de bans actifs + notifie le `banStore` local
  - `OnDecisions` : notifie l'Admin des nouvelles/supprimées décisions via WS (`TypeCrowdSecDecisions`)
  - Fonctionne **sans l'Admin** — le Core banne en autonomie
- **`corews`** : nouveaux messages `TypePushCrowdSecConfig` (Admin→Core) et `TypeCrowdSecDecisions` (Core→Admin)
- **Admin `corews/manager`** : handler `handleCrowdSecDecisions` qui persiste dans `security_threats`/`security_bans`
- **Admin `corews/manager`** : méthode `PushCrowdSecConfig` pour synchroniser la config vers un ou tous les Cores

### Ajouté — Moteur Fail2Ban autonome dans le Core (`core`)

- **`internal/core/fail2ban/`** : nouveau moteur Fail2Ban entièrement autonome dans le Core
  - Fenêtre glissante en mémoire par IP (pas de DB), alimenté directement depuis l'`AccessLogger` via un tap non-bloquant
  - Config persistée sur le volume Core en JSON (`/etc/goproxify/fail2ban/config.json`)
  - `OnBan` : applique le ban immédiatement dans le `banStore` local + persiste dans `bans.json` + notifie l'Admin via WS (`TypeF2BBan`)
  - Fonctionne **sans l'Admin** — le Core banne en autonomie, l'Admin reçoit une notification s'il est connecté
- **`AccessLogger`** : ajout de `SetF2BTap(func(ip, status))` pour alimenter le moteur sans overhead
- **`corews`** : nouveaux messages `TypePushF2BConfig` (Admin→Core) et `TypeF2BBan` (Core→Admin)
- **Admin `corews/manager`** : handler `handleF2BBan` qui persiste le ban dans `security_bans` et émet une alerte
- **Admin `corews/manager`** : méthode `PushF2BConfig` pour synchroniser la config vers un ou tous les Cores

### Ajouté — Dashboard sécurité agrégé Admin (`webapp`)

- **Admin > Sécurité** (vue globale) : KPIs agrégés tous Cores (bans actifs, décisions CrowdSec, CVEs critiques, score posture moyen), état engines IPS (F2B/CrowdSec/WAF), alertes certificats, tableau rapide des Cores avec lien "Voir ce Core"
- **Admin > Sécurité > Bans** : bans actifs agrégés tous Cores avec répartition par source (F2B/CrowdSec/natif) et par Core, historique
- **Admin > Sécurité > Vulnérabilités** : CVEs classées par sévérité (critiques/élevées/moyennes/corrigées) tous Cores, badge CVSS coloré, lien proxy + Core
- **Admin > Sécurité > Menaces** : timeline événements tous Cores (100 derniers), menaces actives avec source et Core
- **Admin > Automatisation** : Règles automatiques (globales, moteur Admin)

### Modifié — Réorganisation navigation admin/core (`webapp`)

- **Admin** : suppression des doublons de sécurité (`security-vulns`, `security-posture`, `security-bans`, `security-sentinel`) — ces pages existent uniquement dans le menu Core
- **Admin** : groupe "Sécurité" remplacé par "Automatisation" (contient uniquement les Règles automatiques, qui restent globales)
- **Core** : ajout de "Moteurs IPS" (`core-security-ips-engines`) dans le menu Sécurité du Core — la config F2B/CrowdSec/WAF est poussée aux Cores, elle se configure donc par Core
- Principe : Admin = gestion plateforme + vues agrégées ; Core = tout ce qui tourne dans un Core

### Ajouté — Intégration métriques Prometheus dans l'UI admin (`webapp` 0.4.5)

- **Dashboard** : bande temps réel (req/s global, taux d'erreur 5xx, bytes in/out) ; sparklines p95 latence + req/s sur chaque nœud Core ; alertes cert expiry Prometheus (<7j) ; indicateur backends dégradés
- **Trafic/Proxies** : bande métriques par proxy sur chaque tuile (req/s, taux d'erreur, p95, backends up)
- **Sécurité Overview** : 4 tuiles métriques (Fail2Ban bans/scans, CrowdSec new/deleted, WAF profils actifs, Pipeline top 3 stages)
- **Moteur de règles** : bande métriques (cycles/min, durée moy., règles actives, actions déclenchées)
- **Infrastructure** : bande métriques cluster (WS Admin/Agent connections, peer sync moyen)
- **Domaines/TLS** : enrichissement cert expiry depuis Prometheus + p95 handshake et connexions actives
- **Portal** : KPI sessions actives (one_shot vs multi) depuis `gpx_portal_sessions_active`
- **Prism** : section top proxies (p95 latence + taux d'erreur) depuis `/internal/v1/metrics/summary`

### Ajouté — Métriques complètes tous services (`core` 0.3.96 · `admin` 0.3.5)

- **Backend health** : `gpx_backend_up{backend}` (gauge 0/1) — `MarkUp`/`MarkDown` instrumentés dans `proxy/healthcheck.go`
- **Peer sync** : `gpx_peer_sync_duration_seconds{peer}` (histogram) — `syncPeer()` instrumenté dans `gateway_peers.go`
- **WAF comportemental** : `gpx_waf_profiles_active` (gauge) — mis à jour dans `behavior/store.go` après chaque GC
- **Portal sessions** : `gpx_portal_sessions_active{type}` (gauge) — mis à jour dans `portal/session.go` après chaque mutation
- **Admin HTTP** : `gpx_admin_http_requests_total{method,status}` et `gpx_admin_http_request_duration_seconds{method}` — `logMiddleware` instrumenté
- **VulnScan** : `gpx_vulnscan_cves_detected_total{severity}`, `gpx_vulnscan_scans_total{result}`, `gpx_vulnscan_scan_duration_seconds` — scanner instrumenté
- **Rules Engine** : `gpx_rulesengine_eval_duration_seconds` (histogram), `gpx_rulesengine_active_rules` (gauge) — `evalAll()` instrumenté

### Ajouté — Métriques par proxy (`core` 0.3.95 · `admin` 0.3.4)

- **Option A** — `handleMetricsSummary` (`GET /internal/v1/metrics/summary`) : nouveau champ `proxies[]` avec détail par host : `requests`, `errors`, `error_rate`, `p95_ms`, `active_requests`, `bytes_in`, `bytes_out`, `blocked_total`
- **Option B** — Prometheus : 2 nouveaux CounterVec `gpx_core_bytes_received_by_host_total{host}` et `gpx_core_bytes_sent_by_host_total{host}` pour tracer les octets par proxy ; `dispatch.go` mis à jour
- **Option C** — Métriques Prometheus des moteurs Admin (`internal/admin/adminmetrics`) :
  - `gpx_f2b_bans_total` / `gpx_f2b_scans_total` (Fail2Ban)
  - `gpx_crowdsec_decisions_total{action}` / `gpx_crowdsec_syncs_total{result}` (CrowdSec)
  - `gpx_rulesengine_evals_total` / `gpx_rulesengine_actions_total{action,result}` (moteur de règles)

### Modifié — Moteurs de ban indépendants (`webapp` 0.4.4)

- **Page Moteurs de ban** : remplacement du sélecteur radio exclusif (native/fail2ban/crowdsec) par 3 cartes indépendantes avec toggle — Fail2Ban, CrowdSec et Sentinel peuvent être activés simultanément
- Chaque carte reflète l'état réel (`enabled`) de chaque moteur et permet de le toggler instantanément sans rechargement
- Carte Sentinel ajoutée sur la page moteurs avec lien vers le dashboard avancé
- **Overview sécurité** : grille des moteurs utilise désormais les états réels (`f2bCfg.enabled`, `csCfg.enabled`, `threatCfg.enabled`) et non plus le provider radio
- i18n : nouveaux clés `engine_enabled`, `engine_disabled`, `ips_engines.multi_hint`, `sentinel_desc/hint/config` dans 4 locales

### Ajouté — Moteur de règles automatiques IPS (`admin` 0.3.0 · `webapp` 0.4.0)

- **Moteur de règles** (`internal/admin/rulesengine`) : boucle de poll 60 s, évaluation par condition, cooldown par règle, `EvalNow()` dry-run
- **5 types de conditions** : CVE critique (seuil CVSS), pic de bans (fenêtre glissante), moteur silencieux (F2B/CrowdSec inactif), taux d'erreur proxy (5xx), IP récidiviste (N bans en M minutes)
- **4 types d'actions** : désactiver proxy, bannir IP, alerte, activer mode strict F2B
- **API REST** `/api/v1/rules-engine` : CRUD règles, historique d'exécution, lancement à la demande, descripteurs de conditions
- **Migration DB** : tables `rules_engine_rules` et `rules_engine_history`
- **Wiring** `server.go` : deps injectées (DisableProxy, CreateBan, EmitAlert, LastActivity, LastSync)
- **Méthodes** `LastActivity()` sur `fail2ban.Engine`, `LastSync()` sur `crowdsec.Bouncer`
- **UI Admin** : page "Règles automatiques" (admin/superadmin), nav entry, liste avec toggle/run/edit/delete, modal de création dynamique, onglet historique
- **Page Bans refonte** : 4 tuiles KPI (bans actifs, par source, décisions CrowdSec, expirant dans 1h), 3 onglets (Actifs / CrowdSec / Historique)
- **Page Moteurs IPS** : sélecteur unifié Fail2Ban / CrowdSec avec panneaux de configuration
- **Overview sécurité** : tuile "Règles automatiques" + grille moteurs 4 colonnes (F2B, CrowdSec, Sentinel, Règles)
- i18n ajouté dans les 4 locales (EN/FR/ES/DE) : `security.rules.*`, `security.ips_engines.*`, `security.bans.kpi_*`, `security.bans.tab_*`

### Ajouté — WAF : 6 nouveaux jeux de règles OWASP CRS-4

- **Java / Log4Shell (944xxx)** : détection JNDI injection (`${jndi:ldap://...}`), Spring EL (`#{Runtime.exec()}`), gadgets de désérialisation Java
- **Remote File Inclusion (931xxx)** : URLs distantes dans les paramètres, wrappers PHP (`php://filter`, `phar://`, `data://`)
- **NodeJS / Prototype Pollution (934xxx)** : injection `__proto__`, `constructor.prototype`, modules Node (`require()`, `child_process`)
- **HTTP Request Smuggling (920xxx)** : coexistence TE+CL, chunked encoding obfusqué
- **Fichiers sensibles / Restricted Files (930xxx)** : accès à `.env`, `.git/`, `wp-config.php`, dumps SQL, fichiers de debug (`phpinfo.php`, `composer.json`…)
- **Fuite de données en réponse (951xxx)** : erreurs SQL dans les réponses, stack traces PHP/Java, clés AWS (`AKIA…`)

**Nouveau — Inspection des réponses** : le moteur WAF peut désormais analyser les corps de réponse (règles `TargetResponse`). En mode `block`, une réponse contenant une fuite est bloquée avant transmission au client. En mode `detect`, la fuite est loguée sans bloquer.

**UI Admin** : le tableau des jeux de règles WAF (page Core > WAF) affiche les 13 catégories (anciennement 7). La désactivation par catégorie couvre les nouveaux IDs.

### Ajouté — Diagnostic trafic

- **Test du chemin de trafic à la demande** (`feat(trafic)`) : exécution étape par étape du chemin d'une requête depuis l'Admin pour diagnostiquer les configurations de routage

### Corrigé

- `fix(auth)` : garde `checkNeedOnboarding` contre le script non chargé — évite une erreur JS au démarrage si le module d'onboarding est absent
- `fix(bans)` : historique de ban — entrées manquantes pour les re-bans et source affichée en brut corrigées

### Documentation

- `docs/security.md` créé : documentation complète des moteurs de sécurité (WAF 13 règles, Sentinel, bans, GeoIP, timeouts, scanner CVE, métriques Prometheus)
- Landing page : carte « Moteurs de sécurité » ajoutée dans la section Documentation ; bullets WAF/Sentinel mis à jour (EN/FR/ES/DE)
- `README.md` et `suivi/roadmap-public.md` mis à jour pour refléter la v0.3

---

## [0.3.1] — 2026-09-17

### Ajouté — Sécurité : Sentinel, WAF, anti-DDoS

**Sentinel — ban immédiat sur signal comportemental**
- `Check()` appelle désormais `banFn` immédiatement dès qu'un signal non-rate (`path`, `ip`, `ua`, `custom_*`) dépasse le seuil. Avant ce fix, une IP pouvait scanner indéfiniment : chaque requête était rejetée individuellement mais l'IP n'était jamais bannie en base.

**Sentinel — paramètres exposés dans l'UI**
- Formulaire Sentinel : fenêtre rate (`rate_window`), seuil ban auto rate (`rate_ban_threshold` + `rate_ban_window`), limite globale anti-DDoS (`global_rps` + `global_burst`)

**Anti-DDoS — timeouts serveur HTTP/QUIC configurables**
- Paramètres `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout` configurables depuis l'Admin (section Sécurité > Paramètres serveur)
- Propagation via WS (`TypePushServerConfig`) et push HTTP legacy
- Avertissement UI : redémarrage requis pour que les timeouts prennent effet

**Vulnscan — autorisation optionnelle des backends IP privées**
- Toggle admin dans le panel Scanner CVE : autorise le scan de backends sur des IPs privées (SSRF opt-in, désactivé par défaut)
- Configurable via UI ou variable d'environnement `GPX_VULNSCAN_ALLOW_PRIVATE`
- API `GET/PUT /security/vulnscan/config` exposée

**Indicateurs d'état des moteurs de sécurité**
- Vue d'ensemble Sécurité : badges d'état pour chaque moteur (WAF, Sentinel, CrowdSec, Fail2Ban, GeoIP)

**Bans — accès rapide Prism depuis la table**
- Bouton « Prism » dans la table des bans actifs : ouvre Prism filtré sur l'IP bannie

### Corrigé

- `fix(security)` : dates `created_at` affichées en `01/01/0001` — normalisées via `strftime` SQLite

---

## [0.3.0] — 2026-09-12

### Ajouté — WAF avancé + moteur Sentinel

**WAF — inspection et scoring (Core `0.3.72`)**
- Scoring anomalie par requête : chaque règle contribue un score, seuil configurable avant blocage
- Inspection corps JSON et form-data (pas uniquement les headers/URI)
- Règles custom hot-reload (rechargement sans redémarrage)
- Métriques WAF exposées (`goproxify_waf_*`) : hits par règle, scores, bloqués vs détectés
- Access log WAF : chaque décision tracée dans les logs d'accès

**Sentinel — moteur de détection comportementale**
- Analyse comportementale stateful par IP : fenêtre glissante configurable (taux d'erreurs, fréquence, patterns)
- Scoring anomalie Sentinel indépendant du WAF (complémentaire)
- Detect mode : log sans bloquer, pour calibrer les seuils avant mise en production
- Listes custom IP allowlist/denylist intégrées au moteur Sentinel
- Métriques Sentinel : événements, scores, décisions
- Propagation de la config Sentinel de l'Admin vers tous les Cores (WS)

**UI Admin**
- Nom « Sentinel » déployé dans l'interface (remplace l'ancienne appellation générique)
- Page et section dédiées WAF/Sentinel dans les paramètres de sécurité
- Section **Accès centralisée** + page **Politiques d'accès** : vue unifiée des règles IP/GeoIP/Bot par proxy
- Fix badges cert et alignement en-têtes colonnes dans la page Politiques d'accès

### Ajouté — Logs : corrélation et performances

**Corrélation exacte par `request_id` (Admin `0.2.122`, Core `0.3.69`)**
- Chaque requête porte un `request_id` unique ; les logs Admin et Core sont corrélés par cet identifiant
- Fix : `RealIP` appliqué dans le middleware admin pour éviter la double IP dans les logs
- Corrélation élargie aux logs admin (même identifiant visible dans Prism et les logs d'accès)

**Performances et affichage (Admin `0.2.121`, Webapp `0.3.102`)**
- Keyset pagination sur la table des logs : performances constantes quelle que soit la profondeur
- Index partiels SQLite sur les colonnes de filtrage fréquentes
- Vue live logs : format `log-row` compact restauré sur desktop ; tableau desktop + cards mobile alignés

### Amélioré — Prism

- Taux d'erreurs et IPs bannies affichés par pays (carte GeoIP)

### Amélioré — Admin : port local de secours

- `local_port` configurable sur l'Admin : accès direct à l'Admin sans passer par le Core (utile si le Core est injoignable)

### Refactorisé — Topologie dans le backup global

- Les snapshots de topologie (`topology_snapshots`) sont désormais intégrés au backup global Admin
- Table `topology_snapshots` supprimée — simplification du schéma

### Corrigé

- Core : gestion des IPs/CIDRs de confiance (`trusted_proxies`) corrigée (parsing CIDR + IPv6)
- Admin : `iconConfig` défini dans `infraAgentCard` (corrige une `ReferenceError` JS)

---

## [0.2.3] — 2026-08-30

### Ajouté — Relay Core→Core multi-hôtes (Portainer / délégation)

**Relay Portainer multi-hôtes**
- `endpoint_cores` : routage par endpoint Portainer vers un Core alternatif — chaque endpoint distant peut être servi par le Core le plus proche
- `skip_endpoints` : liste d'endpoints à ignorer lors de la découverte Portainer
- Connexion automatique du Core aux réseaux Docker des endpoints locaux Portainer
- Utilisation du port hôte publié pour les endpoints distants (au lieu du port conteneur)
- Purge automatique des routes Portainer masquées par la délégation après chaque upsert

**Relay Core→Core**
- Les routes Agent sont relayées vers les Cores délégués (Core→Core sans Admin)
- Relay via `DelegateAPIEndpoint` (endpoint interne `:8000`) avec peer tokens
- Vérification des aliases pour la correspondance de délégation
- Logs diagnostics de délégation dans `PushDelegations` (WS)

**Session WS Agent**
- Restauration de la session WS d'un Agent via `auth_token` quand le join token est consommé
- Auto-push de la config déclarée (`declared_config`) vers l'Agent à la première connexion

### Ajouté — UI Endpoint (Admin webapp)

- Sélecteur « Core cible » dans le modal `agentConfigure`
- Pré-remplissage du modal depuis `declared_config` quand l'Agent est hors ligne
- Pré-population du sélecteur `endpoint_cores` avec les Cores connus
- Pré-remplissage du modal de configuration depuis la config live (Agent connecté)
- Fix : échappement des guillemets dans le payload JSON `onclick` d'`agentConfigure`

### Corrigé

- Migration `agent.json` : ajout des sections `docker`/`portainer` si absentes au démarrage (agents antérieurs au write-through)
- 4 erreurs silencieuses corrigées suite à l'audit dead-code
- Fonctions dupliquées et appels `t()` non évalués supprimés

---

## [0.2.2] — 2026-08-09

### Modifié — Proxies YAML uniquement (suppression SQLite comme source de proxies)

- `GPX_PROXY_STORE` supprimé : les proxies sont **toujours** stockés en fichiers YAML sur le Core (`proxies/*.yaml`, `proxies-revisions/*.yaml`)
- `FilesEnabled()` retourne `true` en dur ; `StoreMode`, `ModeSQLite`, `ModeFiles` supprimés
- `loadFromSQLite` retiré de `coreproxy/load.go` ; Admin lit les proxies via l'API Core
- `PushRoutes` ne pousse plus de routes WS (`full_sync` sans clé `routes`) — le Core lit ses propres fichiers YAML
- Tests MCP et vulnscan migrent de lectures SQLite directes vers un faux serveur Core `httptest`
- `WriteProd` supprime automatiquement le `.json` legacy après écriture `.yaml`
- Panneau YAML de l'éditeur proxy repositionné dans la zone de contenu (corrige décalage visuel)

### Corrigé — Labels Docker multi-hôtes / chemins d'URL

- `goproxify.host` CSV : un seul proxy (premier hostname + aliases) au lieu d'une route par entrée — les pages hors `/` fonctionnent sur tous les domaines
- Normalisation `https://`, port, casse ; un chemin (`https://app.example.fr/admin`) devient une location avec strip-prefix
- Repli des anciennes routes `docker-host:` du même conteneur en aliases

### Ajouté — Wizard architecture + tickets bootstrap (Admin `0.2.35`)

- Toile d'architecture (hôtes + palette) : Core, Agent, Admin, Access-sur-Core, Portainer/K8s, multi-Core / groupe HA
- Packs install par hôte + tickets QR / lien `/i/{token}` + one-liner `curl|bash` (`POST /api/v1/bootstrap-tickets`)
- Auto-accept des nœuds déclarés issus du wizard ; reprise des nœuds existants ; région / autoscale / domaines-TLS
- Ancien wizard Infrastructure scénarisé retiré (entrée « + Ajouter » = toile)
- Landing : présentation de l'assistant d'architecture
- Plan : `docs/plans/2026-08-09-001-feat-architecture-wizard-qr-plan.md`

### Ajouté — MCP + CLI Infrastructure / bootstrap

- MCP : `list_declared_nodes`, `create_declared_node`, `delete_declared_node`, `create_bootstrap_ticket`, `accept_node`, `reject_node`
- Ressource MCP : `goproxify://declared-nodes`
- CLI : `goproxify nodes list|accept|reject`, `goproxify declared list|create|delete`, `goproxify bootstrap create`

### Modifié — Navigation Portail Access

- Sous-menu Core : Catalogue Access, Users Access, Templates Access, Audit Access
- Page dédiée Audit Access (contenu extrait de la page config portail)

### Ajouté — Préparation publication publique

- `NOTICE`, `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`, templates `.github/`
- `suivi/roadmap-public.md` ; badges README ; tags quickstart alignés sur `versions.json`
- Pipeline clean : exclude `docs/audits`, `ALLOW_PRIVATE_IPS=false`, includes communauté
- Pipeline Harness `publish-ghcr` : `public/main` → images GHCR (SemVer + `:preview`, pas `:latest`)
- Secret GHCR dédié `github_ghcr_token` (séparé de `github_publish_token` / droits repo)
- Tags quickstart / landing / release-notes réalignés sur `versions.json` (admin 0.2.28 / core 0.3.17 / agent 0.3.13)
- Scrub surface publique : defaults GHCR (Admin UI / Helm), IPs doc RFC5737 dans tests ; materialize+validate OK
- Publication GitHub/GHCR : reste volontairement **privée** pour l'instant (passage Public différé)
- `DISCLAIMER.md` : préversion 0.x, refus de garantie et de responsabilité d'usage
- Site vitrine : **goproxify.dev** sur Cloudflare Pages (plus de `.io`)
- Runbook : `docs/audits/publication/host-runbook.md`, `ci/prepublish-host.sh`

### Modifié — UI 2FA Access en tuiles (Core `0.3.3`)

- Compte Access : une tuile par méthode (TOTP, OTP email) avec badge Actif/Inactif
- Actions en icônes (QR/configurer, activer, désactiver) ; setup TOTP intégré dans la tuile

### Ajouté — QR code TOTP Access (Core `0.3.2`)

- `POST /api/2fa/totp/setup` renvoie `qr_code` (PNG data URL) en plus de `secret` / `otpauth_uri`
- UI Compte Access : affichage du QR + lien otpauth + clé manuelle

### Ajouté — MCP + CLI Access (Admin `0.2.15`)

- Scopes PAT `portal:read` / `portal:write` (API `/api/v1/portal*`, `/api/v1/portal-page-templates*`)
- Outils MCP Access : config, destinations, users/invite, audit, templates, push
- Ressources MCP : `goproxify://portal/{destinations,users,templates,audit}`
- CLI : `goproxify access config|destinations|users|audit|templates …`

### Ajouté — GoProxify Access (portail SSH / shell)

- Portail public Core : UI HTTPS + SSH UUID (dual façade), pont VM/`sshd` ou Docker via Agent
- Admin : catalogue destinations Trafic-like, users invite SMTP, tags, options par Core
- Coffre utilisateur : login SSH + mot de passe ou clé privée (chiffré sur Core ; jamais renvoyé)
- 2FA Access (TOTP / OTP email), sessions TTL/mode/révocation, audit métadonnées
- UX Access : tuiles, recherche, favoris, onglets ; templates HTML Access (fallback SPA)
- Plans : `docs/plans/2026-08-08-001-…`, `docs/plans/2026-08-08-002-…` (U1–U10)

### Modifié — Docs & landing (Access)

- `suivi/roadmap.md` : Jalon 23 ; README / changelog / landing alignés
- Landing : carte fonctionnalité Access + badge ; Users Access Admin : actions en icônes

### Ajouté — MCP enrichi (Admin `0.2.14`)

- Outils proxies : `update_proxy`, `set_proxy_enabled` ; `create_proxy` accepte `type` / `lb`
- Outils Agents : `list_agents`, `approve_agent`, `revoke_agent` (WS)
- Outils sécurité : `get_security_overview`, `list_security_bans`, `create_security_ban`, `delete_security_ban`, `list_security_threats`, `list_security_cves`
- Ressources MCP : `goproxify://agents`, `goproxify://security/{bans,threats,cves}`
- Docs : `docs/mcp.md`, `docs/mcp-implementation.md`, `docs/fonctionnalites.md` (PAT + MCP)

### Ajouté — WS étape 4 sécu + métriques Prometheus

- `gpx_join_*` usage unique (`JoinTokenStore` persisté) ; révocation locale du token après première connexion WS
- Tokens Agent Admin générés en `gpx_join_*` (rôle `agent`)
- Révocation Agent : `revoke_agent` Admin→Cores, `Hub.RevokeAgent` (ferme WS + invalide HMAC) ; `POST/DELETE /api/v1/agents/{id}/revoke` ; révocation token `role=agent` déclenche le même flux
- Métriques Core : `goproxify_ws_connections_active{role}` et `goproxify_ws_messages_sent_total{role,type}`

### Clarifié — Roadmap produit finalisée

- Jalons 0–22 clos ; versions Admin `0.2.13` / Core `0.3.1` / Agent `0.3.0` / Webapp `0.3.0`
- Backlog produit réduit à l'hygiène CI optionnelle ; dette technique WS/P95 isolée en bas de `suivi/roadmap.md`

### Corrigé — Générateur Labels Docker/K8s

- Champ « URL backend » remplacé par « Port » (`goproxify.port`) — l'Agent construit l'URL depuis l'IP du conteneur / ClusterIP
- Snippets : sélection par toggles depuis la bibliothèque Admin (plus de saisie libre d'IDs) ; résolution Core par nom ou ID
- Labels sécurité complets : GeoIP, IP filter, CORS, rate burst, WAF block/detect, HTTPS backend, passthrough, canary/shadow, prune ; auth via liste déroulante
- Préremplissage Trafic : host + aliases → `goproxify.host` CSV
- Snippets : plus de doublon WAF/Bot/GeoIP/… (réservés aux champs Sécurité natifs) ; webapp `0.3.1`
- Générateur Labels : page détachée → modale (Trafic / proxy / assistant infra), onglets parité Sécurité proxy ; webapp `0.3.2`

### Ajouté — CrowdSec bouncer bout-en-bout (Admin `0.2.13`, Core `0.3.1`)

- Stream LAPI `/v1/decisions/stream` (snapshot + deltas), dédup menaces, rebuild `security_bans`
- Push `push_bans` Admin→Core (full_sync + HTTP legacy) ; BanStore Core avec persistance disque
- Rejet 403 des IPs bannies (CrowdSec / Fail2Ban / natif) ; profils IP allow et IPs privées exemptés
- Alertes `crowdsec_critical` / `fail2ban_ban` à la création de bans
- Désactivation CrowdSec : purge menaces/bans + resync Core ; menaces internes agent → bans

### Corrigé — WAF / rate limit / bot (Core + Admin)

- Modale Sécurité : WAF enregistré en mode `block`/`detect` (plus forcé en `detect`)
- Bot : mapping `mode` → `js_challenge` ; modes monitor/log ; challenge cookie HMAC (anti-bypass)
- Challenge JS : URI échappée (anti-XSS) ; secret de signature
- Rate limit / IP filter / GeoIP : IP client via `RealIP` (CF / XFF) ; `Retry-After` ; refresh rps/burst ; éviction buckets inactifs
- WAF : `exclude_ids` par route respectés ; snippet type `waf` résolu au dispatch
- Page Core WAF : persistance mode + catégories via snippet

### Ajouté — Sécurité des proxies conteneur via labels (Core `0.3.0`, Agent `0.3.0`, Webapp `0.3.0`)

- Labels appliqués sur les routes `docker-host:` : `rate_limit`, `ip_filter`, `cors`, `geo_ip`, `snippets`, `auth_provider`, `waf`, `bot`
- Générateur de labels UI : snippets, auth provider, WAF, bot ; `rate_limit` au format `N/s`
- Snippets type `bot` résolus au dispatch ; fallback chemin GeoIP DB Core
- Package `internal/labels` pour le parsing partagé Agent/Core

### Clarifié — Backlog produit allégé

- Retirés (hors scope) : DEB/RPM, cron `docker exec`, terminal distant UI, E2E Playwright
- Conservés : labels Canary/Shadow auto (cohérence discovery) ; scan CI optionnel (hygiène)
- Reste technique documenté sous Jalon 18 (WS sécurité / retrait HTTP) et auto-scale P95

### Modifié — Landing v0.1.1 (présentation produit)

- Version affichée `v0.2.12` / Go 1.25 ; badges WebSocket, Adaptive LB, i18n
- Cartes fonctionnalités : LB adaptatif, gateway inter-Cores, délégation, pages d'erreur, CLI, Prism Admin+Core
- Schéma architecture : hub WS, métriques Agent, gateway
- Stack : ligne WebSocket control plane ; textes EN par défaut
- Docs : carte délégation → `docs/delegation.md`
- i18n EN/FR/ES/DE : sous-titres de sections + cartes docs

### Ajouté — i18n EN / FR / ES / DE (Admin `0.2.12`, Webapp `0.2.5`)

- Socle `internal/i18n` : résolution `Accept-Language`, catalogues EN (source) + FR/ES/DE, fallback EN
- Pages d'erreur Core localisées pour les visiteurs
- Admin UI : `t()` + override `localStorage` + sélecteur de langue
- Couverture : shell, dashboard, settings, Trafic, Users, Logs, account, erreurs API, emails
- Landing : switcher multi-langue + contenus marketing
- Plan : `docs/plans/2026-08-07-003-feat-multilingual-i18n-plan.md`

### Ajouté — LB adaptatif WS + gateway inter-Cores (Core)

- Métriques conteneur Agent→Core via WS ; merge de pools par host ; poids LB dynamiques
- Tunnel gateway `POST /internal/v1/gateway/tunnel` pour joindre un backend distant via le Core propriétaire
- Failover : après échec proxy, essai du reste du pool + quarantaine courte (évite 502 immédiat)
- Doc architecture : `docs/architecture.md`

### Ajouté — Bibliothèque de pages d'erreur

- Templates Admin (placeholders + assets drag-and-drop multi-fichiers)
- Sync WS vers `/etc/goproxify/error-pages` sur le volume Core (dispo si Admin HS)
- Sélecteur de template sur le formulaire proxy ; application avant matching de routes
- Lien ID log → Admin (pas l'hôte proxyfié)

### Amélioré — CLI opérationnel (token, backup, alert, import)

- `goproxify token create/list/revoke` branché sur `/api/v1/tokens` (TTL `24h`/`7d`, `-endpoint`, `-rbac-role`)
- `goproxify backup create/list/restore` via snapshots Admin + export routage + restore fichier `.gpx-admin-backup`
- `goproxify alert test -channel|-all` via `POST /api/v1/alert-channels/{id}/test`
- `goproxify import` : parse local (`importer.ParseConfig`) + apply HTTP ; `-dry-run` offline ; formats alignés (plus de zoraxy/bunkerweb/csv fantômes)
- Auth commune `-admin-url` / `-token` (ou variables `GPX_CONTROLPLANE_*`)

### Amélioré — Sauvegardes multi-planifications

- Jusqu'à 5 planifications indépendantes (fréquence lisible + rétention dédiée)
- Navigation Sauvegardes par cartes : Snapshots / Planification / Routage / Historique

### Amélioré — Menus unifiés Admin ↔ Core

- Menu **Sécurité** (dashboard, vulnérabilités, posture, bans) dupliqué dans la nav contextuelle Core
- Code unifié `mode: admin|core` (même pattern que Trafic / Certs) ; données filtrées via `/proxies?core=`
- Config Fail2Ban / CrowdSec et déclenchement du scanner réservés à la vue admin globale
- Lien « Dashboard sécurité » dans le hub Paramètres Core
- **Prism unifié** : vue globale Admin + filtre Core (`node_name`) ; légende Codes HTTP pleine tuile
- **Logs** d'accès / système unifiés Admin+Core ; live SSE corrigé
- **Certificats** unifiés via `renderCertsPage`
- Cores accessibles listés dans la sidebar

### Amélioré — UI Sécurité / Bans / Labels / Alertes

- Sous-menus Sécurité : Vulnérabilités / Posture / Bans ; Fail2Ban+CrowdSec dans Bans ; Certificats retirés du dashboard
- Page Bans : bandeau config + filtres
- Prism : IPs déjà bannies marquées ; « Bannir » en icône
- Générateur Labels Docker/K8s redesigné et déplacé dans le wizard Infrastructure
- Sélecteur de type des canaux d'alerte redesigné
- Zone de dépôt fichiers pour migration de config proxy
- Menu burger / responsive admin corrigé
- Vulnscan : progression live + résumé détaillé

### Amélioré — Interactions Logs ↔ Prism

- Bouton **Corréler** remplacé par une icône (délégation d'événements) : corrigé le `onclick` cassé par les guillemets JSON
- Corrélation élargie : logs Agent/système (±30 s) via domaine, message, ou nom de conteneur (variantes dots→tirets)
- Logs : cellules cliquables (IP, domaine, code, méthode, chemin) + chips de filtres actifs (Maj+clic pour cumuler)
- Logs → Prism : icône analyse sur chaque ligne ; Prism → Logs : icône / clic depuis Top IPs, chemins, codes HTTP, backends
- Prism : drill-down IP / chemin / proxy, zoom timeline au clic sur un point, filtre API `ip` / `path`
- Filtre status logs : accepte `5xx` / `5` (famille) en plus du code exact
- Ingestion access logs Core → Admin via WS

### Documenté — Délégation Passthrough vs Terminate

- Nouveau guide [docs/delegation.md](../docs/delegation.md) : schémas, IP client, prérequis Terminate
- Liens dans README, architecture, fonctionnalités, FAQ
- Aide UI Domaines enrichie (modes + endpoint)

### Corrigé — Délégation Terminate (SNI vhost)

- Re-TLS Core d'entrée → Core cible : SNI = Host virtuel (domaine), plus l'IP de l'endpoint
- Alignement `PreserveHost` sur le push WS ; `X-Forwarded-For` via `RealIP`

### Amélioré — RBAC grants (scopes + mode lecture/écriture)

- Primitive unifiée : grant `(type, valeur, read|write)` sur **user** et/ou **équipe**
- Rôle plateforme réduit à `admin` / `user` (plus de plafond operator/viewer pour les proxies)
- Membership d'équipe sans rôle : héritage intégral des grants de l'équipe
- Migration B' : équipes mixtes operator/viewer scindées en équipe write + `… (lecture)`
- UI Utilisateurs : éditeur de grants personnels et d'équipe

### Amélioré — Clarification rôle global vs droits d'équipe (UI Utilisateurs)

- Libellés distincts : niveau de compte (plafond) vs droit d'équipe (« Peut modifier » / « Lecture seule »)
- Aide conditionnelle selon admin / operator / viewer ; empty state corrigé (sans équipe → aucun proxy pour operator/viewer)

### Amélioré — Profils IP persistés sur le volume Core

- Snapshot runtime écrit sous `/etc/goproxify/ip-profiles/profiles.json` à chaque push / full_sync
- Chargé au démarrage Core (survit à un redémarrage sans Admin)
- Config + refresh feeds restent dans l'Admin (SQLite) ; surcharge chemin : `GPX_IP_PROFILES_PATH`

### Amélioré — Formats d'import unifiés + onglets Import / Restore

- `CONFIG_FORMATS` / `CONFIG_FORMAT_SVG` centralisés dans `shared/config-formats.js` (Trafic, Import, onboarding, proxy-form)
- Helper `configFormatPickerHtml` / `configFormatMeta` pour un rendu unique des cartes format
- Onglets Import / Restore : navigation en cartes (icône + titre + description) à la place de `tab-btn` sans styles

### Corrigé — Bans actifs vides + icônes Importer (Trafic)

- Cause bans : `security.Ban.ID` était `int64` alors que la table utilise des UUID `TEXT` → Scan échouait en silence
- UI : `deleteBan` quote correctement l'id string
- Importer Trafic : cartes format avec `CONFIG_FORMAT_SVG` (icônes manquantes à l'étape 1)

### Supprimé — Pipeline UI `build.sh` / `dist/`

- L'Admin sert uniquement `src/` via `go:embed` : suppression de `build.sh`, `dist/index.html`, `shell.html`
- Dockerfile admin : plus de copie vers `/etc/goproxify/storage/webapp/`
- Découpage `pages-all.js` en modules dédiés (proxy, infra, onboarding, sécurité, core, logs, prism)

### Corrigé — Horloge admin absente (embed `src/`)

- L'Admin sert l'UI via `go:embed src`, pas `dist/` : l'horloge était dans `shell.html`/`dist` mais manquait dans `src/index.html`

### Corrigé — Fuseau horaire (TZ) effectif sur Core / Admin / Agent

- Cause : `TZ=Europe/Paris` était injecté mais ineffectif (Core `scratch` sans zoneinfo ; Admin/Agent Alpine sans `tzdata`)
- Fix : embed `time/tzdata` dans le binaire ; `apk add tzdata` sur Admin/Agent ; `TZ` ajouté au chart Helm (`global.timezone`)
- Horloge dans la topbar admin (fuseau serveur via `/api/v1/health` → `timezone` / `time`)
- Timeline Prism : buckets SQLite en heure locale (`strftime(..., 'localtime')`)
- `fmtDate` UI aligne l'affichage sur le TZ serveur

### Changé — Chemin GeoIP MaxMind sur le volume Core

- Défaut UI : `/etc/goproxify/geoip/GeoLite2-Country.mmdb` (au lieu de `/usr/share/GeoIP/...`)
- Le Core crée `/etc/goproxify/geoip` au démarrage et **télécharge** `GeoLite2-Country.mmdb` s'il est absent
- Config Core `geoip.db_url` / `geoip.db_path` / `geoip.auto_download` (défaut miroir P3TERX) — surcharge env `GPX_GEOIP_*`
- Les snippets / configs existants avec l'ancien `db_path` restent inchangés : mettre à jour le champ « Base MaxMind » puis ré-enregistrer

### Fait — Phase B : unification headers runtime

- Canal unique `cfg.headers` (+ `headers.custom`) pour natifs et avancés (CSP, Referrer-Policy, …)
- `applySecHeaders` / édition proxy écrivent dans `headers` ; legacy `response_add_header` migré à la lecture/sauvegarde
- Runtime inchangé : `SecurityHeaders` applique déjà `Custom`
- Merge snippets `headers` : custom fusionné (inline prime), typés complétés si vides

### Amélioré — Page Core « IP / GeoIP / Bot » : sélecteur pays unifié

- Section « Pays bloqués (GeoIP) » : même UI que la modale Sécurité (mode, base MaxMind, regroupements, recherche, liste)
- Sélecteur GeoIP factorisé avec racine DOM configurable (`psec-geo-picker` / `core-geo-picker`)
- Bouton **Enregistrer GeoIP** : crée ou met à jour le snippet `geo_ip` correspondant

### Corrigé — Score « Filtrage IP » : GeoIP + snippets

- Récap / `computeProxyHeaderScore` : le contrôle « Filtrage IP » (+5) compte aussi GeoIP (`countries` / `blocked_countries`) et les snippets déjà résolus (`ip_filter` / `geo_ip`)
- Miroir Go `ComputeHeaderScore` + normalisation `blocked_countries` → `countries` à la résolution de snippets

### Corrigé — Catalogue pays GeoIP non chargé dans l'UI Admin

- L'Admin sert `src/` (go:embed), pas `dist/` : `countries-geo.js` n'était pas référencé dans `src/index.html`
- Ajout du `<script src="js/data/countries-geo.js">` avant `pages-all.js` — la liste pays / regroupements s'affiche dans Paramètres → Filtrage IP → GeoIP

### Amélioré — Phase A : Sécurité proxy centralisée dans la modale Trafic

- Modale Sécurité : Récap aligné sur `ComputeHeaderScore` (TLS, HSTS, XFO, Server, rate limit, WAF, bot, IP filter, auth)
- Paramètres enrichis : headers natifs, rate limiting (`rps`/`burst`), filtrage IP (mode + CIDRs)
- Page Sécurité : grille « Posture par proxy » en lecture ; Détails/Corriger ouvrent la modale proxy
- Alertes bouclier Trafic alignées sur le même score

### Clarifié — Domaines : Tokens = droits, Core d'entrée = routage (Admin `0.2.11`)

- « Core responsable » renommé **Core d'entrée** (routage / délégation / ACME) — ne confère pas les droits
- Notices UI Domaines + Tokens : périmètres token = droits de réception routes/certs
- Sélecteur Domaines : uniquement tokens Core actifs (endpoint ou nœud online), sans declared/pending/fantômes
- Alertes douces si scope domaine manquant sur le token du Core d'entrée
- `resolveCoreRef` : plus d'auto-création de token fantôme ; token Core actif requis

### Corrigé — Core auto sans token visible : affectation domaine possible (Admin `0.2.10`)

- Domaines: la sélection des Cores inclut aussi les Cores détectés dans `/nodes` même sans token actif
- API Domaines: un `core_id` fourni en `node_name` est résolu, et un token Core est auto-créé si absent
- Permet de définir un domaine/périmètre pour un Core auto-connecté sans passage manuel préalable par la page Tokens

### Amélioré — Assistant Agent : stack unifié Core+Agent (Admin `0.2.9`)

- Scénario **Agent seul** avec Core existant : docker-compose / Portainer / CLI générés incluent **Core + Agent** (comme le scénario full)
- Réutilise la config déclarée du Core si disponible ; sinon valeurs par défaut du nœud
- Agent branché sur `http://<core>:8000` dans le même réseau Docker

### Corrigé — Assistant Infrastructure Core+Agent (Admin `0.2.8`)

- Scénario **full** : hôte joignable requis + création du **token Core** (`node_endpoint`) + affichage du token à la fin
- Notice corrigée (plus de fausse « acceptation Infrastructure » pour le Core)
- `GPX_PAIRING_SECRET` = secret Admin uniquement (plus de secret aléatoire divergent)
- Page Infrastructure : section **En attente d'acceptation** (Accepter / Rejeter)
- Domaines du wizard → `token_scopes` domaine sur le token créé

### Corrigé — Sans périmètre = tous les domaines (Admin `0.2.7`)

- Ne plus préférer / basculer vers un token jumeau qui a des scopes : admin sans `token_scopes` retrouve l'accès global

### Corrigé — Périmètres Core réellement appliqués (Admin `0.2.6`)

- Résolution token : préfère l'UUID avec endpoint (évite doublons `node_name` / `id=node_name`)
- Push WS / full_sync / certs : scopes lus sur le token de l'entrée WS (`LoadCoreAccess`)
- `Register` : un seul client par `node_name` ; refuse `id=node_name` (fail-open historique `ConnectFromEnv`)
- Wildcards DNS à un seul label (`*.example.com` ≠ `app.dev.example.com`) — aligné `ByHost`
- UI Trafic Core : résout l'UUID token avant `?core=`
- **Sans périmètre domaine** (scopes vides) + admin → **tous les domaines** (pas de bascule vers un jumeau scopé)

### Corrigé — Périmètres Core / proxies (Admin)

- `GET /api/v1/proxies?core=` filtre la liste selon les `token_scopes` du Core (même règle que le push runtime)
- Ajout / retrait d'un périmètre token → re-push immédiat des routes et certificats aux Cores
- Matching domaine RBAC : aliases + `HostCoveredByPattern` (aligné délégation)
- Page Trafic mode Core : n'affiche plus tous les proxies globaux
- `build.sh` réinclut `js/pages/trafic.js` dans `dist/index.html`

### Ajouté — Tokens API utilisateur (PAT)

**Admin**
- Table `user_api_tokens` / `user_api_token_scopes` — PAT `gpx_pat_*` hashés (SHA-256), aperçu UI, expiration optionnelle, révocation immédiate
- API self-service (session JWT) : `GET/POST /api/v1/me/tokens`, `DELETE /api/v1/me/tokens/:id`, `GET /api/v1/me/tokens/scopes`
- Middleware `RequireAuth` (JWT ou PAT) sur l'API REST ; `EnforcePATScope` borne les appels PAT aux scopes ressource
- Middleware `RequirePAT` sur `/mcp` — le JWT de session UI n'est plus accepté pour le MCP
- Scopes catalogue v1 partagés API + MCP (`proxies:read|write|delete`, `nodes:read`, `users:read`, …) ; autorisation = scopes PAT ∩ droits courants du compte (rôle)
- Audit : acteur `userID via pat:<id>`

**Webapp**
- Page **Mes tokens API** (Paramètres + lien depuis Mon profil) — création avec sélection de scopes, affichage unique du secret, liste / révocation

**Documentation**
- `docs/mcp.md`, `docs/api_specs.md`, `docs/mcp-implementation.md` — auth PAT
- Plan produit : `docs/plans/2026-08-05-001-feat-user-api-tokens-plan.md`
- Landing : cartes Admin/Sécurité/Agent, stack MCP+PAT, liens docs, version `0.2.4` / Go `1.25`

*Versions actuelles (`versions.json`) : admin `0.2.12`, core `0.2.4`, agent `0.2.0`, webapp `0.2.5`, landing `0.1.0`.*

## [0.2.3-core] — 2026-08-05

### Corrigé — Délégation passthrough plus robuste (Core `0.2.3`)
- Force `tls_passthrough=true` sur les routes `deleg-*` wildcard (sauf backend http/https = terminate)
- La purge des conflits se base sur l'ID `deleg-*`, pas seulement sur le booléen
- Log `délégation appliquée` avec host / backend / tls_passthrough

## [0.2.2-core] — 2026-08-05

### Corrigé — Purge des proxies masqués par délégation (Core `0.2.2`)
- À l'application des `deleg-*` / full_sync / push routes, les proxies exacts locaux couverts par un wildcard `tls_passthrough` sont retirés
- Évite le 502 quand le Core responsable conserve encore `api.example.fr` alors qu'une délégation `*.example.fr` est active

## [0.2.4] — 2026-08-05

### Corrigé — Push certificats selon périmètres token (Admin `0.2.4`)
- Les certificats ne sont plus diffusés à tous les Cores
- Admin **sans** périmètre → reçoit tout (défaut)
- Admin **avec** périmètre `domain` → uniquement les certs couverts ; scope `core` → tout
- Aligné sur la sémantique RBAC des routes

## [0.2.3] — 2026-08-05

### Corrigé — Passthrough délégation vs proxy exact (Core `0.2.1`)
- Au SNI, une route wildcard `tls_passthrough` (délégation) est préférée même si un proxy exact local existe pour le même host
- Corrige le 502 quand le Core responsable terminait encore le TLS à cause d'un match exact

### Modifié — Admin `0.2.3`
- Log `routes poussées` avec `filtered_out` pour tracer l'exclusion des hosts délégués

## [0.2.2] — 2026-08-05

### Corrigé — Délégation de domaines (Admin `0.2.2`)
- Les proxies dont le host est couvert par un domaine délégué ne sont plus poussés au Core responsable
- Ils restent uniquement sur le Core cible (`delegated_to_core_id`), pour que le passthrough TLS ne soit plus court-circuité
- Appliqué sur `PushRoutes`, `full_sync`, `GET /internal/v1/routes`, et à la sauvegarde/suppression d'un domaine

### Corrigé — Pages d'erreur par défaut (Core)
- Remplacement de l'affichage du nom/version du Core par un ID de log cliquable (`X-Request-ID`) vers `/api/v1/logs`

### Modifié — Documentation de suivi
- `README.md` : ajout des liens vers `suivi/changelog.md` et `suivi/versioning.md` dans la section Documentation
- `suivi/roadmap.md` : ajout d'une section "Suivi documentaire" pour tracer les mises à jour des documents de référence
- `suivi/versioning.md` : clarification de la règle pour les changements "documentation only"

### Ajouté — Autonomie complète du Core

**Architecture Core-first**
- Démarrage cache-first : le Core charge son cache local en priorité, puis synchronise avec l'Admin en arrière-plan (plus aucun blocage au démarrage si l'Admin est injoignable)
- Auto-enregistrement du Core auprès de l'Admin au démarrage via `POST /internal/v1/cores/register` — remplit automatiquement `node_endpoint` dans la table tokens
- Le cache chiffré AES-256-GCM (`/etc/goproxify/core-cache.gpx`) contient désormais : routes, certificats TLS (cert + clé privée), snippets et fournisseurs d'authentification

**Snippets dans le Core**
- `SnippetStore` thread-safe avec remplacement atomique (`Replace`)
- Endpoint interne `POST /internal/v1/snippets` sur le Core
- Snippets persistés dans le cache chiffré
- Champ `SnippetIDs []string` dans `Route` pour référencer les snippets par ID

**Fournisseurs d'authentification dans le Core**
- `AuthProviderStore` thread-safe avec remplacement atomique (`Replace`)
- Endpoint interne `POST /internal/v1/auth-providers` sur le Core
- Fournisseurs persistés dans le cache chiffré
- Champ `AuthProviderID string` dans `Route` pour référencer le fournisseur par ID

**Push Admin → Core amélioré**
- `DeleteRoute(ctx, id)` dans le pusher : suppression immédiate d'une route sur tous les Cores lors d'un DELETE proxy côté Admin
- `PushSnippets(ctx)` et `PushAuthProviders(ctx)` dans le pusher
- `PushAll(ctx)` : déclenche routes + snippets + fournisseurs en parallèle après enregistrement d'un Core
- Interface `RoutePusher` étendue avec `DeleteRoute`
- Sémantique Replace dans `handlePushRoutes` du Core (remplacement atomique total au lieu d'Upsert individuel)

**TLS cache**
- `CachedCert` (cert PEM + clé PEM) dans le `CertStore` du Core
- `AllPEMs()` pour export vers le cache chiffré — clés privées jamais en DB Admin

### Corrigé
- `navigator.clipboard.writeText` indisponible en contexte HTTP (non-HTTPS) : fallback `execCommand('copy')` dans `copyText()` (ERR-006)
- `DELETE /api/v1/proxies/ 405` causé par un ID proxy vide dans `deleteProxy()` : garde ajoutée
- DNS `network is unreachable` dans les conteneurs Core/Agent sous Portainer : `dns: 127.0.0.11` ajouté dans docker-compose.yml

### Ajouté — SSO & Authentification Étendue (Jalon 15)

**Nouveaux providers Core (middleware par route)**
- **GitHub OAuth2** (`provider: github`) — flow complet OAuth2, vérification org/team, cookie HMAC-SHA256
- **LDAP / Active Directory** (`provider: ldap`, `ldap_ad`) — Basic Auth → bind LDAP, LDAPS + STARTTLS, filtrage groupe DN/CN
- **SAML 2.0** (`provider: saml`) — SP mode via `crewjam/saml`, ACS handler, métadonnées IdP URL ou XML
- **Presets OIDC** : `google`, `microsoft`, `entra`, `auth0`, `okta`, `keycloak`, `zitadel`, `casdoor`, `dex` — IssuerURL pré-remplie, configurable
- Dispatch SSO unifié dans `sso.go` : tous les providers routés vers leur middleware

**Admin**
- Table `auth_providers` — CRUD fournisseurs SSO réutilisables entre proxies
- API `GET/POST /api/v1/auth-providers`, `GET/PUT/DELETE /api/v1/auth-providers/{id}`

**Dépendances**
- `github.com/crewjam/saml v0.5.1`

### Ajouté — Double Authentification (2FA/MFA — Jalon 14)

**Méthodes MFA**
- TOTP (RFC 6238, pur Go), Email OTP, SMS OTP (Twilio/OVH/Vonage), Push ntfy/Gotify, WebAuthn/Passkey, Codes de secours, Appareils de confiance
- Flow JWT intermédiaire `mfa_pending` (5 min) → challenge → JWT complet

### Ajouté — Initialisation
- Structure initiale du projet (arborescence, Docker Compose, documentation)
- Schéma canonique de configuration JSON v4.3
- Roadmap, changelog, dictionnaire d'erreurs

---

## [0.2.1] — 2026-07-31

### Modifié — Refonte RBAC & Page Trafic unifiée

**RBAC (Admin `0.2.1`)**
- Refonte complète de `internal/admin/rbac/rbac.go` : méthodes `canReadProxy`, `canWriteProxy`, `canDeleteProxy` centralisées, vérification par périmètre d'équipe (domain glob / server glob / proxy ID)
- `GET /api/v1/me` retourne le rôle RBAC et les scopes d'équipe — utilisé par l'UI pour initialiser `state.role`
- Middleware proxy : filtre RBAC appliqué sur `list`, `get`, `create`, `update`, `delete`

**Page Trafic (Webapp `0.2.1`)**
- `renderTraficPage({mode})` unique pour Admin et Core — le design Admin fait référence, Core hérite sans duplication
- Toolbar : recherche, compteur, Grouper (aucun/statut/type/source/domaine), Trier (nom A→Z/Z→A/récent/ancien/actif), Import, CSV, vue tuiles + sélecteur colonnes (2-5), vue table
- Filtres Statut (Tous/Actif/Inactif), Type (Tous/HTTP/HTTPS/TCP/UDP/TCP+UDP), Source (Tous/Docker/K8s/Managed)
- Vue tuiles par défaut avec groupBy et sortBy
- Adaptations mode Core : bandeau statut (nom/CPU/mém/raccourcis), pas de chips Core sur les cartes, pas de bouton "Nouveau flux"
- Extraction dans `js/pages/trafic.js` (module dédié, chargé après `pages-all.js`)
- État persistant survit à la navigation (`window._tv/_tc/_tg/_ts/_tf`)

---

<!-- Template pour les prochaines entrées :

## [X.Y.Z] — YYYY-MM-DD

### Ajouté
- ...

### Modifié
- ...

### Corrigé
- ...

### Supprimé
- ...

-->

### Corrigé (suite)

- **Diff config proxy** : double préfixe `/api/v1` dans l'appel JS → 404 systématique (corrigé)
- **Diff config proxy** : `revisionsDiff` n'essayait que `targets[0]` — proxy non trouvé si sur un autre Core ; utilise désormais `fetchProd()` qui parcourt tous les Cores
