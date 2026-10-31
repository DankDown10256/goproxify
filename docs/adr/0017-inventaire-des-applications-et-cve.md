# ADR 0017 — Inventaire des applications exposées et recherche de CVE sur ce qui tourne réellement

**Statut :** accepté, livré (Admin 0.210.0 / Edge 0.124.0 / Agent 0.19.0) · **Date :** 2026-10-25
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0014 (groupe HA, unité de service), ADR-0016 (apprentissage de la surface : la passerelle observe déjà le trafic de chaque proxy) · **Indépendant du WAF :** l'inventaire n'alimente que le menu Vulnérabilités. La reconnaissance de plateforme par nom d'hôte du WAF (`exclude_platforms: ["auto"]`) n'avait pas d'utilité propre et a été retirée (Admin 0.206.0 / Edge 0.120.0)

---

## Contexte

Le scanner CVE de l'Admin (`internal/admin/vulnscan`) ne connaissait des applications exposées que ce que disait leur serveur web : il envoyait une requête `HEAD` à chaque backend et lisait `Server`, `X-Powered-By` et `X-AspNet-Version`. Seuls `nginx` et `apache` étaient reliés à un identifiant CPE ; tout le reste passait par une recherche texte dans NVD, qui retrouve rarement quelque chose. Il ne savait rien de WordPress, de Grafana, de Gitea ni de leurs versions, qui sont pourtant l'endroit où se trouvent la plupart des CVE exploitées (le scanner sait déjà les enrichir avec KEV et EPSS). Il n'atteignait pas non plus les conteneurs d'un réseau Docker privé, et ne voyait pas les proxys créés par labels.

Deux faits rendent mieux possible :

- **Le reverse proxy est le propriétaire des serveurs qu'il expose.** Ce qu'il masque (`hide_server`, retrait d'en-têtes) l'est à la **sortie** : à l'entrée, la réponse du backend porte encore ses versions. La passerelle voit donc ce que l'application dit d'elle-même, que le client y ait accès ou non.
- **Pour un proxy labellisé, l'Agent connaît l'image** du conteneur (`wordpress:6.4.2-apache`, `grafana/grafana:10.2.0`) : un produit et une version exacts, sans rien deviner. Pour un proxy non labellisé (serveur hors Docker, Proxmox, machine du réseau), il n'y a pas d'Agent : seule la réponse du backend renseigne.

Une reconnaissance par nom d'hôte ou d'URL de backend (celle du WAF à l'époque) ne donne aucune version : elle ne peut pas servir à chercher des CVE.

## Décision

Un **inventaire des applications par proxy** (produit, version, source de l'information), alimenté par deux sources passives, et une **recherche de CVE** faite sur cet inventaire.

**Le seul consommateur est le menu Vulnérabilités.** Le WAF n'en reçoit rien : savoir quelle application tourne n'empêche pas une injection et ne change aucune décision de blocage. Pas d'exclusion, de règle ni de seuil déduits de l'inventaire.

### Sources

1. **Image du conteneur (Agent), pour les proxys labellisés.** L'Agent annonce l'image avec chaque conteneur découvert ; la passerelle la garde sur le backend correspondant (`router.Backend.Image`). On en tire le produit (table des images connues) et la version (étiquette). `latest`, un condensat ou une étiquette qui n'est pas une version ne donnent **pas** de version.
2. **Empreinte des réponses du backend (passerelle), pour tous les proxys.** Lecture **passive** des réponses que la passerelle reçoit déjà, au point où le reverse proxy les reçoit (donc avant `hide_server`) : `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, et le `<meta name="generator">` du début des pages HTML (échantillonné, la page n'est pas modifiée). Aucune requête supplémentaire.

Un proxy peut cumuler les sources. Pour un même produit sur un même backend, l'entrée qui porte une version l'emporte (une image `latest` n'en a pas, les réponses l'annoncent) ; à égalité, l'image, qui décrit ce qui est déployé ; si les deux donnent une version et qu'elles diffèrent, l'image reste et une note le dit.

### Inventaire

- **Où** : sur la passerelle. L'image est dans la copie locale chiffrée des routes ; l'empreinte a la sienne (`apps-state.gpx`, `GPX_APPS_STATE_PATH`), relue au démarrage, bornée (64 observations par proxy), expirée après 30 jours sans nouvelle observation. Les membres d'un groupe HA se tirent leurs observations (`GET /internal/v1/inventory/export`) : la plus récente de chaque (backend, produit, source) l'emporte, ce qui rend la fusion idempotente et indépendante de l'ordre (ADR 0014). L'Agent ne dépend que de sa passerelle.
- **Contenu** : par proxy, une liste de `{backend, produit, CPE, version, source, preuve}`. Pas de contenu de requête ni de réponse, pas d'adresse de client.
- **Lecture** : `GET /api/v1/security/inventory`, `goproxify security cve inventory`, outil MCP `get_app_inventory`, et la page Vulnérabilités.

### Recherche de CVE

- **Où** : l'Admin, seul à avoir accès au réseau externe (NVD, KEV, EPSS). Le scanner lit l'inventaire des passerelles (`GET /internal/v1/inventory`) : un backend dont le produit a un CPE et une version est analysé **sans être sondé**, même sur un réseau privé que l'Admin n'atteint pas. NVD est interrogé par CPE et version ; plusieurs backends de la même image donnent une seule question. Les backends que seule la découverte par labels connaît sont désormais scannés.
- **Repli** : un backend qui n'a pas de version dans l'inventaire (étiquette `latest`, produit inconnu, passerelle injoignable ou ancienne, aucun trafic observé) est sondé comme avant par l'Admin (une requête `HEAD` puis `GET` à la racine, en-têtes seulement ; le certificat TLS n'est pas vérifié). C'est pour lui que le réglage « autoriser les IP privées » subsiste.
- **Correspondance** : une table **produit → CPE** (`vendor:product`) embarquée, dont chaque identifiant est sûr (un CPE faux donnerait de fausses CVE) et dont la cohérence est testée. Sans entrée dans la table, le produit est listé sans CVE, jamais interrogé en texte libre.
- **Rapport « non couvert »** : chaque entrée a une couverture (`covered`, `no_version`, `no_cpe`, `unknown`). `GET /security/inventory` porte `coverage` (totaux et lacunes regroupées par raison et par nom, avec la preuve et les proxys) ; `security cve inventory -gaps`, `get_app_inventory` et la page Vulnérabilités le montrent. La passerelle consigne aussi un logiciel **versionné** que la table ne connaît pas, sinon le rapport ne le verrait jamais.
- **Surcharges de CPE** : `GET/PUT /security/cpe-overrides`, `security cve cpe get|set`. L'administrateur donne un identifiant à un produit sans CPE, à un dépôt d'image ou à un logiciel d'en-tête ; la version est lue dans l'étiquette ou le jeton. Elles vivent sur l'Admin, qui seul interroge NVD, complètent la table et **ne la corrigent jamais**.
- **Résultat** : mêmes CVE, mêmes enrichissements (KEV, EPSS), même SLA et même alerte `cve_critical` qu'avant, mais rattachés à un proxy, un produit, une version et une source (`image`, `headers`, `html`). Quand un backend est mis à jour, les CVE ouvertes de l'ancienne version qui ne concernent pas la nouvelle passent à `fixed`.
- **Un résultat à vérifier, pas une preuve** : une distribution qui rétroporte les correctifs affiche une version vulnérable alors qu'elle est corrigée. L'interface le dit.

## Autonomie (ADR 0006)

Reconnaître et garder l'inventaire tournent sur la passerelle seule, y compris après un redémarrage pendant une coupure de l'Admin ou de l'Agent. Seule la **recherche de CVE** dépend de l'Admin (réseau externe) : une coupure n'enlève que cela, l'inventaire continue de se constituer et se lit à la reconnexion. Les surcharges de CPE sont sur l'Admin ; la passerelle n'en dépend pas.

## Écarté : la sonde active

Une sonde par proxy, qui aurait demandé à l'application sa version sur des chemins connus (`/readme.html`, `/api/health`), n'est **pas retenue**. Elle n'aurait servi qu'aux backends qui ne révèlent leur version ni dans leur image, ni dans leurs en-têtes, ni dans leurs pages, ce qui est rare une fois les deux sources passives lues. Elle aurait envoyé du trafic vers les serveurs de l'administrateur (journaux, alertes du WAF ou d'Ephor, adresse de confiance à prévoir) et demandé de maintenir une liste de chemins par application. Le rapport de couverture dit déjà quelles applications restent sans version : si le problème se pose, on y répond par une étiquette de version fixe, une entrée de plus dans la table ou une surcharge de CPE. À rouvrir seulement si le rapport montre des trous que rien de cela ne comble.

## Limites connues

- **Versions rétroportées** : voir plus haut, le résultat est à vérifier.
- **Backend sans trafic ni version** : sondé par l'Admin comme avant ; s'il ne répond pas ou ne dit rien, il reste sans analyse (`no_headers` ou `unreachable` dans le détail du scan).
- **Extensions** (plugins WordPress, modules) : lisibles dans le HTML (`/wp-content/plugins/<nom>/…?ver=`), mais le CPE d'une extension est rarement dans NVD sous un nom prévisible. Ni les extensions ni les paramètres `?ver=` des ressources ne sont lus.
- **Étiquettes mouvantes** (`latest`, `stable`) : l'image seule ne donne pas de version ; les réponses du backend la donnent quand elles la révèlent. Les labels OCI de l'image (`org.opencontainers.image.version`) ne sont pas lus.
- **Kubernetes et catalogue** : seules les images annoncées par les sources Docker et Portainer sont inventoriées.
- **Débit de NVD** : l'API sans clé (≈ 5 requêtes par 30 s) borne le nombre de produits interrogeables par scan. Les requêtes identiques d'un scan ne sont faites qu'une fois ; rien n'est gardé d'un scan à l'autre.
- **Une table n'est pas exhaustive** : un produit absent est listé « non couvert » et se complète par une surcharge ou par une entrée de table.

## Étapes (toutes livrées)

1. **Inventaire par image** (Admin 0.208.0 / Edge 0.122.0 / Agent 0.19.0) : annonce de l'image par l'Agent, `internal/appinv`, `GET /internal/v1/inventory`, scan sans sonde, CVE rattachées à un proxy, un produit, une version.
2. **Empreinte des réponses** (Admin 0.209.0 / Edge 0.123.0) : `internal/edge/fingerprint`, observateur dans `ModifyResponse` du reverse proxy, copie locale chiffrée, partage entre pairs HA, fusion avec l'image.
3. **Table étendue, rapport « non couvert » et surcharges de CPE** (Admin 0.210.0 / Edge 0.124.0).
4. **Retrait de la reconnaissance de plateforme `auto` du WAF** (Admin 0.206.0 / Edge 0.120.0) : `auto`, son état (`waf-platforms`, CLI, MCP, indicateur de l'interface) et ses chemins suggérés sont supprimés. Les plateformes nommées (`exclude_platforms`) et les exclusions par chemin (`waf.exclusions`) restent. La reconnaissance d'application ne vit plus que dans les scans de vulnérabilités, où elle est implicite : pas de réglage « automatique ou non ».

## Questions tranchées

1. **Extensions** : hors périmètre, voir les limites.
2. **Étiquettes mouvantes** : les réponses du backend complètent l'image ; pas de lecture des labels OCI.
3. **Débit de NVD** : cache des requêtes identiques au sein d'un scan.
4. **Lien avec le WAF** : aucun. Ni l'image vue par l'Agent ni l'empreinte des réponses ne servent au WAF. Un correctif virtuel pour une CVE connue serait une autre décision, hors de cet ADR.
5. **Sonde active** : non retenue, voir plus haut.
