# Plugins WebAssembly

Un plugin est un module WebAssembly que les passerelles exécutent dans une sandbox pour décider du sort d'une requête ou d'une réponse : règle d'authentification maison, règle métier, en-tête calculé. Le choix d'architecture est dans [l'ADR 0008](adr/0008-moteur-de-plugins-wasm.md). Les fonctions standard d'un reverse proxy restent natives ; un plugin sert à ce qu'on ne veut pas compiler dans GoProxify.

## Installer et attacher un plugin

**Exemples intégrés** : un Admin neuf propose déjà cinq plugins, sans dépôt à configurer : `path-guard`, `rate-guard`, `body-redact`, `tcp-allow` et `coraza`. La page Plugins les liste dans son catalogue (dépôt « Exemples intégrés », `repo_id` `builtin`) et les installe d'un clic ; `goproxify plugin catalog -repo builtin` et `goproxify plugin fetch <nom> -repo builtin` font de même. Ils viennent des exemples compilés de `examples/plugins` (mêmes octets, vérifiés par un test) et font confiance au binaire de l'Admin : ils s'installent sans signature même quand des clés de confiance sont enregistrées, et apparaissent « intégré » (`signed_by` `builtin`) dans la liste. Ce sont des **exemples** : à lire, à adapter, pas des fonctions du produit — les fonctions standard (compression, anti-bot, cache, WAF…) restent natives. `token-check` n'est pas intégré : son manifeste doit nommer l'hôte de *votre* service d'authentification.

Trois façons de l'attacher à une route : le formulaire (route → Sécurité → onglet **Plugins**, avec l'ordre d'exécution et les champs du manifeste), le JSON de la route, ou des labels Docker (`goproxify.plugins=a,b` et `goproxify.plugin.<nom>.<clé>=<valeur>`, voir [labels.md](labels.md)). Les routes TCP/UDP s'éditent dans le JSON de la route ou par labels.

```bash
goproxify plugin install -manifest plugin.json -wasm plugin.wasm        # admin uniquement
goproxify plugin list
goproxify plugin update  -manifest plugin.json -wasm plugin.wasm
goproxify plugin delete  geo-headers
```

Un plugin s'attache à une route dans sa configuration, avec sa propre configuration :

```json
{ "plugins": [ { "name": "geo-headers", "config": { "header": "X-Geo" } } ] }
```

Les plugins d'une route s'exécutent dans l'ordre de la liste. Ils s'exécutent **après** le WAF, le filtre anti-bot, la limitation de débit et les filtres IP/GeoIP, et **avant** l'authentification (SSO, JWT, mTLS) : un plugin peut donc compléter ou remplacer une authentification, sans voir les requêtes déjà refusées par la sécurité réseau.

L'Admin pousse la liste complète aux passerelles. Une passerelle installe les plugins nouveaux ou modifiés (empreinte SHA-256 vérifiée), retire les absents, les stocke **chiffrés** et les recharge à son démarrage : les plugins fonctionnent Admin coupé, y compris après un redémarrage.

## Signature

**Où elle est vérifiée** : par l'Admin, à l'installation (manuelle ou depuis un dépôt), et — **si la passerelle épingle des clés** (voir « Clés épinglées sur la passerelle » plus bas) — par chaque passerelle. Par défaut les passerelles reçoivent le paquet par le WebSocket Admin → passerelle (authentifié par le secret d'appairage) et ne contrôlent que l'empreinte SHA-256 : elles font confiance à l'Admin, comme pour le reste de ce qu'il leur pousse. Retirer une clé de confiance empêche donc d'installer de nouvelles versions signées par elle, mais **ne retire pas** un plugin déjà installé : supprimez-le ou remplacez-le. `TestPluginChain_SignedRepoToTwoGatewaysWithKeyRotation` rejoue la chaîne complète (dépôt HTTP, installation, deux passerelles, mise à jour avec rotation de clé, clé retirée, module altéré, version non signée, redémarrage d'une passerelle sans l'Admin).

L'empreinte SHA-256 vérifie l'intégrité d'un module, pas son origine. La signature **Ed25519** prouve qui a publié le paquet. Elle couvre le **manifeste normalisé en entier** (politique d'erreur et limites comprises) et l'empreinte du module : un manifeste plus permissif ne peut pas être accolé à un module signé.

```bash
goproxify plugin keygen -out editeur                      # editeur.key (privée, à garder), editeur.pub
goproxify plugin sign -key editeur.key -manifest plugin.json -wasm plugin.wasm   # affiche la signature
goproxify plugin keys add -name "Éditeur" -public-key <base64 de editeur.pub>     # côté Admin
goproxify plugin install -manifest plugin.json -wasm plugin.wasm -signature <signature>
```

- **Aucune clé de confiance enregistrée** : la signature est facultative. Une signature fournie est refusée (elle ne se vérifie pas) : enregistrez d'abord la clé.
- **Au moins une clé enregistrée** : tout plugin installé ou **remplacé** doit être signé par l'une d'elles ; sinon `400`.
- Retirer une clé ne retire pas les plugins qu'elle a signés ; l'identifiant de la clé signataire (`signed_by`) est conservé et affiché.
- L'Admin vérifie la signature à l'installation et conserve celle qui a été vérifiée (colonne `signature`) pour la pousser avec le paquet. Une passerelle qui n'épingle aucune clé fait confiance à l'Admin qui lui pousse la liste (comme pour le reste de la configuration).

### Clés épinglées sur la passerelle

Un Admin compromis pourrait signer lui-même un plugin avec une clé qu'il vient d'enregistrer et le pousser partout. Pour que la passerelle n'ait pas à lui faire confiance sur ce point, épinglez les clés **sur la passerelle**, hors de portée de l'Admin :

```bash
GPX_PLUGIN_TRUSTED_KEYS=<clé publique base64>,<autre clé>      # ou
GPX_PLUGIN_TRUSTED_KEYS_FILE=/etc/goproxify/plugin-keys        # une clé par ligne, # pour commenter
```

Avec le chart Helm : `global.pluginTrustedKeys`. Tant qu'aucune des deux variables n'est définie, rien ne change. Dès que l'une l'est :

- tout paquet doit porter une signature valide, sur le manifeste normalisé et l'empreinte, d'**une** de ces clés — qu'il vienne de l'Admin, d'un pair ou du disque. Sinon il est refusé et **la version qui tourne reste en place** ;
- les copies chiffrées déjà stockées sont **revérifiées au redémarrage** : un plugin installé avant l'épinglage, ou signé par une clé retirée depuis, n'est plus chargé (une route qui y fait référence répond alors `503`, jamais publique) ;
- une configuration inutilisable (aucune clé lisible) **refuse tout** au lieu de désactiver la vérification, et le journal le dit ;
- les **plugins intégrés** de l'Admin ne sont pas signés (ils font confiance à son binaire) : une passerelle qui épingle les refuse. Installez à leur place des plugins signés par votre dépôt ;
- la liste des plugins d'une passerelle indique `verified` pour ceux dont la signature a été contrôlée ;
- c'est le seul cas où retirer une clé retire des plugins : retirez-la de la variable, redémarrez, et ce qu'elle avait signé n'est plus chargé.

Limite : l'épinglage protège contre un Admin ou un transit compromis, pas contre une clé privée qui fuit. `TestPluginChain_PinnedGatewayDoesNotTrustTheAdmin` et `plugins/trust_test.go` couvrent le comportement.

## Dépôts de plugins

Un dépôt est une URL HTTPS qui sert un index JSON :

```json
{ "version": 1, "name": "Mon dépôt",
  "plugins": [ { "name": "geo-headers", "version": "1.2.0", "description": "…", "homepage": "…",
                 "manifest": { … }, "wasm_url": "geo-headers-1.2.0.wasm", "sha256": "…", "signature": "…" } ] }
```

`wasm_url` peut être relative à l'index. `goproxify plugin repo add -name … -url https://…/index.json`, `plugin catalog` liste les plugins proposés (avec l'état installé et les mises à jour), `plugin fetch <nom> -repo <id> [-version v]` installe ou met à jour ; la page *Plugins* fait la même chose. Sans `-version`, la version la plus récente est choisie (comparaison numérique : 1.10.0 > 1.9.0).

**Un dépôt ne confère aucune confiance.** L'installation depuis un dépôt applique les mêmes contrôles qu'une installation manuelle : empreinte SHA-256 de l'index vérifiée sur le module téléchargé, module compilé et contrat contrôlé, et — dès qu'une clé de confiance est enregistrée — signature obligatoire, d'une de ces clés. Sans clé de confiance, l'empreinte ne protège que du transport : son origine n'est garantie par rien. Le serveur Admin relit l'index lui-même (le client ne fournit jamais l'URL du module), n'accepte que HTTPS, refuse les adresses internes (boucle locale, réseaux privés, link-local, métadonnées cloud) sauf dépôt déclaré `allow_private` (qui n'ouvre jamais le link-local ni les métadonnées cloud), suit au plus 3 redirections et borne l'index (1 Mio) et le module (2 Mio).

## Manifeste

```json
{
  "name": "geo-headers", "version": "1.0.0", "api_version": 1,
  "hooks": ["request", "response"],
  "on_error": "deny",
  "limits": { "memory_pages": 16, "timeout_ms": 50 },
  "fields": [ { "key": "header", "label": "En-tête", "kind": "text", "required": true } ]
}
```

| Champ | Rôle |
|---|---|
| `name` | minuscules, chiffres, `-` et `_` (63 caractères au plus) |
| `api_version` | `1` |
| `hooks` | `request`, `response` (au moins un) ; chacun exige l'export `on_<hook>` |
| `on_error` | `deny` (défaut : `503`) ou `allow` (laisse passer en journalisant) quand le plugin échoue |
| `limits.memory_pages` | pages de 64 Kio, 16 par défaut, 256 au plus |
| `limits.timeout_ms` | 50 par défaut, 1 000 au plus ; une boucle infinie est interrompue |
| `fields` | champs de configuration, au format des manifestes de modules (clés, genres, secrets, requis). La configuration d'une route est validée par ce manifeste |
| `hooks` (suite) | `request_body`, `response_body` (corps tamponné), `connect` (routes TCP/UDP), `log` (requête terminée, hors du chemin de la réponse — voir « Hook log ») ; un plugin sans hook applicable au type de la route est refusé à la validation |
| `limits.max_body_bytes` | taille maximale du corps présenté aux hooks de corps : 32 Kio par défaut, 1 Mio au plus |
| `on_oversize` | `deny` (défaut : `413` sur une requête, `502` sur une réponse) ou `skip` (le corps passe sans que le plugin le voie), pour un corps plus gros que `max_body_bytes` |
| `detector` | `true` : les refus du plugin (hooks `request`, `request_body`) sont des détections de sécurité — voir « Plugins de détection ». Faux par défaut ; exige l'un de ces deux hooks |
| `capabilities` | fonctions de l'hôte que le plugin peut importer en plus de `gpx.log` : `kv` (état), `http` (liste d'hôtes joignables), `http_allow_private` — voir ci-dessous |

## ABI v1

Le module exporte `memory`, `alloc(size i32) i32`, et `on_request(ptr i32, len i32) i64` et/ou `on_response(ptr i32, len i32) i64`. L'hôte réserve la place de l'entrée avec `alloc`, y écrit un JSON, appelle le hook, puis lit le JSON de sortie à l'adresse et de la longueur contenues dans la valeur retournée (`ptr << 32 | len`) ; une longueur nulle équivaut à `allow`.

**Entrée de `on_request`** : `{"method","host","path","query","headers":{"Nom":["valeur"]},"client_ip","config":{…}}` — `on_response` y ajoute `"status"` et `"response_headers"`. Les en-têtes transmis comprennent `Authorization` et `Cookie` : un plugin est du code de politique, à relire comme tel.

**Sortie** : `{"action":"allow"|"deny"|"modify","status":403,"body":"…","set_headers":{},"remove_headers":[],"log":"…"}`

- `allow` (ou sortie vide) : laisse passer.
- `deny` : répond avec `status` (4xx/5xx, 403 par défaut) et `body`. Sur `on_response`, le corps du backend est écarté.
- `modify` : pose et retire des en-têtes (de la requête pour `on_request`, de la réponse pour `on_response`), puis laisse passer.
- `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Trailer` ne peuvent être ni posés ni retirés ; une valeur contenant CR, LF ou NUL est refusée.

Si le module exporte `_initialize` (TinyGo, Rust en « reactor »), l'hôte l'appelle sur chaque instance neuve avant `alloc` : sans lui, le tas et les variables globales du module ne sont pas prêts. Il doit être sans argument ni résultat.

L'hôte n'importe qu'une fonction : `gpx.log(ptr i32, len i32)` (journal, 1 Kio par appel). Tout autre import (WASI, système de fichiers, réseau, horloge, aléa) est refusé au chargement. Une instance neuve est créée à chaque appel : un plugin n'a pas d'état.

## Hooks de corps

`request_body` et `response_body` reçoivent le corps en entier, tamponné en mémoire et encodé en base64 dans le JSON (`"body"`). La sortie `modify` peut porter `"replace_body": "<base64>"` pour remplacer le corps ; `Content-Length` est recalculé. Un corps plus gros que `limits.max_body_bytes` suit `on_oversize`.

- La **requête** est lue jusqu'à la limite ; si tous les plugins sont en dépassement (`skip`), le flux d'origine est restitué en entier au backend.
- La **réponse** est retenue jusqu'à son terme : elle n'est plus transmise au fil de l'eau tant qu'un plugin de réponse est attaché. Un flux (`text/event-stream`) ne peut pas être retenu : il est traité comme un dépassement. HEAD, 1xx, 204 et 304 n'ont pas de corps : rien n'est examiné. Le corps est vu tel que le backend l'envoie (`Content-Encoding` compris : un backend qui compresse livre des octets compressés).
- Un refus tardif (`deny` sur la réponse) retire les en-têtes propres à la réponse du backend (`Set-Cookie`, `Content-Encoding`, `ETag`…).

## Hook log

`log` est appelé **après** l'envoi de la réponse, de façon asynchrone : il ne peut ni refuser ni modifier quoi que ce soit, et sa sortie est ignorée (seuls ses échecs sont comptés). Il reçoit la requête et la réponse terminée : `{method, host, path, query, headers, client_ip, status, response_headers, duration_ms, bytes_out, config}`. Avec la capacité `http` il peut envoyer l'événement à un collecteur ; avec `kv` tenir des compteurs ; `gpx.log` écrit dans le journal de la passerelle.

- **Jamais sur le chemin de la requête.** Les appels passent par une file bornée par passerelle (1 024 entrées, 2 exécutants) ; un plugin lent ou en boucle (borné par `timeout_ms`) ne retarde aucune réponse. File pleine : l'appel est **abandonné et compté** (`gpx_plugin_log_dropped_total{plugin}`), jamais accumulé. Un journal n'est donc pas une piste d'audit garantie ; pour cela, le journal d'accès de la passerelle reste la source.
- `on_error` ne s'applique pas (rien à refuser) ; un échec incrémente `gpx_plugin_log_calls_total{plugin,result="error"}` et est journalisé.
- Un refus d'un autre plugin de la chaîne (`deny`, 503 de plugin absent) est une réponse comme une autre : le journal la voit avec son statut.
- Les octets comptés sont ceux écrits au client ; une connexion détournée (WebSocket) est notée `101`.

## Plugins de détection

Un plugin qui déclare `"detector": true` est un moteur de règles (comme `coraza`), pas un contrôle d'accès. Ses refus aux hooks `request` et `request_body` :

- sont signalés au journal d'accès : le nom du plugin rejoint `waf_matches`, donc le badge « Match WAF » du Journal, la trace d'IP, l'aperçu de ban et l'analyse ASN ;
- peuvent bannir l'IP qui en accumule, si la configuration de la route le demande. Le manifeste doit alors déclarer trois champs numériques, lus par la passerelle (`coraza` les déclare) :

| Champ | Rôle | Défaut |
|---|---|---|
| `ban_after` | refus avant ban, par IP et par plugin | 0 : jamais |
| `ban_window_sec` | fenêtre glissante de comptage | 300 |
| `ban_duration_sec` | durée du ban | 3600 |

Le ban porte la source `plugin:<nom>` et la raison `<nom>: trop de refus` ; il apparaît dans « Bans actifs par source » et « Raisons fréquentes ». Il vise la même cible que les bans d'Ephor (l'adresse exacte) et ne touche jamais les réseaux privés, Cloudflare, la liste blanche des bans ni celle d'Ephor. Il est posé et persisté par la passerelle, propagé à ses pairs HA, et ne dépend pas de l'Admin pour s'appliquer ni pour survivre à un redémarrage ; le compteur de refus, lui, est en mémoire.

Tout refus de plugin au hook de requête, détecteur ou non, est compté dans `gpx_pipeline_blocked_total{stage="plugin", reason="<plugin>"}`. Un plugin qui refuse un accès légitime (clé d'API absente, `token-check`) ne doit pas se déclarer détecteur : ses refus banniraient sinon des clients normaux.

## État et réseau (capacités)

Un plugin n'a **aucune capacité par défaut**. Celles qu'il déclare dans `capabilities` sont les seules fonctions de l'hôte qu'il peut importer ; un import non déclaré est refusé au chargement.

- **`kv`** — état clé/valeur propre au plugin, en mémoire de la passerelle (perdu au redémarrage et au remplacement du plugin). `gpx.kv_get(kptr,klen) -> i64` (−1 si absent, sinon `ptr<<32|len`), `gpx.kv_set(kptr,klen,vptr,vlen,ttl_ms) -> i32` (0 ok, 1 quota atteint, 2 arguments invalides), `gpx.kv_incr(kptr,klen,delta,ttl_ms) -> i64` (compteur à fenêtre fixe, utile pour une limitation de débit ; `math.MinInt64` en cas d'erreur). Bornes : 1 024 clés, clé de 128 octets, valeur de 4 Kio, durée de vie 1 h par défaut et 24 h au plus.
- **`http`** — `gpx.http_fetch(ptr,len) -> i64` envoie la requête JSON `{method,url,headers,body,timeout_ms}` et retourne `{status,headers,body,error}`. Seuls les hôtes de `capabilities.http` (noms exacts ou `*.exemple.fr`) sont joignables ; les adresses internes (boucle locale, réseaux privés) sont refusées *à la connexion* (contre le rebinding DNS) sauf `http_allow_private`, et le lien local, le multicast et les métadonnées cloud le sont toujours, même avec elle ; pas de redirection suivie, pas de proxy d'environnement, méthodes GET/HEAD/POST/PUT/DELETE, 3 appels par hook, réponse tronquée à 64 Kio, délai limité à 80 % du temps restant du hook (déclarez un `timeout_ms` suffisant, 1 000 au plus).

## Routes TCP/UDP

Le hook `connect` reçoit `{client_ip, protocol, listen_port, route_id, config}` et répond `allow` ou `deny` (la connexion est fermée avant tout appel au backend, ou le datagramme ignoré). En UDP la décision est mémorisée une seconde par adresse source. Un plugin absent de la passerelle refuse la connexion, comme pour une route HTTP.

La passerelle ouvre un écouteur par route `tcp`/`udp` qui porte un `listen_port`, le ferme quand la route disparaît et le recrée quand son backend ou ses plugins changent ; ils se rouvrent après un redémarrage sans l'Admin.

## Coût d'un appel

Mesuré avec un module de deux pages mémoire (`go test ./internal/edge/plugins -bench .`, Ryzen 7 5700G) : environ **55 µs et 165 Kio alloués par appel** en amd64 (moteur compilé), environ 58 µs en 386 (interpréteur), un hook trivial. L'essentiel est l'instanciation d'une instance neuve (mémoire linéaire remise à zéro), qui garantit qu'aucun état ne passe d'une requête à l'autre. À 10 000 requêtes/s avec un plugin, cela représente de l'ordre d'un demi-cœur et 1,6 Go/s d'allocations pour le ramasse-miettes. Conséquences pratiques :

- déclarez le **minimum de mémoire** dont le module a besoin (le coût suit sa taille mémoire initiale) ;
- un plugin par route et un seul hook suffisent presque toujours ; chaque plugin et chaque hook s'additionnent ;
- le temps passé dans le plugin lui-même (`timeout_ms`) s'ajoute à ce coût fixe.

Ces chiffres sont une base : à mesurer avec votre propre module et votre trafic avant de généraliser un plugin à toutes les routes.

## Coût d'un vrai module

Le plugin d'exemple en TinyGo avec `encoding/json` (412 Kio) coûtait environ **0,5 ms et 270 Kio par appel** en amd64 (1,9 ms en 386 interprété), dix fois le module assemblé à la main ci-dessus ; le même plugin en Rust avec `serde_json` (57 Kio) coûte environ **0,24 ms et 390 Kio**. L'exemple livré, en TinyGo avec une lecture manuelle de l'entrée (8 Kio), coûte environ **75 µs et 180 Kio** : la réflexion d'`encoding/json` et la taille du module dominent, pas le moteur. Sur le chemin chaud, préférez une analyse minimale de l'entrée (et testez-la contre des entrées piégées). Pour un plugin sur le chemin chaud, préférez une analyse minimale de l'entrée plutôt qu'`encoding/json`, optimisez avec `wasm-opt`, et mesurez avec votre module.

## Exemples compilés

`examples/plugins/` contient sept plugins écrits avec de vrais compilateurs ; `go test ./internal/edge/plugins` les charge et exécute leurs décisions (c'est le test de la chaîne réelle : compilateur → moteur). Chacun a son `manifest.json` et son README ; les cinq derniers partagent `_abi/abi.go` (mémoire de l'ABI, lecture du JSON sans `encoding/json`), recopié dans chaque dossier pour que chacun se compile seul.

| Exemple | Ce qu'il exerce | Taille |
|---|---|---|
| `path-guard` (TinyGo), `path-guard-rs` (Rust) | hook `request` : refus par préfixe de chemin, en-tête posé | 8 Kio, 57 Kio |
| `rate-guard` (TinyGo, SDK) | capacité `kv` : limitation de débit par client et par route avec `gpx.KVIncr` ; seul exemple écrit avec le SDK Go | 24 Kio |
| `body-redact` (TinyGo) | hook `response_body` : remplace un texte dans le corps (`replace_body`), corps binaire et jusqu'à 256 Kio | 14 Kio |
| `token-check` (TinyGo) | capacité `http` : valide une clé d'API auprès d'un service interne avec `gpx.http_fetch` | 12 Kio |
| `tcp-allow` (TinyGo) | hook `connect` : n'accepte sur une route TCP/UDP que des préfixes d'adresse | 11 Kio |
| `coraza` (TinyGo) | moteur Coraza (SecLang) en module : les `SecRule` de la route décident du refus ; moteur reconstruit à chaque appel (~7 ms pour quatre règles) | 1,2 Mio |

Ce que les écrire a appris :

- **L'entrée contient des échappements `\uXXXX`.** L'hôte écrit `&`, `<` et `>` en `&`, `<`, `>`, et un caractère hors du plan de base en paire de substitution. Un lecteur JSON écrit à la main qui ne les décode pas altère silencieusement la valeur : une clé d'API qui contient `&` ne correspond plus à rien. `_abi/abi.go` les décode (paires comprises) ; `path-guard`, plus ancien, ne le fait pas (voir son README).
- **La mémoire d'un plugin à corps se dimensionne sur le corps.** `body-redact` traite 256 Kio avec 64 pages (4 Mio) : le corps arrive en base64 (×1,33), est décodé, remplacé puis ré-encodé, soit une dizaine de fois sa taille à un instant ou un autre. Avec 32 pages le même appel s'arrête sur une erreur d'allocation. Lire une valeur sans antislash sans la recopier (`str` dans `abi.go`) évite l'essentiel de cette amplification.
- **Un moteur complet se paie à chaque appel.** `coraza` (1,2 Mio) reconstruit Coraza et ses règles à chaque requête, faute d'état entre deux appels : environ 7 ms pour quatre règles (amd64). Il tient dans les maxima d'un plugin (256 pages, 1 s) avec un jeu de règles réduit, pas avec OWASP CRS en entier. Coraza se compile avec le tag `no_fs_access`, sinon il tente d'écrire sur un disque que le module n'a pas.
- **Un plugin dont les limites sont trop justes échoue proprement** (`on_error`), il ne corrompt rien : c'est ce qui a signalé les deux points précédents.

## SDK Go

`sdk/go` (module `github.com/vincamok/goproxify/sdk/go`, paquet `gpx`) évite de réécrire l'ABI : un plugin déclare ses gestionnaires dans `init()` (l'hôte exécute `_initialize` sur chaque instance, jamais `main()`) et reçoit un `*gpx.Event` typé (méthode, chemin, en-têtes insensibles à la casse, configuration, corps décodé, statut, durée…) ; il rend `gpx.Allow()`, `gpx.Deny(statut, corps)` ou `gpx.Modify().SetHeader(…)`. `gpx.KVIncr`, `gpx.HTTPFetch` et `gpx.Log` enveloppent les fonctions de l'hôte. Les échappements `u+XXXX` de l'entrée sont décodés et il n'utilise pas `encoding/json`. Détails, API et limites : [sdk/go/README.md](../sdk/go/README.md). Un module écrit avec le SDK pèse environ 12 Kio de plus qu'un module à lecture manuelle, pour un coût d'appel équivalent (environ 120 µs mesurés sur `rate-guard`).

## Mesure en charge

Mesuré avec les exemples ci-dessus, sur un Ryzen 7 5700G (16 threads, moteur compilé amd64), une vraie passerelle (tout le middleware d'une route), un vrai backend HTTP et 64 clients en keep-alive, **tout sur la même machine** : le client, le backend et la passerelle se partagent les cœurs, les débits sont donc un plancher, pas une capacité. Le backend répond 3 Kio.

| Route | Requêtes/s | Latence p50 | p95 | p99 |
|---|---|---|---|---|
| sans plugin | 40 800 | 1,1 ms | 3,9 ms | 4,9 ms |
| `path-guard` | 16 600 | 3,5 ms | 7,8 ms | 10,3 ms |
| `rate-guard` (kv) | 17 800 | 3,4 ms | 7,5 ms | 10,0 ms |
| `body-redact` (corps de 3 Kio) | 7 200 | 5,7 ms | 26,1 ms | 37,7 ms |
| les trois empilés | 5 300 | 9,5 ms | 29,4 ms | 39,9 ms |

Aucune erreur sur ces mesures ; sous concurrence, chaque scénario sert des réponses correctes (`TestPluginLoad_CorrectUnderConcurrency`). Pour les refaire : `GPX_LOAD=1 GOARCH=amd64 go test ./internal/edge -run TestPluginLoad_Report -v -count=1` (`GPX_LOAD_CLIENTS`, `GPX_LOAD_SECONDS`) et `go test ./internal/edge -bench PluginChain`.

Ce qu'on en retient :

- **Un plugin de requête divise le débit par deux et demi à saturation** (de 40 800 à 16 600 requêtes/s ici), pour un surcoût de l'ordre de 0,1 à 0,16 ms par appel en séquence (`BenchmarkTinyGoPathGuard`, `BenchmarkExamplePlugins` : 110 à 160 µs lors de cette mesure, 75 µs relevés plus haut sur une machine au repos). Chaque appel alloue environ 176 Kio (instance neuve) : à ce débit, c'est le ramasse-miettes qui plafonne, pas le code du plugin.
- **Un hook de corps coûte beaucoup plus** : environ 1,1 ms par appel pour 3 Kio dans `body-redact` (décodage base64, recherche, ré-encodage dans le module), et la réponse est retenue jusqu'à son terme. Les p95 et p99 montent à 26 et 38 ms. À réserver aux routes qui en ont besoin.
- **Les coûts s'additionnent** : trois plugins empilés coûtent à peu près la somme, pas le maximum.
- **L'interpréteur** (386, autres architectures que amd64 et arm64) est environ vingt fois plus lent que le moteur compilé sur un corps de plusieurs centaines de Kio : n'en tirez aucun chiffre de capacité.
- Non mesuré : plusieurs passerelles, un backend distant, des corps de plus de 256 Kio, des plugins qui appellent `gpx.http_fetch` sous charge (le temps est alors celui du service appelé), et la mémoire résidente sur plusieurs heures.

## Limites

- Pas d'état partagé entre passerelles (le `kv` est local à une passerelle).
- Pas de compilateur fourni : produisez le WASM avec la chaîne de votre langage (Rust `wasm32-unknown-unknown`, TinyGo `wasm-unknown`). `examples/plugins/path-guard` est un plugin Go compilé avec TinyGo 0.43 (`tinygo build -target=wasm-unknown -no-debug -scheduler=none`) et `examples/plugins/path-guard-rs` le même plugin en Rust 1.99 (`cargo build --release --target wasm32-unknown-unknown`) ; la suite de tests exécute les deux. En Rust, la pile par défaut de 1 Mio fait dépasser `memory_pages` (16 par défaut) : réduisez-la avec `-C link-arg=-zstack-size=65536` (voir le README de l'exemple).
- La mesure en charge ci-dessus tient sur une seule machine (client, backend et passerelle ensemble) : elle donne l'ordre de grandeur du surcoût, pas une capacité. Rien n'a été mesuré avec plusieurs passerelles ni sur la durée (mémoire résidente).
- Un appel instancie un module neuf (environ 176 Kio alloués, 110 à 160 µs) : un plugin sur une route à très fort débit en reste le premier consommateur de CPU et de ramasse-miettes. Une instance réutilisée entre appels romprait la garantie « pas d'état entre deux requêtes » ; ce n'est pas fait.
- **SDK : Go (TinyGo) seulement.** `sdk/go` porte l'ABI pour TinyGo (voir « SDK Go »). Dans les autres langages l'ABI (mémoire, JSON d'entrée et de sortie) est à réécrire ; l'exemple Rust `path-guard-rs` est le point de départ.
