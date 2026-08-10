# Délégation inter-Cores

La **délégation** permet à un **Core d'entrée** (frontal, IP publique / DNS) de transférer le trafic d'un domaine (souvent un wildcard `*.example.fr`) vers un **Core cible** sur le réseau interne.

Dans l'Admin : page **Domaines** → cocher « Déléguer vers un autre Core » → choisir le Core cible, l'endpoint `host:port`, et le **mode**.

Rappel : **Core d'entrée ≠ droits**. Le Core d'entrée reçoit le trafic ; les **périmètres domaine** du token Core décident qui reçoit routes et certificats.

---

## Les deux modes

### Passthrough (défaut)

Le Core d'entrée **ne déchiffre pas** le TLS. Il lit le SNI du ClientHello, puis ouvre un **tunnel TCP** vers l'endpoint du Core cible.

```
Client ──TLS chiffré──▶ Core d'entrée ──copie TCP──▶ Core cible ──▶ backends
                           (SNI only)
```

| | |
|---|---|
| Certificat vu par le client | Celui du **Core cible** (ou derrière) |
| Headers `X-Forwarded-For` | Non (pas de HTTP côté entrée) |
| IP dans les logs du Core cible | IP du **Core d'entrée** (peer TCP) |
| Charge sur le Core d'entrée | Faible (L4) |
| Endpoint | `host:port` (dial TCP brut) |

**Quand l'utiliser :** simplicité, perf, le Core cible reste maître du TLS / des apps.

### Terminate

Le Core d'entrée **termine le TLS**, puis reverse-proxy HTTP(S) vers le Core cible en conservant le `Host` d'origine. Il injecte `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`.

```
Client ──TLS──▶ Core d'entrée ──HTTPS (SNI=domaine)──▶ Core cible ──▶ backends
                 (cert entrée)     + X-Forwarded-For
```

| | |
|---|---|
| Certificat vu par le client | Celui du **Core d'entrée** |
| Headers forward | Oui (`X-Forwarded-For` = IP vue par l'entrée) |
| IP dans les logs du Core cible | IP publique client (via `RealIP` / XFF) si l'entrée l'a vue |
| Charge sur le Core d'entrée | Plus élevée (terminaison + re-proxy) |
| Endpoint | `host:port` → poussé en `https://host:port` (`TLSSkipVerify`) |

**Quand l'utiliser :** besoin de l'IP client réelle sur le Core cible (logs, WAF, fail2ban, GeoIP), ou politique TLS centralisée sur le frontal.

---

## Prérequis Terminate

1. Le **Core d'entrée** doit avoir le certificat du domaine (périmètre token / ACME sur ce Core).
2. L'endpoint doit joindre le **HTTPS** du Core cible (souvent `:443` LAN).
3. Le Core cible garde les **proxies applicatifs** ; l'entrée ne reçoit que la route synthétique `deleg-*`.

Le re-TLS entrée → cible utilise le **SNI = Host virtuel** (domaine), pas l'IP de l'endpoint — sinon le Core cible ne trouve pas de certificat.

---

## Logs d'accès : ce que vous verrez

| Mode | Logs Core d'entrée | Logs Core cible |
|---|---|---|
| Passthrough | IP client (si NAT OK) | IP du Core d'entrée |
| Terminate | IP client | IP client (via XFF) |

Si l'entrée loggue une IP privée type passerelle LAN (`192.168.x.1`), c'est souvent du **hairpin NAT** depuis le LAN — pas un bug de délégation. Depuis Internet, l'entrée doit voir des IPs publiques.

---

## Choix rapide

| Besoin | Mode |
|---|---|
| Simple, TLS géré sur le Core apps | **Passthrough** |
| IP client / WAF / analytics sur le Core apps | **Terminate** |
| Frontal « dumb » L4 | **Passthrough** |
| Frontal TLS + inspection HTTP | **Terminate** |
