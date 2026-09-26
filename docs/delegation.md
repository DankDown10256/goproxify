# Délégation inter-passerelles

La **délégation** permet à un **Passerelle d'entrée** (frontal, IP publique / DNS) de transférer le trafic d'un domaine (souvent un wildcard `*.example.fr`) vers un **Passerelle cible** sur le réseau interne.

Dans l'Admin : page **Domaines** → cocher « Déléguer vers une autre passerelle » → choisir la passerelle cible, l'endpoint `host:port`, et le **mode**.

Rappel : **Passerelle d'entrée ≠ droits**. La passerelle d'entrée reçoit le trafic ; les **périmètres domaine** du token passerelle décident qui reçoit routes et certificats.

---

## Les deux modes

### Passthrough (défaut)

La passerelle d'entrée **ne déchiffre pas** le TLS. Elle lit le SNI du ClientHello, puis ouvre un **tunnel TCP** vers l'endpoint de la passerelle cible.

```
Client ──TLS chiffré──▶ passerelle d'entrée ──copie TCP──▶ passerelle cible ──▶ backends
                           (SNI only)
```

| | |
|---|---|
| Certificat vu par le client | Celui du **Passerelle cible** (ou derrière) |
| Headers `X-Forwarded-For` | Non (pas de HTTP côté entrée) |
| IP dans les logs de la passerelle cible | IP de la **passerelle d'entrée** (peer TCP) |
| Charge sur la passerelle d'entrée | Faible (L4) |
| Endpoint | `host:port` (dial TCP brut) |

**Quand l'utiliser :** simplicité, perf, la passerelle cible reste maître du TLS / des apps.

### Terminate

La passerelle d'entrée **termine le TLS**, puis reverse-proxy HTTP(S) vers la passerelle cible en conservant le `Host` d'origine. Elle injecte `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`.

```
Client ──TLS──▶ passerelle d'entrée ──HTTPS (SNI=domaine)──▶ passerelle cible ──▶ backends
                 (cert entrée)     + X-Forwarded-For
```

| | |
|---|---|
| Certificat vu par le client | Celui du **Passerelle d'entrée** |
| Headers forward | Oui (`X-Forwarded-For` = IP vue par l'entrée) |
| IP dans les logs de la passerelle cible | IP publique client (via `RealIP` / XFF) si l'entrée l'a vue |
| Charge sur la passerelle d'entrée | Plus élevée (terminaison + re-proxy) |
| Endpoint | `host:port` → poussé en `https://host:port` (`TLSSkipVerify`) |

**Quand l'utiliser :** besoin de l'IP client réelle sur la passerelle cible (logs, WAF, fail2ban, GeoIP), ou politique TLS centralisée sur le frontal.

---

## Prérequis Terminate

1. Le **Passerelle d'entrée** doit avoir le certificat du domaine (périmètre token / ACME sur cette passerelle).
2. L'endpoint doit joindre le **HTTPS** de la passerelle cible (souvent `:443` LAN).
3. La passerelle cible garde les **proxies applicatifs** ; l'entrée ne reçoit que la route synthétique `deleg-*`.

Le re-TLS entrée → cible utilise le **SNI = Host virtuel** (domaine), pas l'IP de l'endpoint — sinon la passerelle cible ne trouve pas de certificat.

---

## Logs d'accès : ce que vous verrez

| Mode | Logs passerelle d'entrée | Logs passerelle cible |
|---|---|---|
| Passthrough | IP client (si NAT OK) | IP de la passerelle d'entrée |
| Terminate | IP client | IP client (via XFF) |

Si l'entrée loggue une IP privée type passerelle LAN (`192.168.x.1`), c'est souvent du **hairpin NAT** depuis le LAN — pas un bug de délégation. Depuis Internet, l'entrée doit voir des IPs publiques.

---

## Choix rapide

| Besoin | Mode |
|---|---|
| Simple, TLS géré sur la passerelle apps | **Passthrough** |
| IP client / WAF / analytics sur la passerelle apps | **Terminate** |
| Frontal « dumb » L4 | **Passthrough** |
| Frontal TLS + inspection HTTP | **Terminate** |

---

## Relay passerelle→Passerelle via Portainer (`endpoint_edges`)

La délégation de domaines (ci-dessus) est configurée dans l'Admin. Pour les routes **découvertes dynamiquement via l'Agent Portainer** (multi-hôtes), un mécanisme de relay différent s'applique.

Quand l'Agent découvre des conteneurs sur un **endpoint Portainer distant**, il peut relayer leurs routes directement vers une passerelle alternative via `endpoint_edges` dans `agent.json`. Le relay utilise l'**endpoint interne `:8000`** de la passerelle cible avec le peer token configuré.

```
Agent ──discovery──▶ Portainer API
                          │
              endpoint "host-dc2" ──▶ passerelle dc2 :8000 ──▶ backends dc2
              endpoint "local"    ──▶ passerelle locale :8000 ──▶ backends locaux
```

Les routes Portainer poussées vers une passerelle déléguée sont automatiquement **purgées** de la passerelle locale pour éviter les doublons et les conflits de passthrough.

Voir la [section Portainer multi-hôtes dans architecture.md](architecture.md#agent-discovery--telemetry).
