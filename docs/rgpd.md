# GoProxify — RGPD / GDPR Compliance Guide

> This document applies to operators running GoProxify. GoProxify is a **self-hosted** tool: the operator is the data controller for all personal data processed through it. Register of processing, impact assessment, privacy notice and data-subject procedures: [rgpd-conformite.md](rgpd-conformite.md).

---

## 1. Data collected and where it lives

| Data | Component | Storage | Default retention |
|---|---|---|---|
| Client IP address | Edge (access log) | Local log database on the Edge (365 days) ; the Admin keeps only the lines flagged by the WAF or Ephor (since Admin `0.175.0` it receives no ordinary access line), 90 days | 365 days on the Edge, 90 days on the Admin for flagged lines only |
| HTTP method, path, host, status, latency | Edge (access log) | Local log database on the Edge (365 days) ; the Admin keeps only the lines flagged by the WAF or Ephor | 365 days on the Edge, 90 days on the Admin for flagged lines only |
| User-Agent header | Edge (access log) | Local log database on the Edge (365 days) ; the Admin keeps only the lines flagged by the WAF or Ephor | 365 days on the Edge, 90 days on the Admin for flagged lines only |
| Referrer header | Edge (access log) | Local log database on the Edge (365 days) ; the Admin keeps only the lines flagged by the WAF or Ephor | 365 days on the Edge, 90 days on the Admin for flagged lines only |
| WAF rule matches (categories only, no payload) | Passerelle (access log) | Admin SQLite | 90 days |
| Banned IP + ban reason + expiry, ban history | Passerelle / Admin | Admin SQLite (`security_bans`, `security_ban_history`, IP in clear) | History and expired bans: 365 days (`retention_ban_days`); an active ban is kept until it expires |
| GeoIP cache of observed IPs (country, city, coordinates) | Admin | Admin SQLite (`geoip_cache`, IP in clear) | Same as access logs (`retention_access_days`) |
| Client errors per IP and per minute (4xx except 404), for the cross-gateway thresholds | Edge → Admin | Local log database on the Edge (`ip_errors`) + Admin SQLite (`edge_ip_errors`), IP in clear; never sent for an anonymised or pseudonymised IP | 48 hours on the Edge, 24 hours on the Admin |
| Admin user email + bcrypt password hash | Admin | Admin SQLite | Until deleted |
| Admin user session JWT | Admin | In-memory + cookie (browser session) | Until logout or expiry |
| Audit log (who did what, when) | Admin | Admin SQLite | 90 days |
| GeoIP lookups | Edge | In-memory only, MaxMind DB on Edge disk | Never stored per-request |
| SSH portal session metadata (target, duration) | Passerelle / Admin | Admin SQLite | Until deleted |
| SSH portal credentials (login/key) | Edge | AES-GCM encrypted on Edge disk, never sent to Admin | Until deleted |

**What GoProxify does NOT collect:**
- Request bodies (WAF inspects them in memory; they are never logged)
- Response bodies (same: in-memory inspection only)
- Cookie values
- Authorization headers or tokens
- Any data sent to Anthropic, Cloudflare, or any third party

---

## 2. Minimisation options

### IP anonymisation in access logs (recommended for GDPR)

Enable in `edge.json`:

```json
{
  "engine": {
    "ip_anonymize": true
  }
}
```

Or push from the Admin UI → **Logs** page → settings (gear icon, admins only) → **Client IP addresses (GDPR)** → *Anonymised*.

Effect:
- IPv4: last octet zeroed → `192.168.1.123` becomes `192.168.1.0`
- IPv6: last 80 bits zeroed → prefix `/48` is kept
- The Edge's Ephor (thresholds included) still receives the real IP before anonymisation and keep banning
- The Admin's cross-gateway thresholds, which read the stored logs, ignores truncated IPs: `x.x.x.0` or a `/48` prefix covers many clients, and banning it would hit none of them (IPv4) or innocent ones (IPv6). The Edge flags every truncated line (`ip_truncated`), including when anonymisation comes from its own `edge.json`. What is lost: the Admin no longer catches an IP whose errors are spread over several Edges — see [security.md](security.md#seuils-multi-passerelles)
- The Admin UI does not offer to ban or analyse a truncated IP: the **Logs** page detail labels it *Truncated IP (anonymisation)* and hides **Ban** and the IP reputation scan; Prism's top IPs tags it *Truncated* and hides re-scan and **Ban**; Prism's "dominant IP" anomaly (which offers **Ban**) only considers attributable IPs. The flag is exposed as `ip_truncated` in `GET /api/v1/logs`, the live stream `/logs/live`, `GET /prism/ips`, `GET /prism/ip-scan` and the MCP tool `list_logs`. Lines stored before Admin `0.71.1`, or sent by an Edge older than `0.17.12`, carry no flag and are shown as regular IPs

### Log retention

Configure in the Admin UI → **Logs** page → settings (gear icon) or via API:

```http
PUT /api/v1/logs/settings
{
  "retention_access_days": 90,
  "retention_system_days": 30,
  "retention_ban_days": 365
}
```

| Setting | Default | GDPR recommendation |
|---|---|---|
| `retention_access_days` | 90 | 90 days is already the default; 13 months is the CNIL maximum — also applies to the GeoIP cache |
| `retention_system_days` | 90 | 90 days |
| `retention_ban_days` | 365 | Legitimate interest — adjust to policy. Applies to the ban history and to expired bans (API only, no field in the UI yet) |

These Admin settings only cover what the Admin keeps itself — the security events (lines flagged by the WAF or Ephor) and its own logs. Ordinary access lines live in each gateway's database, 365 days by default: since Admin `0.183.0` the settings modal sets the retention of the gateways (common value, plus an optional value per gateway; `edge_retention` in the API), each gateway applies it on its own at its next hourly purge, keeps it across a restart with the Admin off and reports what it applies. Lowering it deletes the oldest lines for good.

Older entries are purged automatically every night: access and system logs, the ban history, bans expired for longer than `retention_ban_days`, and GeoIP cache entries older than `retention_access_days`. A ban that is still active (or permanent) is never purged.

**Legal hold and full export (Edge `0.88.0`).** A legal procedure can require keeping data past the retention and handing it over. `goproxify edge logs hold add` freezes a date range on a gateway: the nightly purge skips every log file overlapping it until `hold release`. `goproxify edge logs export` writes the lines of a range (filterable by IP and domain) with the real IP decrypted by the gateway's own key, encrypted by a password, with a manifest signed by the gateway (SHA-256 of the data, operator, reason, gateway clock) and a local hash-chained audit trail; it works with the Admin off. A hold by IP or domain (`-ip`, `-domain`) keeps only the targeted lines, so other people's data still expires on schedule; the registry stores the IP of the person concerned, the audit trail only its hash. A hold does not block an explicit erasure order (Article 17), which also deletes the lines a hold archived: the operator decides which obligation applies, and the audit trail keeps the reason of each hold. Document the procedure in your register of processing — see [docs/cli.md](cli.md#goproxify-edge).

### IP pseudonymisation (recommandé pour RGPD strict)

Mode plus fort que l'anonymisation : l'IP est **chiffrée** (AES-GCM 256 bits) en base SQLite côté Admin. Dans la base de logs de la passerelle, la colonne `ip` reçoit toujours une IP tronquée ; l'IP réelle y est aussi gardée chiffrée (AES-GCM, clé propre à la passerelle, `log-ip-key.gpx`) et n'en sort que par une révélation demandée à la passerelle. L'IP réelle ne peut être obtenue que par un utilisateur possédant le scope `gdpr:reveal` (voir §3 bis).

Activer dans l'interface Admin → page **Logs** → réglages (icône engrenage, admins) → **Adresses IP des clients (RGPD)** → *Pseudonymisées*, ou via API :

```http
PUT /api/v1/logs/settings
{ "ip_pseudonymize": true }
```

Ou dans `edge.json` (non supporté — ce réglage est Admin-side).

| Comportement | Anonymisation | Pseudonymisation |
|---|---|---|
| IP dans la base de logs de la passerelle (colonne `ip`) | tronquée (x.x.x.0) | tronquée (x.x.x.0) |
| IP dans SQLite Admin | tronquée | chiffrée AES-GCM |
| Ephor de la passerelle (Seuils compris) | IP réelle ✓ | IP réelle ✓ |
| Seuils multi-passerelles de l'Admin (logs) | IP tronquée ignorée | IP pseudonymisée ignorée |
| Bannir / analyser l'IP depuis l'interface (Logs, Prism) | masqué (« IP tronquée ») | masqué (« Pseudonymisée ») |
| Révélation possible ? | ❌ irréversible | ✓ avec scope `gdpr:reveal` |

Les deux modes sont exclusifs : l'Admin refuse (`400`) un réglage qui les laisserait actifs ensemble. Sur la passerelle, l'anonymisation l'emporte toujours : si `ip_anonymize: true` est défini dans `edge.json`, l'IP réelle n'est jamais envoyée à l'Admin, même quand celui-ci active la pseudonymisation.

La clé AES-GCM est générée automatiquement au premier démarrage et stockée dans la table `gdpr_keys` de la base Admin. Elle ne quitte jamais le serveur Admin. Elle reste chargée quand la pseudonymisation est désactivée : les entrées déjà pseudonymisées restent révélables jusqu'à la fin de leur rétention.

Modifier ces réglages, comme effacer des logs (ci-dessous), est réservé aux rôles admin et superadmin (scope `logs:write` pour un token API). Chaque changement de mode est inscrit au journal d'audit (`logs_ip_anonymize`, `logs_ip_pseudonymize`).

Chaque passerelle garde une copie chiffrée des réglages reçus de l'Admin (`/etc/goproxify/edge-settings.gpx`) et la recharge au démarrage : une passerelle redémarrée pendant une coupure de l'Admin continue d'anonymiser ou de pseudonymiser les IP de son access log.

---

### Right to erasure (Article 17) — delete by IP

```http
DELETE /api/v1/logs/by-ip/{ip}
```

Removes all log entries of the given IP, **including pseudonymised entries**: each one carries a keyed fingerprint of the real IP (`ip_hmac`, HMAC-SHA256), so the Admin finds them without decrypting the logs. IPv6 is matched whatever its notation. Entries pseudonymised before Admin `0.70.5` get their fingerprint in the background at the next start.

The erasure also covers what the Admin keeps about that IP **outside the logs**, all stored in clear: the bans (`security_bans`), the ban history (`security_ban_history`) and the GeoIP cache entry (`geoip_cache`: country, city, coordinates). The response counts each one:

```json
{ "deleted": 12, "bans_deleted": 1, "ban_history_deleted": 3, "geoip_cache_deleted": 1, "ip_counters_deleted": 2, "audit_ip_cleared": 2, "ip": "203.0.113.42" }
```

Deleting a ban also lifts it on the gateways, like an unban, including bans a gateway set itself. The IP is matched whatever its notation (IPv6). `audit_ip_cleared` counts the audit entries whose address was blanked: the entry (who did what, when) stays, only the actor's IP goes.

**On the gateways** (Admin `0.163.0`, Edge `0.73.0`): the Admin also sends an `erase_ips` order. Each gateway deletes the lines of that IP from its local log database — in clear or pseudonymised (matched by the IP fingerprint) — with `secure_delete` and a truncation of the write-ahead log so the erased value does not stay readable in the files, and deletes the IP from its local ban history. Its writes are not paused. A gateway that is offline when you erase receives the order when it reconnects: the Admin keeps it in `edge_erasure_queue`, **the IP encrypted with the GDPR key**, for 365 days (the longest a gateway keeps its access lines by default), then drops it.

**Not covered by the erasure** (see [rgpd-conformite.md §4](rgpd-conformite.md#4-exercer-les-droits-des-personnes) for the full list): backups already taken, the in-memory state of Ephor on the gateways (thresholds included) (gone at restart or expiry; Ephor's encrypted local copies `threat-state.gpx` and `behavior-state.gpx` hold per-IP scores for minutes and a clean-history counter for 7 days, and an erasure order clears an IP from them at the next save), the unban records of the gateways (`unbans`: they stop a lifted ban from being set again), and third-party services (CrowdSec, alert channels). Erasing the history of an IP also means a gateway that missed its unban can no longer be replayed it.

### Right of access and portability (Articles 15 and 20)

```http
POST /api/v1/logs/subject-export
{ "ip": "203.0.113.42", "reason": "GDPR Art.15 request" }
```

or `{ "user_id": "…" }` (exactly one of the two). Admin only (`logs:write` for an API token). The IP travels in the body, not in the URL. The answer is a JSON file to download with everything the Admin keeps:

- for an IP: the log entries (pseudonymised ones are found through their fingerprint and show the IP you asked for, never decrypted), the bans, the ban history, the GeoIP position and the audit entries carrying that address;
- for an account: the profile (e-mail, role, teams, creation date — never the password hash), the log entries attributed to it and its audit entries.

Logs are capped at 100 000 lines (`logs_truncated`). The gateways' local log databases are not part of the export. The export is audited (`rgpd_export_ip`, `rgpd_export_user`) with the reason and the counts, not the IP in clear.

```bash
goproxify logs subject-export --by-ip 203.0.113.42 --reason "GDPR Art.15 request" --output export.json
```

`{ip}` must be a valid IP address (`400` otherwise). An audit entry (`rgpd_erasure_ip`) and a system log are created with the reason and the number of deleted entries; neither contains the erased IP in clear, only its fingerprint (`hmac:…`), or its truncated form if the pseudonymisation key is unavailable.

CLI equivalent:

```bash
goproxify logs delete --by-ip 203.0.113.42 --reason "GDPR Art.17 request"
```

### Right to erasure — delete by user

```http
DELETE /api/v1/logs/by-user/{user_id}
```

Removes all log entries attributed to an authenticated user (JWT subject).

---

## 3 bis. Droit de révélation IP (scope `gdpr:reveal`)

Les utilisateurs possédant le scope `gdpr:reveal` peuvent obtenir l'IP réelle d'une entrée pseudonymisée, avec traçabilité complète. C'est possible tant que l'entrée est conservée, même si la pseudonymisation a été désactivée depuis.

### Qui peut avoir ce droit ?

| Compte | `gdpr:reveal` |
|---|---|
| Super-admin | ✓ toujours |
| Rôle `dpo` (délégué à la protection des données) | ✓ — droits d'un compte `user`, plus la révélation |
| Compte auquel le super-admin a accordé le droit | ✓ — quel que soit son rôle (DPO externe, juriste, RSSI…) |
| Membre d'une équipe à laquelle le super-admin a accordé le droit | ✓ — tant qu'il en est membre |
| Admin, utilisateur sans délégation | ❌ |

Avec un token API, le scope `gdpr:reveal` doit en plus figurer sur le token ; un compte ne peut le placer sur ses tokens que s'il détient le droit.

**Seul le super-admin délègue** : lui seul attribue ou retire le rôle `dpo`, accorde ou retire le droit à un compte ou à une équipe, et change les membres d'une équipe qui le porte. Chaque attribution est inscrite au journal d'audit (`set_permissions`).

**Comptes protégés** : un compte super-admin ou détenteur du droit ne peut être modifié, voir son mot de passe changé ou être supprimé que par le super-admin. Sinon, un admin pourrait réinitialiser le mot de passe d'un DPO et révéler des IP sous son identité. De même, un import ou une restauration de sauvegarde lancé par un admin n'attribue jamais ce droit (rôle `dpo`, membres d'une équipe qui le porte).

Pour déléguer :

- **Interface** : page **Utilisateurs** → modifier le compte → rôle **dpo**, ou case **Révélation des IP pseudonymisées (RGPD)** ; pour une équipe → modifier l'équipe → case **Les membres peuvent révéler les IP pseudonymisées**. Ces contrôles ne sont actifs que pour le super-admin.
- **CLI** : `goproxify user create -email dpo@example.com -password … -role dpo`, `goproxify user update <id> -permissions gdpr:reveal` (`none` pour retirer), `goproxify teams permissions <id> -permissions gdpr:reveal`.
- **API** : `role: "dpo"` ou `permissions: ["gdpr:reveal"]` sur `POST/PUT /api/v1/users`, `PUT /api/v1/teams/{id}/permissions` (voir [api_specs.md](api_specs.md#utilisateurs-équipes-et-permissions--apiv1users-apiv1teams)).

Un admin ne peut toujours rien révéler, mais il peut désactiver la pseudonymisation : les nouvelles entrées sont alors conservées en clair. La séparation protège les entrées déjà pseudonymisées, pas la configuration future.

### Via l'interface

Page **Logs** → cliquer une entrée dont l'IP est « Pseudonymisée » → **Révéler l'IP** (bouton visible des seuls détenteurs du droit) → saisir le motif légal → **Révéler**. L'IP s'affiche dans le panneau de détail uniquement.

### Via API

```http
POST /api/v1/logs/reveal-ip
Content-Type: application/json
{
  "entry_id": 4821,
  "reason": "Réquisition judiciaire n°2026/1234"
}
```

Réponse :
```json
{
  "entry_id": 4821,
  "ip": "203.0.113.42",
  "requested_by": "dpo@example.com",
  "reason": "Réquisition judiciaire n°2026/1234",
  "ts": "2026-09-20T14:32:01Z"
}
```

### Via CLI

```bash
goproxify logs reveal-ip \
  --entry-id 4821 \
  --reason "Réquisition judiciaire n°2026/1234"
```

### Audit

Chaque révélation crée automatiquement une entrée dans le journal d'audit (`action = gdpr_reveal_ip`) avec l'acteur, l'ID de l'entrée et le motif. Un log système de niveau `warn` est également créé.

---

## 3. GeoIP (MaxMind GeoLite2)

The Edge downloads **GeoLite2-Country** at startup (if `geoip.auto_download: true`). This database is:
- Stored locally on the Edge volume (`/etc/goproxify/geoip/`)
- Never sent anywhere
- Used only for allow/block decisions and Prism dashboard enrichment (country of request)
- The IP itself is never sent to MaxMind at runtime

MaxMind's terms require attribution and accept that the database is used offline. No personal data is transmitted to MaxMind during normal operation.

To disable auto-download, set `geoip.auto_download: false` in `edge.json` and supply your own database.

### Admin: Prism map (city-level position)

The Admin geolocates client IPs to draw the Prism map (country, city, region). Two modes:

- **Local database (default when available)**: the Admin downloads **GeoLite2-City** in the background at startup (`geoip.auto_download: true`, path `geoip.city_db_path`, source `geoip.city_db_url`, default `/etc/goproxify/geoip/GeoLite2-City.mmdb`). IPs are resolved offline and never leave the Admin.
- **Fallback: ip-api.com (off by default)**: while the database is absent (download in progress, disabled, or unreachable), IPs stay without a position and **nothing leaves the Admin**. Setting `geoip.allow_external_lookup: true` in `admin.json` lets the Admin query the public service ip-api.com over plain HTTP in that window, **which sends the client IPs to that third party** (outside the EU, no contract): do not enable it without a legal basis and a processor agreement. Meanwhile the Prism map and the country of log entries fill in once the database has downloaded.

Results (IP, country, city, region, latitude, longitude) are cached in the Admin database (`geoip_cache`). Positions are approximate (city level).

---

## 4. Third-party integrations (operator-configured)

These integrations are **opt-in** and configured by the operator. GoProxify sends data to them only when explicitly configured.

| Integration | Data sent | When |
|---|---|---|
| CrowdSec LAPI | Client IP (ban check) | On each request if bouncer enabled |
| Alert channels (email, Slack, ntfy…) | Event metadata (no client IP by default) | On alert trigger |
| ACME (Let's Encrypt) | Domain name only | On certificate issuance/renewal |
| DNS providers (OVH, Cloudflare…) | Domain/token for DNS-01 challenge | On certificate issuance/renewal |
| External auth providers (OIDC, SAML, LDAP) | Redirect URI, no credentials stored in GoProxify | On SSO flow |
| SIEM export (syslog / HTTP, Admin `0.178.0`) | Log lines of the gateway's own database, the IP **as stored** (truncated under anonymisation or pseudonymisation; the encrypted real IP is never exported), user agent, path | Continuously, once a destination is configured |

The SIEM keeps its own copy: an erasure by IP (Article 17) deletes the lines from the gateways and the Admin but **cannot reach the SIEM**. Erase them there with the SIEM's own tools, or choose anonymisation or pseudonymisation before exporting.

---

## 5. Data processor checklist for operators

Before going to production, ensure:

- [ ] IP anonymisation enabled (`ip_anonymize: true`) if no legitimate need to store full IPs — or pseudonymisation if real IPs must remain obtainable for legal requests
- [ ] Only the accounts that need it are admins (they can change these settings and erase logs) or can reveal pseudonymised IPs (superadmin, `dpo` role, right granted to an account or a team — review the GDPR badges on the Users page)
- [ ] Log retention set to the shortest period that meets your legal obligations (defaults: 90 days for logs, 365 for the ban history, 90 for portal session recordings)
- [ ] `geoip.allow_external_lookup` left at `false`
- [ ] Register of processing, impact assessment and privacy notice done from [rgpd-conformite.md](rgpd-conformite.md)
- [ ] Admin user list reviewed — remove test accounts
- [ ] SSH portal vault entries reviewed — remove unused targets
- [ ] Alert channel configurations reviewed — confirm no personal data is included in alert payloads
- [ ] If using CrowdSec, check CrowdSec's own GDPR documentation
- [ ] Backup encryption enabled (`GPX_BACKUP_KEY`) if backups may contain personal data
- [ ] Privacy notice for end users updated to mention reverse proxy logging

---

## 6. Security measures protecting personal data

| Measure | Details |
|---|---|
| TLS in transit | All Admin↔Edge↔browser communication is TLS — certificates in RAM only on Edge |
| SSH vault encryption | AES-GCM, key never leaves passerelle |
| Admin authentication | JWT ECDSA P-256, bcrypt passwords, optional MFA (TOTP / WebAuthn) |
| Audit log | All admin operations are recorded with actor, timestamp, action |
| Role-based access | Teams + scopes limit who can read logs or security data |
| Backup encryption | AES-GCM via `GPX_BACKUP_KEY` |
